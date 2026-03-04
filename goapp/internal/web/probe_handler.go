package web

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"vpshelper-go/internal/cloudflare"
	"vpshelper-go/internal/firewall"
	"vpshelper-go/internal/security"
	"vpshelper-go/internal/shell"
	"vpshelper-go/internal/store"
	"vpshelper-go/internal/tunnel"
	"vpshelper-go/internal/update"
)

// generateProbeSecret generates a cryptographically random 32-byte hex secret.
func generateProbeSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func (h *Handler) probeManagement(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}
	c.HTML(http.StatusOK, "probe_nodes.html", gin.H{
		"Title": "探针管理",
	})
}

func (h *Handler) probeNodes(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	var message string
	var msgOK bool

	if c.Request.Method == http.MethodPost {
		action := strings.TrimSpace(c.PostForm("action"))
		switch action {

		case "add":
			name := strings.TrimSpace(c.PostForm("name"))
			if name == "" {
				message = "节点名称不能为空。"
				break
			}
			secret, err := generateProbeSecret()
			if err != nil {
				message = "密钥生成失败：" + err.Error()
				break
			}
			if _, err := store.CreateProbeNode(h.dbConn, name, "", secret); err != nil {
				message = "添加节点失败：" + err.Error()
				break
			}
			message = "节点已添加，密钥已自动生成。"
			msgOK = true

		case "delete":
			idStr := strings.TrimSpace(c.PostForm("id"))
			id, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil || id <= 0 {
				message = "无效的节点 ID。"
				break
			}
			if err := store.DeleteProbeNode(h.dbConn, id); err != nil {
				message = "删除失败：" + err.Error()
				break
			}
			message = "节点已删除。"
			msgOK = true

		case "edit":
			idStr := strings.TrimSpace(c.PostForm("id"))
			id, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil || id <= 0 {
				message = "无效的节点 ID。"
				break
			}
			name := strings.TrimSpace(c.PostForm("name"))
			note := strings.TrimSpace(c.PostForm("note"))
			vendor := strings.TrimSpace(c.PostForm("vendor"))
			vendorUrl := strings.TrimSpace(c.PostForm("vendor_url"))
			priceAmt := strings.TrimSpace(c.PostForm("price_amount"))
			price := ""
			if priceAmt != "" {
				price = strings.TrimSpace(c.PostForm("price_currency") + priceAmt + c.PostForm("price_period"))
			} else {
				price = strings.TrimSpace(c.PostForm("price"))
			}
			expiredAt := strings.TrimSpace(c.PostForm("expired_at"))
			intervalStr := strings.TrimSpace(c.PostForm("report_interval"))

			if name == "" {
				message = "节点名称不能为空。"
				break
			}

			intervalVal, _ := strconv.Atoi(intervalStr)
			if intervalVal < 1 {
				intervalVal = 60
			}

			if err := store.UpdateProbeNodeDetails(h.dbConn, id, name, note, vendor, vendorUrl, price, expiredAt, intervalVal); err != nil {
				message = "更新失败：" + err.Error()
				break
			}
			message = "节点信息已更新。"
			msgOK = true

			// 尝试给在线节点实时推送新的汇报周期
			pushErr := tunnel.PushConfigToNode(id, "config", map[string]int{"report_interval": intervalVal})
			if pushErr == nil {
				message += "（新汇报周期已实时应用。）"
			}

		case "regen_secret":
			idStr := strings.TrimSpace(c.PostForm("id"))
			id, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil || id <= 0 {
				message = "无效的节点 ID。"
				break
			}
			secret, err := generateProbeSecret()
			if err != nil {
				message = "密钥生成失败：" + err.Error()
				break
			}
			if err := store.UpdateProbeNodeSecret(h.dbConn, id, secret); err != nil {
				message = "重置密钥失败：" + err.Error()
				break
			}
			message = "密钥已重新生成。"
			msgOK = true

		case "upgrade":
			idStr := strings.TrimSpace(c.PostForm("id"))

			scheme := "http"
			if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" || c.GetHeader("Cf-Visitor") != "" {
				scheme = "https"
			}
			host := c.Request.Host
			baseURL := fmt.Sprintf("%s://%s", scheme, host)

			settings, _ := store.GetSettings(h.dbConn, []string{"probe_master_address"})
			if settings["probe_master_address"] != "" {
				addr := strings.TrimRight(settings["probe_master_address"], "/")
				// 确保始终携带 scheme，避免老版本探针收到无协议的地址后拼出非法 URL
				if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
					addr = "https://" + addr
				}
				baseURL = addr
			}

			if idStr == "all" {
				nodes, err := store.ListProbeNodes(h.dbConn)
				if err != nil {
					message = "获取节点列表失败。"
					break
				}
				count := 0
				for _, n := range nodes {
					if n.Online {
						payload := map[string]string{"secret": n.Secret, "host": baseURL}
						if err := tunnel.PushConfigToNode(n.ID, "upgrade", payload); err == nil {
							count++
						}
					}
				}
				message = fmt.Sprintf("已向 %d 个在线节点下发升级指令。", count)
				msgOK = true
			} else {
				id, err := strconv.ParseInt(idStr, 10, 64)
				if err != nil || id <= 0 {
					message = "无效的节点 ID。"
					break
				}
				node, err := store.GetProbeNodeBySecret(h.dbConn, c.PostForm("secret_for_upgrade"))
				if err != nil || node.ID != id {
					// Fallback to fetch from DB if correct secret is not provided
					nodes, _ := store.ListProbeNodes(h.dbConn)
					for _, n := range nodes {
						if n.ID == id {
							node = n
							break
						}
					}
				}

				payload := map[string]string{"secret": node.Secret, "host": baseURL}
				pushErr := tunnel.PushConfigToNode(id, "upgrade", payload)
				if pushErr != nil {
					message = "节点当前没在线，请确保在线后再操作。"
				} else {
					message = "已向该探针节点下发自动升级指令。"
					msgOK = true
				}
			}

		case "save_master_settings":
			masterAddress := strings.TrimSpace(c.PostForm("probe_master_address"))
			masterAddress = strings.TrimRight(masterAddress, "/") // 清理末尾反斜杠
			
			historyDays := strings.TrimSpace(c.PostForm("probe_history_days"))
			if historyDays == "" {
				historyDays = "90"
			}

			_ = store.SetSetting(h.dbConn, "probe_history_days", historyDays)
			_ = store.SetSetting(h.dbConn, "probe_master_address", masterAddress)

			message = "主控配置已保存。"
			msgOK = true

			// 向所有仍在线的探针热推送新的主控地址配置
			if masterAddress != "" {
				tunnel.PushConfigToAllNodes("update_master_address", map[string]string{"host": masterAddress})
				message += "（已向在线探针下发新主控地址。）"
			}

		case "save_websocket_settings":
			privatePort := strings.TrimSpace(c.PostForm("probe_private_port"))
			addressIn := strings.TrimSpace(c.PostForm("probe_address"))
			enableDDNS := c.PostForm("enable_ddns") == "on" || c.PostForm("enable_ddns") == "true"
			enableAutoTLS := c.PostForm("enable_auto_tls") == "on" || c.PostForm("enable_auto_tls") == "true"

			if privatePort == "" {
				privatePort = "15019"
			}
			var publicAddress, ddnsDomain string
			if enableDDNS {
				ddnsDomain = addressIn
			} else {
				publicAddress = addressIn
			}

			// 如果关闭了自动 TLS，清除已存的证书状态
			if !enableAutoTLS {
				_ = store.SetSetting(h.dbConn, "probe_auto_tls", "false")
				_ = store.SetSetting(h.dbConn, "probe_tls_cert_pem", "")
				_ = store.SetSetting(h.dbConn, "probe_tls_key_pem", "")
			} else {
				_ = store.SetSetting(h.dbConn, "probe_auto_tls", "true")
			}

			_ = store.SetSetting(h.dbConn, "probe_private_port", privatePort)
			_ = store.SetSetting(h.dbConn, "probe_public_address", publicAddress)
			_ = store.SetSetting(h.dbConn, "probe_ddns_domain", ddnsDomain)

			message = "WebSocket 通信设置已保存，端口更改需重启服务生效。"
			msgOK = true

			// 自动协助放行专属通讯端口
			pPortInt, _ := strconv.Atoi(privatePort)
			if pPortInt > 0 && pPortInt <= 65535 {
				fwType := firewall.DetectType()
				if firewall.IsActive(fwType) {
					fwOk, fwMsg := firewall.OpenPort(fwType, pPortInt, "tcp", "")
					if fwOk {
						message += fmt.Sprintf(" (防火墙已自动放行 %d/tcp)", pPortInt)
					} else {
						message += fmt.Sprintf(" (⚠️ 联动防火墙放行失败: %s)", fwMsg)
					}
				}
			}

			// If a DDNS domain is configured, immediately push the current IP to Cloudflare.
			if ddnsDomain != "" {
				if errMsg := cloudflare.TriggerProbeDDNS(h.dbConn); errMsg != "" {
					message = message + " | DDNS 更新失败：" + errMsg
					msgOK = false
				} else {
					message = message + " | DDNS 已成功触发更新。"
				}
			}

			// 如果启用了自动 TLS 且填写了域名，立即触发证书申请
			if enableAutoTLS && addressIn != "" && !isIPAddress(addressIn) {
				go tunnel.RequestCertificate(h.dbConn, addressIn)
				message += " | 正在后台申请 TLS 证书，请稍后刷新查看状态。"
			}

		case "save_node_ddns_settings":
			nodeDDNSDomain := strings.TrimSpace(c.PostForm("probe_node_ddns_domain"))
			_ = store.SetSetting(h.dbConn, "probe_node_ddns_domain", nodeDDNSDomain)

			message = "探针节点 DDNS 设置已保存。"
			msgOK = true

			// Optional: Trigger immediately in a goroutine
			go cloudflare.TriggerNodeDDNS(h.dbConn)
		}
	}

	settings, err := store.GetSettings(h.dbConn, []string{
		"probe_private_port", "probe_public_address", "probe_ddns_domain",
		"probe_history_days", "probe_auto_tls",
		"probe_tls_cert_status", "probe_tls_cert_error", "probe_tls_cert_updated_at",
		"probe_master_address", "probe_node_ddns_domain",
	})
	if err != nil {
		c.String(http.StatusInternalServerError, "加载设置失败")
		return
	}
	privatePort := settings["probe_private_port"]
	if privatePort == "" {
		privatePort = "15019" // default
	}
	publicAddress := settings["probe_public_address"]
	ddnsDomain := settings["probe_ddns_domain"]
	historyDays := settings["probe_history_days"]
	if historyDays == "" {
		historyDays = "90"
	}
	enableAutoTLS := settings["probe_auto_tls"] == "true"
	certReqStatus := settings["probe_tls_cert_status"] // "", "running", "success", "error"
	certReqError := settings["probe_tls_cert_error"]
	certReqAt := settings["probe_tls_cert_updated_at"]
	masterAddress := settings["probe_master_address"]
	nodeDDNSDomain := settings["probe_node_ddns_domain"]

	// 读取证书详细状态
	certInfo := tunnel.GetCertInfo(h.dbConn)

	nodes, err := store.ListProbeNodes(h.dbConn)
	if err != nil {
		c.String(http.StatusInternalServerError, "加载节点列表失败")
		return
	}

	// Build install command base URL from request host.
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" || c.GetHeader("Cf-Visitor") != "" {
		scheme = "https"
	}
	host := c.Request.Host
	baseURL := fmt.Sprintf("%s://%s", scheme, host)
	if masterAddress != "" {
		baseURL = masterAddress
	}

	// Consolidate for frontend
	combinedAddress := publicAddress
	if ddnsDomain != "" {
		combinedAddress = ddnsDomain
	}
	enableDDNS := ddnsDomain != ""

	templateName := "probe_nodes_list.html"
	if strings.Contains(c.Request.URL.Path, "/comm") {
		templateName = "probe_nodes_comm.html"
	}

	c.HTML(http.StatusOK, templateName, gin.H{
		"Title":         "探针管理",
		"Message":       message,
		"MsgOK":         msgOK,
		"Nodes":         nodes,
		"BaseURL":       baseURL,
		"PrivatePort":   privatePort,
		"Address":       combinedAddress,
		"EnableDDNS":    enableDDNS,
		"EnableAutoTLS": enableAutoTLS,
		"CertInfo":      certInfo,
		"CertReqStatus": certReqStatus,
		"CertReqError":  certReqError,
		"CertReqAt":     certReqAt,
		"HistoryDays":   historyDays,
		"MasterAddress": masterAddress,
		"NodeDDNSDomain": nodeDDNSDomain,
	})
}

// probeDiscover is the public API endpoint for probes to dynamically discover the WebSocket connection address.
func (h *Handler) probeDiscover(c *gin.Context) {
	ip := c.ClientIP()
	if security.IsBanned(ip) {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		security.RecordFailure(h.dbConn, ip)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid authorization header"})
		return
	}
	secret := strings.TrimPrefix(authHeader, "Bearer ")

	node, err := store.GetProbeNodeBySecret(h.dbConn, secret)
	if err != nil {
		security.RecordFailure(h.dbConn, ip)
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid secret"})
		return
	}

	settings, _ := store.GetSettings(h.dbConn, []string{"probe_private_port", "probe_public_address", "probe_ddns_domain", "probe_auto_tls"})

	port := settings["probe_private_port"]
	if port == "" {
		port = "15019"
	}
	autoTLS := settings["probe_auto_tls"] == "true"
	wsScheme := "ws"
	if autoTLS {
		if certInfo := tunnel.GetCertInfo(h.dbConn); certInfo != nil && certInfo.IsValid {
			wsScheme = "wss"
		}
	}

	address := ""
	ddns := settings["probe_ddns_domain"]
	publicAddr := settings["probe_public_address"]

	// 1. 如果有域名优先使用域名
	if ddns != "" {
		address = fmt.Sprintf("%s://%s:%s/tunnel", wsScheme, ddns, port)
	} else if publicAddr != "" {
		// 2. 没有域名则使用写死的公网IP/地址
		address = publicAddr
	} else {
		// 3. 都没有，则自动探测公网IP并下发
		ips := cloudflare.GetPublicIPs()
		if ips.IPv4 != "" {
			address = fmt.Sprintf("%s://%s:%s/tunnel", wsScheme, ips.IPv4, port)
		} else if ips.IPv6 != "" {
			address = fmt.Sprintf("%s://[%s]:%s/tunnel", wsScheme, ips.IPv6, port)
		} else {
			clientIP := c.ClientIP()
			if strings.Contains(clientIP, ":") {
				address = fmt.Sprintf("%s://[%s]:%s/tunnel", wsScheme, clientIP, port)
			} else {
				address = fmt.Sprintf("%s://%s:%s/tunnel", wsScheme, clientIP, port)
			}
		}
	}

	// 统一针对没写协议头的 address 做标准化修饰
	if !strings.HasPrefix(address, "ws") && !strings.HasPrefix(address, "http") {
		if !strings.Contains(address, ":") || net.ParseIP(address) != nil || (strings.Contains(address, ":") && strings.HasPrefix(address, "[")) {
			// pure domain or IP without port
			address = fmt.Sprintf("%s://%s:%s/tunnel", wsScheme, address, port)
		} else {
			// has port attached, just add scheme
			address = wsScheme + "://" + address
		}
	} else {
		// Normalizes http/https to ws/wss
		if strings.HasPrefix(address, "https://") {
			address = "wss://" + strings.TrimPrefix(address, "https://")
		} else if strings.HasPrefix(address, "http://") {
			address = "ws://" + strings.TrimPrefix(address, "http://")
		}
	}
	address = strings.TrimSuffix(address, "/")
	if strings.HasSuffix(address, "/tunnel") {
		address = address + "/" + secret
	} else {
		address = address + "/tunnel/" + secret
	}

	tasksRaw, _ := store.GetProbeTasksForNode(h.dbConn, node.ID)
	tasksRes := make([]map[string]interface{}, 0, len(tasksRaw))
	for _, t := range tasksRaw {
		tasksRes = append(tasksRes, map[string]interface{}{
			"id":     t.ID,
			"target": t.Target,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"success":         true,
		"node_id":         node.ID,
		"name":            node.Name,
		"address":         address,
		"report_interval": node.ReportInterval,
		"ping_tasks":      tasksRes,
	})
}

// probeDashboard renders either the wrapper layout or the specific iframe content
func (h *Handler) probeDashboard(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	content := c.Query("content")
	if content == "" {
		c.HTML(http.StatusOK, "probe_dashboard.html", gin.H{
			"Title": "探针监视",
			"Tab":   c.Query("tab"),
		})
		return
	}

	nodes, err := store.ListProbeNodes(h.dbConn)
	if err != nil {
		c.String(http.StatusInternalServerError, "加载节点列表失败")
		return
	}

	tasks, _ := store.ListProbeTasks(h.dbConn)

	if content == "netstatus" {
		c.HTML(http.StatusOK, "probe_dashboard_netstatus.html", gin.H{
			"Title": "网络状态",
			"Nodes": nodes,
			"Tasks": tasks,
		})
		return
	}

	// Default to status
	c.HTML(http.StatusOK, "probe_dashboard_status.html", gin.H{
		"Title": "探针状态",
		"Nodes": nodes,
		"Tasks": tasks,
	})
}

// probePingHistory returns historical ping latency and loss for a specific node to draw charts.
func (h *Handler) probePingHistory(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	nodeIDStr := c.Query("node_id")
	hoursStr := c.Query("hours")

	nodeID, _ := strconv.ParseInt(nodeIDStr, 10, 64)
	hours, _ := strconv.Atoi(hoursStr)

	if hours <= 0 {
		hours = 24 // default 24h
	}

	history, err := store.GetProbePingHistoryForNode(nodeID, hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"history": history,
	})
}

// probeLatestBinary proxies the download of the latest probe binary to bypass GitHub blockades.
func (h *Handler) probeLatestBinary(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	secret := strings.TrimPrefix(authHeader, "Bearer ")
	_, err := store.GetProbeNodeBySecret(h.dbConn, secret)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	osParam := strings.ToLower(c.Query("os"))
	archParam := strings.ToLower(c.Query("arch"))
	if osParam == "" || archParam == "" {
		c.String(http.StatusBadRequest, "missing os/arch")
		return
	}

	info, rel, err := update.FetchLatestGitHubRelease(c.Request.Context(), "fengzhanhuaer", "VpsHelper", "")
	if err != nil || !info.OK {
		c.String(http.StatusInternalServerError, "failed to get release from upstream")
		return
	}

	var targetURL string
	var targetName string
	for _, a := range rel.Assets {
		n := strings.ToLower(a.Name)
		if strings.Contains(n, "vpsprobe") && strings.Contains(n, osParam) && strings.Contains(n, archParam) {
			targetURL = a.BrowserDownload
			targetName = a.Name
			break
		}
	}
	if targetURL == "" {
		c.String(http.StatusNotFound, "asset not found")
		return
	}

	if c.Query("info") == "true" {
		c.JSON(http.StatusOK, gin.H{
			"name":     targetName,
			"tag_name": info.TagName,
			"url":      fmt.Sprintf("/api/probe/latest_binary?os=%s&arch=%s", osParam, archParam),
		})
		return
	}

	req, err := http.NewRequestWithContext(c.Request.Context(), "GET", targetURL, nil)
	if err != nil {
		c.String(http.StatusInternalServerError, "req create error")
		return
	}

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		c.String(http.StatusBadGateway, "upstream download failed")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.String(resp.StatusCode, "upstream returned error")
		return
	}

	c.DataFromReader(resp.StatusCode, resp.ContentLength, resp.Header.Get("Content-Type"), resp.Body, nil)
}

// probeInstallScript downloads the install script from GitHub and proxies it
func (h *Handler) probeInstallScript(c *gin.Context) {
	secret := c.Query("secret")
	if secret == "" {
		c.String(http.StatusUnauthorized, "echo 'Error: secret parameter is required'; exit 1")
		return
	}

	_, err := store.GetProbeNodeBySecret(h.dbConn, secret)
	if err != nil {
		c.String(http.StatusForbidden, "echo 'Error: invalid secret or node not found'; exit 1")
		return
	}

	scriptURL := fmt.Sprintf("https://raw.githubusercontent.com/fengzhanhuaer/VpsHelper/main/install-probe.sh?t=%d", time.Now().Unix())

	req, err := http.NewRequestWithContext(c.Request.Context(), "GET", scriptURL, nil)
	if err != nil {
		c.String(http.StatusInternalServerError, "echo 'Error: Failed to construct proxy request'; exit 1")
		return
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.String(http.StatusBadGateway, "Failed to download installation script from upstream: "+err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.String(resp.StatusCode, "Upstream returned non-OK status: %d", resp.StatusCode)
		return
	}

	c.DataFromReader(resp.StatusCode, resp.ContentLength, "text/plain; charset=utf-8", resp.Body, nil)
}

// isIPAddress returns true if addr is a raw IPv4/IPv6 address (not a domain name).
func isIPAddress(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	return net.ParseIP(host) != nil
}

// probeNodesDeleted handles the recycle bin page for deleted nodes.
func (h *Handler) probeNodesDeleted(c *gin.Context) {
	message := ""
	msgOK := false

	if c.Request.Method == http.MethodPost {
		action := strings.TrimSpace(c.PostForm("action"))
		idStr := strings.TrimSpace(c.PostForm("id"))
		id, err := strconv.ParseInt(idStr, 10, 64)

		if err == nil && id > 0 {
			switch action {
			case "restore":
				if err := store.RestoreDeletedProbeNode(h.dbConn, id); err != nil {
					message = "恢复失败：" + err.Error()
				} else {
					message = "节点已成功恢复。"
					msgOK = true
				}
			case "hard_delete":
				if err := store.HardDeleteProbeNode(h.dbConn, id); err != nil {
					message = "永久删除失败：" + err.Error()
				} else {
					message = "节点记录已永久抹除。"
					msgOK = true
				}
			}
		}
	}

	nodes, err := store.ListDeletedProbeNodes(h.dbConn)
	if err != nil {
		c.String(http.StatusInternalServerError, "加载已删除节点列表失败")
		return
	}

	c.HTML(http.StatusOK, "probe_nodes_deleted.html", gin.H{
		"Title":   "已删除节点",
		"Message": message,
		"MsgOK":   msgOK,
		"Nodes":   nodes,
	})
}

// probeNodeManage wraps the individual node management with tabs (details, shell, etc.).
func (h *Handler) probeNodeManage(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	// ── Handle POST quick-actions ────────────────────────────────
	if c.Request.Method == http.MethodPost {
		idStr := c.PostForm("id")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil || id <= 0 {
			c.String(http.StatusBadRequest, "invalid node id")
			return
		}
		tab := c.PostForm("tab")
		if tab == "" {
			tab = "detail"
		}
		action := c.PostForm("action")
		var msg string
		var ok bool

		switch action {
		case "upgrade":
			scheme := "http"
			if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" || c.GetHeader("Cf-Visitor") != "" {
				scheme = "https"
			}
			baseURL := fmt.Sprintf("%s://%s", scheme, c.Request.Host)
			settings, _ := store.GetSettings(h.dbConn, []string{"probe_master_address"})
			if ma := strings.TrimRight(settings["probe_master_address"], "/"); ma != "" {
				if !strings.HasPrefix(ma, "http://") && !strings.HasPrefix(ma, "https://") {
					ma = "https://" + ma
				}
				baseURL = ma
			}
			node, err := store.GetProbeNodeByID(h.dbConn, id)
			if err != nil {
				msg = "节点不存在"
			} else {
				payload := map[string]string{"secret": node.Secret, "host": baseURL}
				if pushErr := tunnel.PushConfigToNode(id, "upgrade", payload); pushErr != nil {
					msg = "探针当前不在线，请确保在线后再操作"
				} else {
					msg = "已下发升级指令，探针将自动重启更新"
					ok = true
				}
			}

		case "edit":
			name := strings.TrimSpace(c.PostForm("name"))
			if name == "" {
				msg = "节点名称不能为空"
				break
			}
			note := strings.TrimSpace(c.PostForm("note"))
			vendor := strings.TrimSpace(c.PostForm("vendor"))
			vendorUrl := strings.TrimSpace(c.PostForm("vendor_url"))
			priceAmt := strings.TrimSpace(c.PostForm("price_amount"))
			price := ""
			if priceAmt != "" {
				price = strings.TrimSpace(c.PostForm("price_currency") + priceAmt + c.PostForm("price_period"))
			}
			expiredAt := strings.TrimSpace(c.PostForm("expired_at"))
			intervalVal, _ := strconv.Atoi(strings.TrimSpace(c.PostForm("report_interval")))
			if intervalVal < 1 {
				intervalVal = 60
			}
			if err := store.UpdateProbeNodeDetails(h.dbConn, id, name, note, vendor, vendorUrl, price, expiredAt, intervalVal); err != nil {
				msg = "保存失败：" + err.Error()
			} else {
				msg = "节点设置已更新"
				ok = true
				tunnel.PushConfigToNode(id, "config", map[string]int{"report_interval": intervalVal})
			}
		}

		redirectURL := fmt.Sprintf("/probe/node/manage?id=%d&tab=%s&msg=%s", id, tab, url.QueryEscape(msg))
		if ok {
			redirectURL += "&ok=1"
		}
		c.Redirect(http.StatusSeeOther, redirectURL)
		return
	}

	// ── GET: render layout ───────────────────────────────────────
	nodeIDStr := c.Query("id")
	nodeID, err := strconv.ParseInt(nodeIDStr, 10, 64)
	if err != nil || nodeID <= 0 {
		c.String(http.StatusBadRequest, "invalid node id")
		return
	}
	node, err := store.GetProbeNodeByID(h.dbConn, nodeID)
	if err != nil {
		c.String(http.StatusNotFound, "node not found")
		return
	}

	tab := c.Query("tab")
	if tab == "" {
		tab = "detail"
	}

	allNodes, _ := store.ListProbeNodes(h.dbConn)

	c.HTML(http.StatusOK, "probe_manage_layout.html", gin.H{
		"Title":    "单探针管理 - " + node.Name,
		"Node":     node,
		"Tab":      tab,
		"AllNodes": allNodes,
		"Message":  c.Query("msg"),
		"MsgOK":    c.Query("ok") == "1",
	})
}


// probeNodeDetail renders the details specific to one node.
func (h *Handler) probeNodeDetail(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}
	nodeIDStr := c.Query("id")
	nodeID, _ := strconv.ParseInt(nodeIDStr, 10, 64)
	node, err := store.GetProbeNodeByID(h.dbConn, nodeID)
	if err != nil {
		c.String(http.StatusNotFound, "node not found")
		return
	}

	c.HTML(http.StatusOK, "probe_manage_detail.html", gin.H{
		"Title": "探针详情 - " + node.Name,
		"Node":  node,
	})
}

// probeNodeShell renders a remote shell interface matching the /shell simple pattern.
func (h *Handler) probeNodeShell(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}
	nodeIDStr := c.Query("id")
	nodeID, _ := strconv.ParseInt(nodeIDStr, 10, 64)
	node, err := store.GetProbeNodeByID(h.dbConn, nodeID)
	if err != nil {
		c.String(http.StatusNotFound, "node not found")
		return
	}

	sess := sessions.Default(c)
	sessionKey := fmt.Sprintf("probe_cwd_%d", nodeID)
	cwd, _ := sess.Get(sessionKey).(string)
	if cwd == "" {
		cwd = "~"
	}

	history := shell.LoadHistory(h.cfg.DataDir, username)
	shortcuts, _ := h.loadShellShortcuts(username)

	historyJSON, _ := json.Marshal(history)
	shortcutsJSON, _ := json.Marshal(shortcuts)

	c.HTML(http.StatusOK, "probe_manage_shell.html", gin.H{
		"Title":         "远程 Shell - " + node.Name,
		"Node":          node,
		"CWD":           cwd,
		"HistoryJSON":   string(historyJSON),
		"ShortcutsJSON": string(shortcutsJSON),
		"Shortcuts":     shortcuts,
		"History":       history,
	})
}

// probeNodeShellExec executes a command via proxy on the probe.
func (h *Handler) probeNodeShellExec(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false, "output": "未登录或会话已过期。", "cwd": ""})
		return
	}

	nodeIDStr := c.Query("id")
	nodeID, _ := strconv.ParseInt(nodeIDStr, 10, 64)

	command := strings.TrimSpace(c.PostForm("command"))
	
	sess := sessions.Default(c)
	sessionKey := fmt.Sprintf("probe_cwd_%d", nodeID)
	cwd, _ := sess.Get(sessionKey).(string)
	if cwd == "" {
		cwd = "~"
	}

	if command == "" {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "output": "命令不能为空。", "cwd": cwd})
		return
	}

	shell.AppendHistory(h.cfg.DataDir, username, command)

	respJSONStr, err := tunnel.OpenExecStream(nodeID, cwd, command)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "output": "[代理转发错误] " + err.Error(), "cwd": cwd})
		return
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(respJSONStr), &parsed); err == nil {
		if newCWD, ok := parsed["cwd"].(string); ok && newCWD != cwd {
			sess.Set(sessionKey, newCWD)
			_ = sess.Save()
		}
		c.JSON(http.StatusOK, parsed)
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "output": "[探针端解析错误] " + respJSONStr, "cwd": cwd})
	}
}

// probeNodeLog renders the log interface for a specific probe node.
func (h *Handler) probeNodeLog(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}
	nodeIDStr := c.Query("id")
	nodeID, _ := strconv.ParseInt(nodeIDStr, 10, 64)
	node, err := store.GetProbeNodeByID(h.dbConn, nodeID)
	if err != nil {
		c.String(http.StatusNotFound, "node not found")
		return
	}

	c.HTML(http.StatusOK, "probe_manage_log.html", gin.H{
		"Title": "探针日志 - " + node.Name,
		"Node":  node,
	})
}

// probeNodeLogData fetches the latest logs from the remote probe.
func (h *Handler) probeNodeLogData(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	nodeIDStr := c.Query("id")
	nodeID, _ := strconv.ParseInt(nodeIDStr, 10, 64)

	output, err := tunnel.OpenLogStream(nodeID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "data": output})
}
