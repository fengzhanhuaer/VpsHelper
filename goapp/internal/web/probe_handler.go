package web

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"vpshelper-go/internal/cloudflare"
	"vpshelper-go/internal/firewall"
	"vpshelper-go/internal/security"
	"vpshelper-go/internal/store"
	"vpshelper-go/internal/tunnel"
)

// generateProbeSecret generates a cryptographically random 32-byte hex secret.
func generateProbeSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
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
			note := strings.TrimSpace(c.PostForm("note"))
			if name == "" {
				message = "节点名称不能为空。"
				break
			}
			secret, err := generateProbeSecret()
			if err != nil {
				message = "密钥生成失败：" + err.Error()
				break
			}
			if _, err := store.CreateProbeNode(h.dbConn, name, note, secret); err != nil {
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
			price := strings.TrimSpace(c.PostForm("price"))
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

			if err := store.UpdateProbeNodeDetails(h.dbConn, id, name, note, vendor, price, expiredAt, intervalVal); err != nil {
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
			if !strings.Contains(host, "localhost") && !strings.Contains(host, "127.0.0.1") {
				scheme = "https"
			}
			baseURL := fmt.Sprintf("%s://%s", scheme, host)

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

		case "save_settings":
			privatePort := strings.TrimSpace(c.PostForm("probe_private_port"))
			addressIn := strings.TrimSpace(c.PostForm("probe_address"))
			enableDDNS := c.PostForm("enable_ddns") == "on" || c.PostForm("enable_ddns") == "true"
			
			if privatePort == "" {
				privatePort = "15019"
			}
			var publicAddress, ddnsDomain string
			if enableDDNS {
				ddnsDomain = addressIn
			} else {
				publicAddress = addressIn
			}
			
			historyDays := strings.TrimSpace(c.PostForm("probe_history_days"))
			if historyDays == "" {
				historyDays = "90"
			}

			_ = store.SetSetting(h.dbConn, "probe_private_port", privatePort)
			_ = store.SetSetting(h.dbConn, "probe_public_address", publicAddress)
			_ = store.SetSetting(h.dbConn, "probe_ddns_domain", ddnsDomain)
			_ = store.SetSetting(h.dbConn, "probe_history_days", historyDays)
			
			message = "设置已保存，端口更改需重启服务生效。"
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
				// Run a synchronous trigger so the user sees the result immediately.
				if errMsg := cloudflare.TriggerProbeDDNS(h.dbConn); errMsg != "" {
					message = message + " | DDNS 更新失败：" + errMsg
					msgOK = false
				} else {
					message = message + " | DDNS 已成功触发更新。"
				}
			}
		}
	}

	settings, err := store.GetSettings(h.dbConn, []string{"probe_private_port", "probe_public_address", "probe_ddns_domain", "probe_history_days"})
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
	if !strings.Contains(host, "localhost") && !strings.Contains(host, "127.0.0.1") {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, host)

	// Consolidate for frontend
	combinedAddress := publicAddress
	if ddnsDomain != "" {
		combinedAddress = ddnsDomain
	}
	enableDDNS := ddnsDomain != ""

	c.HTML(http.StatusOK, "probe_nodes.html", gin.H{
		"Title":         "探针节点管理",
		"Message":       message,
		"MsgOK":         msgOK,
		"Nodes":         nodes,
		"BaseURL":       baseURL,
		"PrivatePort":   privatePort,
		"Address":       combinedAddress,
		"EnableDDNS":    enableDDNS,
		"HistoryDays":   historyDays,
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

	// 优先引入 cloudflare 的函数，确保包导入（如果不报错，意味着已经在顶层引入过了或者可以通过 goimports 自动整理，但在文件顶部可能没引用 cloudflare 包，需要在文件开头处理）
	settings, _ := store.GetSettings(h.dbConn, []string{"probe_private_port", "probe_public_address", "probe_ddns_domain"})
	
	port := settings["probe_private_port"]
	if port == "" {
		port = "15019"
	}

	address := ""
	ddns := settings["probe_ddns_domain"]
	publicAddr := settings["probe_public_address"]

	// 1. 如果有域名优先使用域名
	if ddns != "" {
		address = fmt.Sprintf("ws://%s:%s/tunnel", ddns, port)
	} else if publicAddr != "" {
		// 2. 没有域名则使用写死的公网IP/地址
		address = publicAddr
	} else {
		// 3. 都没有，则自动探测公网IP并下发（优先送 IPv4，后备 IPv6。或者如果探测不到就用 c.ClientIP() 回退）
		ips := cloudflare.GetPublicIPs()
		if ips.IPv4 != "" {
			address = fmt.Sprintf("ws://%s:%s/tunnel", ips.IPv4, port)
		} else if ips.IPv6 != "" {
			address = fmt.Sprintf("ws://[%s]:%s/tunnel", ips.IPv6, port)
		} else {
			clientIP := c.ClientIP()
			if strings.Contains(clientIP, ":") {
				address = fmt.Sprintf("ws://[%s]:%s/tunnel", clientIP, port)
			} else {
				address = fmt.Sprintf("ws://%s:%s/tunnel", clientIP, port)
			}
		}
	}

	// 统一针对没写协议头的 address 做标准化修饰（如果是从 publicAddr 拿出来的纯粹 ip:port，或者裸域名）
	if !strings.HasPrefix(address, "ws") && !strings.HasPrefix(address, "http") {
		// none scheme
		if !strings.Contains(address, ":") || net.ParseIP(address) != nil || (strings.Contains(address, ":") && strings.HasPrefix(address, "[")) {
			// pure domain or IP without port
			address = fmt.Sprintf("ws://%s:%s/tunnel", address, port)
		} else {
			// has port attached, just add scheme
			address = "ws://" + address
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

	c.JSON(http.StatusOK, gin.H{
		"success":         true,
		"node_id":         node.ID,
		"name":            node.Name,
		"address":         address,
		"report_interval": node.ReportInterval,
	})
}

// probeDashboard renders the live status dashboard for all probe nodes.
func (h *Handler) probeDashboard(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	nodes, err := store.ListProbeNodes(h.dbConn)
	if err != nil {
		c.String(http.StatusInternalServerError, "加载节点列表失败")
		return
	}

	c.HTML(http.StatusOK, "probe_dashboard.html", gin.H{
		"Title": "探针状态大屏",
		"Nodes": nodes,
	})
}
