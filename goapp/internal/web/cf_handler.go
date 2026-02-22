package web

import (
	"net"
	"net/http"
	"strings"

	"vpshelper-go/internal/cloudflare"
	"vpshelper-go/internal/store"

	"github.com/gin-gonic/gin"
)

// realClientIP extracts the best-effort real IP from a gin context.
// It respects CF-Connecting-IP (Cloudflare), X-Real-IP, X-Forwarded-For, then falls back to RemoteAddr.
func realClientIP(c *gin.Context) string {
	if ip := strings.TrimSpace(c.GetHeader("CF-Connecting-IP")); ip != "" {
		return ip
	}
	if ip := strings.TrimSpace(c.GetHeader("X-Real-IP")); ip != "" {
		return ip
	}
	if fwd := strings.TrimSpace(c.GetHeader("X-Forwarded-For")); fwd != "" {
		parts := strings.SplitN(fwd, ",", 2)
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err == nil {
		return host
	}
	return c.Request.RemoteAddr
}

// cloudflareAddSelf appends the caller's real IP to cf_allow_ips (if not already present)
// and responds with JSON so the frontend can call it via fetch without a full page reload.
func (h *Handler) cloudflareAddSelf(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false, "error": "not logged in"})
		return
	}

	ip := realClientIP(c)
	if ip == "" || net.ParseIP(ip) == nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "无法获取有效的客户端 IP: " + ip})
		return
	}

	// Normalise: ensure IPv4 gets /32
	parsed := net.ParseIP(ip)
	var cidrIP string
	if v4 := parsed.To4(); v4 != nil {
		cidrIP = v4.String() + "/32"
	} else {
		cidrIP = parsed.String() + "/128"
	}

	settings, err := store.GetSettings(h.dbConn, []string{"cf_allow_ips"})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": "load settings failed"})
		return
	}

	existing := strings.TrimSpace(settings["cf_allow_ips"])
	lines := strings.Split(existing, "\n")

	// Check duplicate
	for _, line := range lines {
		if strings.TrimSpace(line) == cidrIP || strings.TrimSpace(line) == ip {
			c.JSON(http.StatusOK, gin.H{"ok": true, "ip": cidrIP, "message": "IP 已在白名单中: " + cidrIP})
			return
		}
	}

	// Append
	if existing == "" {
		existing = cidrIP
	} else {
		existing = existing + "\n" + cidrIP
	}
	_ = store.SetSetting(h.dbConn, "cf_allow_ips", existing)

	// Reset DDNS watch key so the background service picks up the change immediately
	_ = store.SetSetting(h.dbConn, "cf_ddns_last_key", "")

	c.JSON(http.StatusOK, gin.H{"ok": true, "ip": cidrIP, "message": "已将 " + cidrIP + " 添加到白名单"})
}

func (h *Handler) cloudflarePage(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	settings, err := store.GetSettings(h.dbConn, []string{
		"cf_api_token", "cf_zone_id", "cf_zone_domain", "cf_block_uris", "cf_block_ips",
		"cf_account_id", "cf_policy_id", "cf_allow_ips",
		"tg_bot_webhook_secret",
	})
	if err != nil {
		c.String(http.StatusInternalServerError, "load settings failed")
		return
	}

	if c.Request.Method == http.MethodGet {
		cfBlockURIs := settings["cf_block_uris"]
		if cfBlockURIs == "" {
			secret := settings["tg_bot_webhook_secret"]
			if secret != "" {
				cfBlockURIs = "/api/" + secret
			} else {
				cfBlockURIs = "/api/"
			}
		}

		cfBlockIPs := settings["cf_block_ips"]
		if cfBlockIPs == "" {
			cfBlockIPs = "AS62041\nAS59930\nAS44907\nAS211157" // Telegram ASNs
		}

		c.HTML(http.StatusOK, "cloudflare.html", gin.H{
			"Title":     "Cloudflare Settings",
			"Token":      settings["cf_api_token"],
			"ZoneID":     settings["cf_zone_id"],
			"ZoneDomain": settings["cf_zone_domain"],
			"BlockURIs":  cfBlockURIs,
			"BlockIPs":   cfBlockIPs,
			"AccountID":  settings["cf_account_id"],
			"PolicyID":   settings["cf_policy_id"],
			"AllowIPs":   settings["cf_allow_ips"],
		})
		return
	}

	// POST save
	cfToken := strings.TrimSpace(c.PostForm("cf_api_token"))
	cfZoneID := strings.TrimSpace(c.PostForm("cf_zone_id"))
	cfZoneDomain := strings.TrimSpace(c.PostForm("cf_zone_domain"))
	cfBlockURIs := strings.TrimSpace(c.PostForm("cf_block_uris"))
	cfBlockIPs := strings.TrimSpace(c.PostForm("cf_block_ips"))
	cfAccountID := strings.TrimSpace(c.PostForm("cf_account_id"))
	cfPolicyID := strings.TrimSpace(c.PostForm("cf_policy_id"))
	cfAllowIPs := strings.TrimSpace(c.PostForm("cf_allow_ips"))

	_ = store.SetSetting(h.dbConn, "cf_api_token", cfToken)
	_ = store.SetSetting(h.dbConn, "cf_zone_id", cfZoneID)
	_ = store.SetSetting(h.dbConn, "cf_zone_domain", cfZoneDomain)
	_ = store.SetSetting(h.dbConn, "cf_block_uris", cfBlockURIs)
	_ = store.SetSetting(h.dbConn, "cf_block_ips", cfBlockIPs)
	_ = store.SetSetting(h.dbConn, "cf_account_id", cfAccountID)
	_ = store.SetSetting(h.dbConn, "cf_policy_id", cfPolicyID)
	_ = store.SetSetting(h.dbConn, "cf_allow_ips", cfAllowIPs)

	c.HTML(http.StatusOK, "cloudflare.html", gin.H{
		"Title":      "Cloudflare Settings",
		"Token":      cfToken,
		"ZoneID":     cfZoneID,
		"ZoneDomain": cfZoneDomain,
		"BlockURIs":  cfBlockURIs,
		"BlockIPs":   cfBlockIPs,
		"AccountID":  cfAccountID,
		"PolicyID":   cfPolicyID,
		"AllowIPs":   cfAllowIPs,
		"Message":    "配置已保存。",
		"MsgOK":      true,
	})
}

func (h *Handler) cloudflareSync(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	cfToken := strings.TrimSpace(c.PostForm("cf_api_token"))
	cfZoneID := strings.TrimSpace(c.PostForm("cf_zone_id"))
	cfZoneDomain := strings.TrimSpace(c.PostForm("cf_zone_domain"))
	cfBlockURIs := strings.TrimSpace(c.PostForm("cf_block_uris"))
	cfBlockIPs := strings.TrimSpace(c.PostForm("cf_block_ips"))
	cfAccountID := strings.TrimSpace(c.PostForm("cf_account_id"))
	cfPolicyID := strings.TrimSpace(c.PostForm("cf_policy_id"))
	cfAllowIPs := strings.TrimSpace(c.PostForm("cf_allow_ips"))

	// Save first
	_ = store.SetSetting(h.dbConn, "cf_api_token", cfToken)
	_ = store.SetSetting(h.dbConn, "cf_zone_id", cfZoneID)
	_ = store.SetSetting(h.dbConn, "cf_zone_domain", cfZoneDomain)
	_ = store.SetSetting(h.dbConn, "cf_block_uris", cfBlockURIs)
	_ = store.SetSetting(h.dbConn, "cf_block_ips", cfBlockIPs)
	_ = store.SetSetting(h.dbConn, "cf_account_id", cfAccountID)
	_ = store.SetSetting(h.dbConn, "cf_policy_id", cfPolicyID)
	_ = store.SetSetting(h.dbConn, "cf_allow_ips", cfAllowIPs)

	action := c.PostForm("action")
	var errMsg string
	var succMsg string

	client := cloudflare.NewAPIClient(cfToken, cfAccountID, cfZoneID)

	// If Zone ID is empty, resolve domain automatically
	if cfZoneID == "" {
		domain := cfZoneDomain
		if domain == "" {
			// Auto-detect from request Host (strip port if present)
			host := c.Request.Host
			if idx := strings.LastIndex(host, ":"); idx != -1 {
				host = host[:idx]
			}
			domain = host
		}
		if domain != "" {
			if id, err := client.LookupZoneID(domain); err != nil {
				errMsg = "自动查询 Zone ID 失败 (" + domain + "): " + err.Error()
			} else {
				cfZoneID = id
				if cfZoneDomain == "" {
					cfZoneDomain = domain
				}
				client = cloudflare.NewAPIClient(cfToken, cfAccountID, cfZoneID)
				_ = store.SetSetting(h.dbConn, "cf_zone_id", cfZoneID)
				_ = store.SetSetting(h.dbConn, "cf_zone_domain", cfZoneDomain)
			}
		}
	}

	if action == "sync_block" {
		uris := strings.Split(cfBlockURIs, "\n")
		var validURIs []string
		for _, u := range uris {
			u = strings.TrimSpace(u)
			if u != "" {
				validURIs = append(validURIs, u)
			}
		}

		ips := strings.Split(cfBlockIPs, "\n")
		var validIPs []string
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				validIPs = append(validIPs, ip)
			}
		}
		if err := client.SyncBlockList(validURIs, validIPs); err != nil {
			errMsg = "推送防火墙 BlockList 失败: " + err.Error()
		} else {
			succMsg = "同步推送到防火墙屏蔽规则成功！"
		}
	} else if action == "sync_allow" {
		ips := strings.Split(cfAllowIPs, "\n")
		var validIPs []string
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				validIPs = append(validIPs, ip)
			}
		}
		if newPolicyID, err := client.SyncReusablePolicy(cfPolicyID, validIPs); err != nil {
			errMsg = "推送 ZeroTrust 复用策略白名单失败: " + err.Error()
		} else {
			if cfPolicyID == "" && newPolicyID != "" {
				cfPolicyID = newPolicyID
				_ = store.SetSetting(h.dbConn, "cf_policy_id", cfPolicyID)
			}
			succMsg = "同步推送到 ZeroTrust 全局复用策略成功！"
		}
	} else {
		errMsg = "未知的同步动作。"
	}

	c.HTML(http.StatusOK, "cloudflare.html", gin.H{
		"Title":      "Cloudflare Settings",
		"Token":      cfToken,
		"ZoneID":     cfZoneID,
		"ZoneDomain": cfZoneDomain,
		"BlockURIs":  cfBlockURIs,
		"BlockIPs":   cfBlockIPs,
		"AccountID":  cfAccountID,
		"PolicyID":   cfPolicyID,
		"AllowIPs":   cfAllowIPs,
		"Error":      errMsg,
		"Message":    succMsg,
		"MsgOK":      succMsg != "",
	})
}
