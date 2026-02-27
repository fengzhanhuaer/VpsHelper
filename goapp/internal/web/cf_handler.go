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
func (h *Handler) cfIndex(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	if c.Request.Method == http.MethodGet {
		settings, err := store.GetSettings(h.dbConn, []string{"cf_api_token"})
		if err != nil {
			c.String(http.StatusInternalServerError, "load settings failed")
			return
		}

		c.HTML(http.StatusOK, "cloudflare_index.html", gin.H{
			"Title":   "Cloudflare 管理",
			"Token":   settings["cf_api_token"],
			"Message": c.Query("message"),
			"MsgOK":   c.Query("status") == "ok",
		})
		return
	}

	// POST save for global credentials
	cfToken := strings.TrimSpace(c.PostForm("cf_api_token"))
	_ = store.SetSetting(h.dbConn, "cf_api_token", cfToken)

	c.Redirect(http.StatusSeeOther, "/cloudflare?message=公共凭据已保存&status=ok")
}

func (h *Handler) cfBlocklistPage(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	settings, err := store.GetSettings(h.dbConn, []string{
		"cf_block_uris", "cf_block_ips", "tg_bot_webhook_secret",
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

		c.HTML(http.StatusOK, "cloudflare_blocklist.html", gin.H{
			"Title":     "🔥 防火墙 BlockList",
			"BlockURIs": cfBlockURIs,
			"BlockIPs":  cfBlockIPs,
			"Message":   c.Query("message"),
			"MsgOK":     c.Query("status") == "ok",
			"Error":     c.Query("error"),
		})
		return
	}

	// POST save only
	cfBlockURIs := strings.TrimSpace(c.PostForm("cf_block_uris"))
	cfBlockIPs := strings.TrimSpace(c.PostForm("cf_block_ips"))

	_ = store.SetSetting(h.dbConn, "cf_block_uris", cfBlockURIs)
	_ = store.SetSetting(h.dbConn, "cf_block_ips", cfBlockIPs)

	c.Redirect(http.StatusSeeOther, "/cloudflare/blocklist?message=配置已保存（不同步）&status=ok")
}

func (h *Handler) cfBlocklistSync(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	cfBlockURIs := strings.TrimSpace(c.PostForm("cf_block_uris"))
	cfBlockIPs := strings.TrimSpace(c.PostForm("cf_block_ips"))

	// Save first
	_ = store.SetSetting(h.dbConn, "cf_block_uris", cfBlockURIs)
	_ = store.SetSetting(h.dbConn, "cf_block_ips", cfBlockIPs)

	settings, _ := store.GetSettings(h.dbConn, []string{"cf_api_token", "cf_account_id", "cf_zone_id", "cf_zone_domain"})
	cfToken := settings["cf_api_token"]
	cfAccountID := settings["cf_account_id"]
	cfZoneID := settings["cf_zone_id"]
	cfZoneDomain := settings["cf_zone_domain"]

	if cfToken == "" {
		c.Redirect(http.StatusSeeOther, "/cloudflare/blocklist?error=缺少%20API%20Token，请在公共凭据中设置")
		return
	}

	client := cloudflare.NewAPIClient(cfToken, cfAccountID, cfZoneID)

	// Always actively query the current Account ID
	if id, err := client.FetchAccountID(); err == nil && id != "" {
		cfAccountID = id
		client.AccountID = cfAccountID
		_ = store.SetSetting(h.dbConn, "cf_account_id", cfAccountID)
	}

	// Actively resolve zone ID every time to avoid using cached ID when domain changes
	domain := cfZoneDomain
	if domain == "" {
		host := c.Request.Host
		if idx := strings.LastIndex(host, ":"); idx != -1 {
			host = host[:idx]
		}
		domain = host
	}
	if domain != "" {
		if id, err := client.LookupZoneID(domain); err == nil && id != "" {
			cfZoneID = id
			if cfZoneDomain == "" {
				cfZoneDomain = domain
			}
			client = cloudflare.NewAPIClient(cfToken, cfAccountID, cfZoneID)
			_ = store.SetSetting(h.dbConn, "cf_zone_id", cfZoneID)
			_ = store.SetSetting(h.dbConn, "cf_zone_domain", cfZoneDomain)
		}
	}

	// Make sync call
	var validURIs, validIPs []string
	for _, u := range strings.Split(cfBlockURIs, "\n") {
		if t := strings.TrimSpace(u); t != "" {
			validURIs = append(validURIs, t)
		}
	}
	for _, ip := range strings.Split(cfBlockIPs, "\n") {
		if t := strings.TrimSpace(ip); t != "" {
			validIPs = append(validIPs, t)
		}
	}

	if err := client.SyncBlockList(validURIs, validIPs); err != nil {
		c.Redirect(http.StatusSeeOther, "/cloudflare/blocklist?error=推送失败:"+err.Error())
	} else {
		c.Redirect(http.StatusSeeOther, "/cloudflare/blocklist?message=同步推送到防火墙屏蔽规则成功！&status=ok")
	}
}

func (h *Handler) cfWhitelistPage(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	settings, err := store.GetSettings(h.dbConn, []string{"cf_allow_ips"})
	if err != nil {
		c.String(http.StatusInternalServerError, "load settings failed")
		return
	}

	if c.Request.Method == http.MethodGet {
		c.HTML(http.StatusOK, "cloudflare_whitelist.html", gin.H{
			"Title":    "🛡️ ZeroTrust 白名单",
			"AllowIPs": settings["cf_allow_ips"],
			"Message":  c.Query("message"),
			"MsgOK":    c.Query("status") == "ok",
			"Error":    c.Query("error"),
		})
		return
	}

	// POST save only
	cfAllowIPs := strings.TrimSpace(c.PostForm("cf_allow_ips"))
	_ = store.SetSetting(h.dbConn, "cf_allow_ips", cfAllowIPs)

	c.Redirect(http.StatusSeeOther, "/cloudflare/whitelist?message=配置已保存（不同步）&status=ok")
}

func (h *Handler) cfWhitelistSync(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	cfAllowIPs := strings.TrimSpace(c.PostForm("cf_allow_ips"))
	_ = store.SetSetting(h.dbConn, "cf_allow_ips", cfAllowIPs)

	settings, _ := store.GetSettings(h.dbConn, []string{"cf_api_token", "cf_account_id", "cf_policy_id"})
	cfToken := settings["cf_api_token"]
	cfAccountID := settings["cf_account_id"]
	cfPolicyID := settings["cf_policy_id"]

	if cfToken == "" {
		c.Redirect(http.StatusSeeOther, "/cloudflare/whitelist?error=缺少%20API%20Token，请在公共凭据中设置")
		return
	}

	client := cloudflare.NewAPIClient(cfToken, cfAccountID, "")

	// Always actively query the current Account ID
	if id, err := client.FetchAccountID(); err == nil && id != "" {
		cfAccountID = id
		client.AccountID = cfAccountID
		_ = store.SetSetting(h.dbConn, "cf_account_id", cfAccountID)
	}

	var validIPs []string
	for _, ip := range strings.Split(cfAllowIPs, "\n") {
		if t := strings.TrimSpace(ip); t != "" {
			validIPs = append(validIPs, t)
		}
	}

	if newPolicyID, err := client.SyncReusablePolicy("", validIPs); err != nil {
		c.Redirect(http.StatusSeeOther, "/cloudflare/whitelist?error=推送失败:"+err.Error())
	} else {
		if cfPolicyID == "" && newPolicyID != "" {
			_ = store.SetSetting(h.dbConn, "cf_policy_id", newPolicyID)
		}
		c.Redirect(http.StatusSeeOther, "/cloudflare/whitelist?message=同步推送到%20ZeroTrust%20全局复用策略成功！&status=ok")
	}
}
