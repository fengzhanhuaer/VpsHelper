package web

import (
	"net/http"
	"strings"

	"vpshelper-go/internal/cloudflare"
	"vpshelper-go/internal/store"

	"github.com/gin-gonic/gin"
)

func (h *Handler) cloudflarePage(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	settings, err := store.GetSettings(h.dbConn, []string{
		"cf_api_token", "cf_zone_id", "cf_block_uris", "cf_block_ips",
		"cf_account_id", "cf_app_id", "cf_policy_id", "cf_allow_ips",
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
			"Token":     settings["cf_api_token"],
			"ZoneID":    settings["cf_zone_id"],
			"BlockURIs": cfBlockURIs,
			"BlockIPs":  cfBlockIPs,
			"AccountID": settings["cf_account_id"],
			"AppID":     settings["cf_app_id"],
			"PolicyID":  settings["cf_policy_id"],
			"AllowIPs":  settings["cf_allow_ips"],
		})
		return
	}

	// POST save
	cfToken := strings.TrimSpace(c.PostForm("cf_api_token"))
	cfZoneID := strings.TrimSpace(c.PostForm("cf_zone_id"))
	cfBlockURIs := strings.TrimSpace(c.PostForm("cf_block_uris"))
	cfBlockIPs := strings.TrimSpace(c.PostForm("cf_block_ips"))
	cfAccountID := strings.TrimSpace(c.PostForm("cf_account_id"))
	cfAppID := strings.TrimSpace(c.PostForm("cf_app_id"))
	cfPolicyID := strings.TrimSpace(c.PostForm("cf_policy_id"))
	cfAllowIPs := strings.TrimSpace(c.PostForm("cf_allow_ips"))

	_ = store.SetSetting(h.dbConn, "cf_api_token", cfToken)
	_ = store.SetSetting(h.dbConn, "cf_zone_id", cfZoneID)
	_ = store.SetSetting(h.dbConn, "cf_block_uris", cfBlockURIs)
	_ = store.SetSetting(h.dbConn, "cf_block_ips", cfBlockIPs)
	_ = store.SetSetting(h.dbConn, "cf_account_id", cfAccountID)
	_ = store.SetSetting(h.dbConn, "cf_app_id", cfAppID)
	_ = store.SetSetting(h.dbConn, "cf_policy_id", cfPolicyID)
	_ = store.SetSetting(h.dbConn, "cf_allow_ips", cfAllowIPs)

	c.HTML(http.StatusOK, "cloudflare.html", gin.H{
		"Title":     "Cloudflare Settings",
		"Token":     cfToken,
		"ZoneID":    cfZoneID,
		"BlockURIs": cfBlockURIs,
		"BlockIPs":  cfBlockIPs,
		"AccountID": cfAccountID,
		"AppID":     cfAppID,
		"PolicyID":  cfPolicyID,
		"AllowIPs":  cfAllowIPs,
		"Message":   "配置已保存。",
		"MsgOK":     true,
	})
}

func (h *Handler) cloudflareSync(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	cfToken := strings.TrimSpace(c.PostForm("cf_api_token"))
	cfZoneID := strings.TrimSpace(c.PostForm("cf_zone_id"))
	cfBlockURIs := strings.TrimSpace(c.PostForm("cf_block_uris"))
	cfBlockIPs := strings.TrimSpace(c.PostForm("cf_block_ips"))
	cfAccountID := strings.TrimSpace(c.PostForm("cf_account_id"))
	cfAppID := strings.TrimSpace(c.PostForm("cf_app_id"))
	cfPolicyID := strings.TrimSpace(c.PostForm("cf_policy_id"))
	cfAllowIPs := strings.TrimSpace(c.PostForm("cf_allow_ips"))

	// Save first
	_ = store.SetSetting(h.dbConn, "cf_api_token", cfToken)
	_ = store.SetSetting(h.dbConn, "cf_zone_id", cfZoneID)
	_ = store.SetSetting(h.dbConn, "cf_block_uris", cfBlockURIs)
	_ = store.SetSetting(h.dbConn, "cf_block_ips", cfBlockIPs)
	_ = store.SetSetting(h.dbConn, "cf_account_id", cfAccountID)
	_ = store.SetSetting(h.dbConn, "cf_app_id", cfAppID)
	_ = store.SetSetting(h.dbConn, "cf_policy_id", cfPolicyID)
	_ = store.SetSetting(h.dbConn, "cf_allow_ips", cfAllowIPs)

	action := c.PostForm("action")
	var errMsg string
	var succMsg string

	client := cloudflare.NewAPIClient(cfToken, cfAccountID, cfZoneID)

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
		if err := client.SyncWhiteList(cfAppID, cfPolicyID, validIPs); err != nil {
			errMsg = "推送 ZeroTrust 白名单失败: " + err.Error()
		} else {
			succMsg = "同步推送到 ZeroTrust 策略放行规则成功！"
		}
	} else {
		errMsg = "未知的同步动作。"
	}

	c.HTML(http.StatusOK, "cloudflare.html", gin.H{
		"Title":     "Cloudflare Settings",
		"Token":     cfToken,
		"ZoneID":    cfZoneID,
		"BlockURIs": cfBlockURIs,
		"BlockIPs":  cfBlockIPs,
		"AccountID": cfAccountID,
		"AppID":     cfAppID,
		"PolicyID":  cfPolicyID,
		"AllowIPs":  cfAllowIPs,
		"Error":     errMsg,
		"Message":   succMsg,
		"MsgOK":     succMsg != "",
	})
}
