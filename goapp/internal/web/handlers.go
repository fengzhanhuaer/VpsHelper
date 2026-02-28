package web

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gotd/td/telegram/auth"
	"golang.org/x/crypto/bcrypt"

	"vpshelper-go/internal/config"
	"vpshelper-go/internal/d1"
	"vpshelper-go/internal/firewall"
	"vpshelper-go/internal/logger"
	"vpshelper-go/internal/shell"
	"vpshelper-go/internal/ssh"
	"vpshelper-go/internal/status"
	"vpshelper-go/internal/store"
	"vpshelper-go/internal/tg"
	"vpshelper-go/internal/tgbot"
	"vpshelper-go/internal/update"
	"vpshelper-go/internal/version"
)

type Handler struct {
	cfg    config.Config
	dbConn *sql.DB
}

func Register(router *gin.Engine, cfg config.Config, dbConn *sql.DB) {
	h := &Handler{cfg: cfg, dbConn: dbConn}

	go h.autoDatabaseCleanup()

	router.GET("/", h.index)
	router.GET("/home", h.home)
	router.GET("/login", h.login)
	router.POST("/login", h.login)
	router.GET("/register", h.register)
	router.POST("/register", h.register)
	router.GET("/logout", h.logout)
	router.GET("/change_password", h.changePassword)
	router.POST("/change_password", h.changePassword)
	router.GET("/settings/github", h.githubSettings)
	router.POST("/settings/github", h.githubSettings)
	router.GET("/auth/github/login", h.githubLogin)
	router.GET("/auth/github/callback", h.githubCallback)
	router.GET("/tg_helper", h.tgHelper)
	router.POST("/tg_helper", h.tgHelperToggle)
	router.GET("/tg/settings", h.tgSettings)
	router.POST("/tg/settings", h.tgSettings)
	router.GET("/tg/bot/settings", h.tgBotSettings)
	router.POST("/tg/bot/settings", h.tgBotSettings)
	router.POST("/tg/bot/test", h.tgBotTestMessage)
	router.POST("/tg/bot/webhook_info", h.tgBotWebhookInfo)
	router.GET("/tg/chat", h.tgChat)
	router.GET("/tg/chat/messages", h.tgChatMessages)
	router.GET("/tg/chat/search", h.tgChatSearch)
	router.POST("/tg/chat/send", h.tgChatSend)
	router.GET("/tg/login/start", h.tgLoginStart)
	router.POST("/tg/login/start", h.tgLoginStart)
	router.GET("/tg/login/verify", h.tgLoginVerify)
	router.POST("/tg/login/verify", h.tgLoginVerify)
	router.GET("/tg/accounts", h.tgAccounts)
	router.POST("/tg/accounts", h.tgAccounts)
	router.GET("/tg/proxy", h.tgProxy)
	router.POST("/tg/proxy", h.tgProxy)
	router.GET("/tg/dialogs", h.tgDialogs)
	router.POST("/tg/dialogs", h.tgDialogs)
	router.POST("/tg/dialogs/refresh/stream", h.tgDialogsRefreshStream)
	router.GET("/tg/auto/reply", h.tgAutoReply)
	router.POST("/tg/auto/reply", h.tgAutoReply)
	router.GET("/tg/auto/send", h.tgAutoSend)
	router.POST("/tg/auto/send", h.tgAutoSend)
	router.GET("/tg/auto/send/new", h.tgAutoSendNew)
	router.POST("/tg/auto/send/new", h.tgAutoSendNew)
	router.GET("/tg/auto/send/history", h.tgAutoSendHistory)
	router.GET("/settings/database", func(c *gin.Context) { c.Redirect(http.StatusMovedPermanently, "/cloudflare/database") })
	router.GET("/cloudflare/database", h.databaseSettings)
	router.POST("/cloudflare/database", h.databaseSettings)
	router.POST("/cloudflare/database/backup/stream", h.databaseBackupStream)
	router.POST("/cloudflare/database/pull/stream", h.databasePullStream)
	router.GET("/cloudflare/database/tables", h.databaseTableList)
	router.GET("/cloudflare/database/table/data", h.databaseTableData)
	router.GET("/settings/ssh", h.sshSettings)
	router.POST("/settings/ssh", h.sshSettings)
	// System Settings
	router.GET("/system/settings", h.systemSettings)
	router.GET("/system/update", h.systemUpdate)
	router.POST("/system/update", h.systemUpdate)
	router.POST("/system/update/stream", h.systemUpdateStream)
	router.GET("/server/status", h.serverStatus)
	router.GET("/server/status/data", h.serverStatusData)
	router.GET("/system/log", h.systemLog)
	router.GET("/system/log/data", h.systemLogData)
	router.GET("/shell", h.shellConsole)
	router.POST("/shell/exec", h.shellExec)
	router.POST("/shell/shortcuts/add", h.shellShortcutsAdd)
	router.POST("/shell/shortcuts/delete/:id", h.shellShortcutsDelete)
	router.POST("/shell/shortcuts/clear", h.shellShortcutsClear)
	router.GET("/firewall", h.firewallPage)
	router.POST("/firewall", h.firewallPage)
	router.GET("/cloudflare", h.cfIndex)
	router.POST("/cloudflare", h.cfIndex)
	router.GET("/cloudflare/blocklist", h.cfBlocklistPage)
	router.POST("/cloudflare/blocklist", h.cfBlocklistPage)
	router.POST("/cloudflare/blocklist/sync", h.cfBlocklistSync)
	router.GET("/cloudflare/whitelist", h.cfWhitelistPage)
	router.POST("/cloudflare/whitelist", h.cfWhitelistPage)
	router.POST("/cloudflare/whitelist/sync", h.cfWhitelistSync)
	router.POST("/cloudflare/addself", h.cloudflareAddSelf)
	router.GET("/ns/lottery", h.nsLottery)
	router.POST("/ns/lottery", h.nsLottery)
	router.GET("/probe/nodes", h.probeManagement)
	router.GET("/probe/nodes/list", h.probeNodes)
	router.POST("/probe/nodes/list", h.probeNodes)
	router.GET("/probe/nodes/comm", h.probeNodes)
	router.POST("/probe/nodes/comm", h.probeNodes)
	router.GET("/probe/nodes/deleted", h.probeNodesDeleted)
	router.POST("/probe/nodes/deleted", h.probeNodesDeleted)
	router.GET("/probe/node/manage", h.probeNodeManage)
	router.GET("/probe/node/detail", h.probeNodeDetail)
	router.GET("/probe/node/shell", h.probeNodeShell)
	router.POST("/probe/node/shell/exec", h.probeNodeShellExec)
	router.GET("/probe/node/log", h.probeNodeLog)
	router.GET("/probe/node/log/data", h.probeNodeLogData)
	router.GET("/probe/nodes/tasks", h.probeTasks)
	router.POST("/probe/nodes/tasks", h.probeTasks)
	router.GET("/probe/dashboard", h.probeDashboard)
	// Add backward compatibility for cached 301 redirects from older code
	router.GET("/probe/dashboard/status", func(c *gin.Context) { c.Redirect(http.StatusFound, "/probe/dashboard") })
	router.GET("/probe/dashboard/netstatus", func(c *gin.Context) { c.Redirect(http.StatusFound, "/probe/dashboard?tab=netstatus") })
	router.GET("/probe/ws", h.probeDashboardWS)
	router.GET("/api/probe/discover", h.probeDiscover)
	router.GET("/api/probe/ping_history", h.probePingHistory)
	router.GET("/api/probe/latest_binary", h.probeLatestBinary)
	router.GET("/api/probe/install", h.probeInstallScript)
	router.POST("/api/:secret", h.tgBotWebhook)

	// AI Assistant routes
	router.GET("/ai/assistant", h.aiAssistant)
	router.POST("/api/ai/chat", h.aiChat)
	router.GET("/api/ai/models", h.getAvailableModels)
}

func (h *Handler) index(c *gin.Context) {
	if h.currentUser(c) != "" {
		c.Redirect(http.StatusFound, "/home")
		return
	}

	hasUsers, err := store.HasUsers(h.dbConn)
	if err != nil {
		c.String(http.StatusInternalServerError, "load users failed")
		return
	}
	if !hasUsers {
		c.Redirect(http.StatusFound, "/register")
		return
	}
	c.Redirect(http.StatusFound, "/login")
}

func (h *Handler) home(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}
	c.HTML(http.StatusOK, "home.html", gin.H{
		"Title":    "VpsHelper",
		"Username": username,
	})
}

func (h *Handler) register(c *gin.Context) {
	hasUsers, err := store.HasUsers(h.dbConn)
	if err != nil {
		c.String(http.StatusInternalServerError, "load users failed")
		return
	}
	// 单用户模式：只要系统中已存在用户，就禁止注册
	if hasUsers {
		c.String(http.StatusForbidden, "注册已关闭（单用户模式）")
		return
	}

	if c.Request.Method == http.MethodGet {
		c.HTML(http.StatusOK, "register.html", gin.H{
			"Title":    "Register",
			"HasUsers": hasUsers,
		})
		return
	}

	username := strings.TrimSpace(c.PostForm("username"))
	password := strings.TrimSpace(c.PostForm("password"))
	confirm := strings.TrimSpace(c.PostForm("confirm"))

	var errMsg string
	if username == "" || password == "" {
		errMsg = "用户名和密码不能为空。"
	} else if password != confirm {
		errMsg = "两次输入的密码不一致。"
	} else {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			errMsg = "密码处理失败。"
		} else if err := store.CreateUser(h.dbConn, username, string(hash)); err != nil {
			errMsg = "用户名已存在。"
		}
	}

	if errMsg != "" {
		c.HTML(http.StatusOK, "register.html", gin.H{
			"Title":    "Register",
			"HasUsers": hasUsers,
			"Error":    errMsg,
		})
		return
	}

	sess := sessions.Default(c)
	sess.Set("user", username)
	_ = sess.Save()
	c.Redirect(http.StatusFound, "/home")
}

func isIPInWhitelist(clientIP, whitelistStr string) bool {
	if whitelistStr == "" {
		return false
	}
	clientIPAddr := net.ParseIP(clientIP)
	if clientIPAddr == nil {
		return false
	}

	entries := strings.FieldsFunc(whitelistStr, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ';'
	})

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			if ip.Equal(clientIPAddr) {
				return true
			}
		} else {
			ips, err := net.LookupIP(entry)
			if err == nil {
				for _, ip := range ips {
					if ip.Equal(clientIPAddr) {
						return true
					}
				}
			}
		}
	}
	return false
}

func (h *Handler) login(c *gin.Context) {
	hasUsers, err := store.HasUsers(h.dbConn)
	if err != nil {
		c.String(http.StatusInternalServerError, "load users failed")
		return
	}
	if !hasUsers {
		c.Redirect(http.StatusFound, "/register")
		return
	}

	// GitHub Authentication Firewall Check
	settings, _ := store.GetSettings(h.dbConn, []string{"github_client_id", "github_client_secret", "github_allowed_user", "github_auth_enabled", "github_whitelist"})
	if settings["github_auth_enabled"] == "true" &&
		strings.TrimSpace(settings["github_client_id"]) != "" &&
		strings.TrimSpace(settings["github_client_secret"]) != "" &&
		strings.TrimSpace(settings["github_allowed_user"]) != "" {

		clientIP := c.ClientIP()
		isWhitelisted := isIPInWhitelist(clientIP, settings["github_whitelist"])

		if !isWhitelisted {
			sess := sessions.Default(c)
			authFlag := sess.Get("github_authorized")
			if authFlag == nil || authFlag.(bool) != true {
				c.Redirect(http.StatusFound, "/auth/github/login")
				return
			}
		}
	}

	if c.Request.Method == http.MethodGet {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"Title": "Login",
		})
		return
	}

	username := strings.TrimSpace(c.PostForm("username"))
	password := strings.TrimSpace(c.PostForm("password"))

	if username == "" || password == "" {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"Title": "Login",
			"Error": "用户名和密码不能为空。",
		})
		return
	}

	hash, err := store.GetPasswordHash(h.dbConn, username)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"Title": "Login",
			"Error": "账号或密码错误。",
		})
		return
	}

	sess := sessions.Default(c)
	sess.Set("user", username)
	_ = sess.Save()
	c.Redirect(http.StatusFound, "/home")
}

func (h *Handler) logout(c *gin.Context) {
	sess := sessions.Default(c)
	sess.Clear()
	_ = sess.Save()
	c.Redirect(http.StatusFound, "/login")
}

func (h *Handler) changePassword(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	if c.Request.Method == http.MethodGet {
		c.HTML(http.StatusOK, "change_password.html", gin.H{
			"Title":    "修改密码",
			"Username": username,
		})
		return
	}

	oldPassword := strings.TrimSpace(c.PostForm("old_password"))
	newPassword := strings.TrimSpace(c.PostForm("new_password"))
	confirmPassword := strings.TrimSpace(c.PostForm("confirm_password"))

	var msg string
	msgOK := false
	if oldPassword == "" || newPassword == "" || confirmPassword == "" {
		msg = "请完整填写旧密码、新密码和确认密码。"
	} else if newPassword != confirmPassword {
		msg = "两次输入的新密码不一致。"
	} else {
		hash, err := store.GetPasswordHash(h.dbConn, username)
		if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(oldPassword)) != nil {
			msg = "旧密码错误。"
		} else {
			newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
			if err != nil {
				msg = "密码处理失败。"
			} else if err := store.UpdatePasswordHash(h.dbConn, username, string(newHash)); err != nil {
				msg = "保存失败。"
			} else {
				msg = "密码已修改。"
				msgOK = true
			}
		}
	}

	c.HTML(http.StatusOK, "change_password.html", gin.H{
		"Title":    "修改密码",
		"Username": username,
		"Message":  msg,
		"MsgOK":    msgOK,
	})
}

func (h *Handler) tgHelper(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}
	settings, err := store.GetSettings(h.dbConn, []string{"telegram_api_id", "telegram_api_hash", "tg_bot_token", "tg_bot_admin_id", "tg_enabled"})
	if err != nil {
		c.String(http.StatusInternalServerError, "load settings failed")
		return
	}

	apiID := settings["telegram_api_id"]
	apiHash := settings["telegram_api_hash"]
	configured := apiID != "" && apiHash != ""

	botConfigured := settings["tg_bot_token"] != "" && settings["tg_bot_admin_id"] != ""

	// tg_enabled: empty or "1" means enabled, only "0" means disabled.
	tgEnabled := strings.TrimSpace(settings["tg_enabled"]) != "0"

	message := strings.TrimSpace(c.Query("message"))
	msgOK := c.Query("status") == "ok"

	c.HTML(http.StatusOK, "tg_helper.html", gin.H{
		"Title":         "TgHelper",
		"Configured":    configured,
		"BotConfigured": botConfigured,
		"TGEnabled":     tgEnabled,
		"Message":       message,
		"MsgOK":         msgOK,
	})
}

func (h *Handler) tgHelperToggle(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}
	action := strings.TrimSpace(c.PostForm("tg_toggle"))
	var msg string
	msgOK := true
	switch action {
	case "enable":
		_ = store.SetSetting(h.dbConn, "tg_enabled", "1")
		msg = "TG 功能已开启，后台服务将在下一轮循环中恢复运行。"
	case "disable":
		_ = store.SetSetting(h.dbConn, "tg_enabled", "0")
		msg = "TG 功能已关闭，后台服务将在下一轮循环时停止。"
	default:
		msg = "未知操作。"
		msgOK = false
	}
	redirectURL := "/tg_helper?message=" + url.QueryEscape(msg)
	if msgOK {
		redirectURL += "&status=ok"
	}
	c.Redirect(http.StatusSeeOther, redirectURL)
}

func (h *Handler) tgLoginStart(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	settings, err := store.GetSettings(h.dbConn, []string{"telegram_api_id", "telegram_api_hash", "tg_all_proxy"})
	if err != nil {
		c.String(http.StatusInternalServerError, "load settings failed")
		return
	}

	apiIDText := settings["telegram_api_id"]
	apiHash := settings["telegram_api_hash"]
	allProxy := settings["tg_all_proxy"]
	if apiIDText == "" || apiHash == "" {
		c.HTML(http.StatusOK, "tg_login_start.html", gin.H{
			"Title": "TG Login",
			"Error": "请先配置 Telegram API ID 和 Hash。",
		})
		return
	}

	if c.Request.Method == http.MethodGet {
		c.HTML(http.StatusOK, "tg_login_start.html", gin.H{
			"Title": "TG Login",
		})
		return
	}

	// ── Session Text import (fast path, no phone code needed) ────
	if strings.TrimSpace(c.PostForm("action")) == "session" {
		sessionText := strings.TrimSpace(c.PostForm("session_text"))
		accountName := strings.TrimSpace(c.PostForm("account_name"))
		if sessionText == "" {
			c.HTML(http.StatusOK, "tg_login_start.html", gin.H{
				"Title": "TG Login",
				"Error": "请粘贴 session_text。",
				"Tab":   "session",
			})
			return
		}
		apiID, err := strconv.Atoi(apiIDText)
		if err != nil {
			c.HTML(http.StatusOK, "tg_login_start.html", gin.H{
				"Title": "TG Login",
				"Error": "API ID 格式不正确。",
				"Tab":   "session",
			})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
		defer cancel()
		self, canonical, err := tg.GetSelfFromSessionText(ctx, apiID, apiHash, sessionText, allProxy)
		if err != nil {
			c.HTML(http.StatusOK, "tg_login_start.html", gin.H{
				"Title":       "TG Login",
				"Error":       "Session 验证失败：" + err.Error(),
				"Tab":         "session",
				"SessionText": sessionText,
				"AccountName": accountName,
			})
			return
		}
		// Auto-fill account name from TG user if not provided.
		if accountName == "" && self != nil {
			accountName = strings.TrimSpace(self.Username)
			if accountName == "" {
				accountName = strings.TrimSpace(strings.TrimSpace(self.FirstName + " " + self.LastName))
			}
			if accountName == "" {
				accountName = strings.TrimSpace(self.Phone)
			}
		}
		var tgUserID int64
		if self != nil {
			tgUserID = self.ID
		}
		if err := store.CreateTGAccount(h.dbConn, username, accountName, canonical, tgUserID); err != nil {
			c.HTML(http.StatusOK, "tg_login_start.html", gin.H{
				"Title":       "TG Login",
				"Error":       "保存账号失败：" + err.Error(),
				"Tab":         "session",
				"SessionText": sessionText,
				"AccountName": accountName,
			})
			return
		}
		c.Redirect(http.StatusFound, "/tg_helper")
		return
	}

	// ── Phone code flow ───────────────────────────────────────────
	phone := strings.TrimSpace(c.PostForm("phone"))
	accountName := strings.TrimSpace(c.PostForm("account_name"))
	if phone == "" {
		c.HTML(http.StatusOK, "tg_login_start.html", gin.H{
			"Title":       "TG Login",
			"Error":       "手机号不能为空。",
			"Phone":       phone,
			"AccountName": accountName,
		})
		return
	}

	apiID, err := strconv.Atoi(apiIDText)
	if err != nil {
		c.HTML(http.StatusOK, "tg_login_start.html", gin.H{
			"Title":       "TG Login",
			"Error":       "API ID 格式不正确。",
			"Phone":       phone,
			"AccountName": accountName,
		})
		return
	}

	flowID, err := store.CreateLoginFlow(h.dbConn, username, phone, accountName)
	if err != nil {
		c.HTML(http.StatusOK, "tg_login_start.html", gin.H{
			"Title":       "TG Login",
			"Error":       "创建登录流程失败。",
			"Phone":       phone,
			"AccountName": accountName,
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 25*time.Second)
	defer cancel()
	storage := tg.NewLoginFlowSessionStorage(h.dbConn, flowID)
	codeHash, err := tg.SendLoginCode(ctx, apiID, apiHash, phone, storage, allProxy)
	if err != nil {
		_ = store.DeleteLoginFlow(h.dbConn, flowID, username)
		c.HTML(http.StatusOK, "tg_login_start.html", gin.H{
			"Title":       "TG Login",
			"Error":       "发送验证码失败。",
			"Phone":       phone,
			"AccountName": accountName,
		})
		return
	}

	if err := store.UpdateLoginFlowCodeHash(h.dbConn, flowID, codeHash); err != nil {
		_ = store.DeleteLoginFlow(h.dbConn, flowID, username)
		c.HTML(http.StatusOK, "tg_login_start.html", gin.H{
			"Title":       "TG Login",
			"Error":       "保存验证码信息失败。",
			"Phone":       phone,
			"AccountName": accountName,
		})
		return
	}

	c.Redirect(http.StatusFound, "/tg/login/verify?flow_id="+strconv.FormatInt(flowID, 10))
}

func (h *Handler) tgLoginVerify(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	flowIDText := c.Query("flow_id")
	if flowIDText == "" {
		flowIDText = c.PostForm("flow_id")
	}
	flowID, err := strconv.ParseInt(flowIDText, 10, 64)
	if err != nil || flowID <= 0 {
		c.String(http.StatusBadRequest, "invalid flow id")
		return
	}

	flow, err := store.GetLoginFlow(h.dbConn, flowID, username)
	if err != nil {
		c.String(http.StatusNotFound, "login flow not found")
		return
	}

	settings, err := store.GetSettings(h.dbConn, []string{"telegram_api_id", "telegram_api_hash", "tg_all_proxy"})
	if err != nil {
		c.String(http.StatusInternalServerError, "load settings failed")
		return
	}

	apiIDText := settings["telegram_api_id"]
	apiHash := settings["telegram_api_hash"]
	allProxy := settings["tg_all_proxy"]
	apiID, err := strconv.Atoi(apiIDText)
	if err != nil || apiHash == "" {
		c.String(http.StatusBadRequest, "api settings invalid")
		return
	}

	if c.Request.Method == http.MethodGet {
		c.HTML(http.StatusOK, "tg_login_verify.html", gin.H{
			"Title":  "TG Verify",
			"FlowID": flowID,
			"Phone":  flow.Phone,
		})
		return
	}

	code := strings.TrimSpace(c.PostForm("code"))
	password := strings.TrimSpace(c.PostForm("password"))
	if code == "" {
		c.HTML(http.StatusOK, "tg_login_verify.html", gin.H{
			"Title":  "TG Verify",
			"FlowID": flowID,
			"Phone":  flow.Phone,
			"Error":  "验证码不能为空。",
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 35*time.Second)
	defer cancel()
	storage := tg.NewLoginFlowSessionStorage(h.dbConn, flowID)
	self, err := tg.SignIn(ctx, apiID, apiHash, flow.Phone, code, flow.PhoneCodeHash, password, storage, allProxy)
	if err != nil {
		errMsg := "登录失败。"
		if errors.Is(err, auth.ErrPasswordNotProvided) {
			errMsg = "需要两步验证密码。"
		}
		c.HTML(http.StatusOK, "tg_login_verify.html", gin.H{
			"Title":  "TG Verify",
			"FlowID": flowID,
			"Phone":  flow.Phone,
			"Error":  errMsg,
		})
		return
	}

	updatedFlow, err := store.GetLoginFlow(h.dbConn, flowID, username)
	if err != nil {
		c.HTML(http.StatusOK, "tg_login_verify.html", gin.H{
			"Title":  "TG Verify",
			"FlowID": flowID,
			"Phone":  flow.Phone,
			"Error":  "读取会话失败。",
		})
		return
	}

	accountName := strings.TrimSpace(updatedFlow.AccountName)
	if accountName == "" && self != nil {
		accountName = strings.TrimSpace(self.Username)
		if accountName == "" {
			accountName = strings.TrimSpace(self.Phone)
		}
	}
	if accountName == "" {
		accountName = flow.Phone
	}

	if err := store.CreateTGAccount(h.dbConn, username, accountName, updatedFlow.SessionText, self.ID); err != nil {
		c.HTML(http.StatusOK, "tg_login_verify.html", gin.H{
			"Title":  "TG Verify",
			"FlowID": flowID,
			"Phone":  flow.Phone,
			"Error":  "保存账号失败。",
		})
		return
	}
	_ = store.DeleteLoginFlow(h.dbConn, flowID, username)

	c.Redirect(http.StatusFound, "/tg_helper")
}

func (h *Handler) tgSettings(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	settings, err := store.GetSettings(h.dbConn, []string{"telegram_api_id", "telegram_api_hash"})
	if err != nil {
		c.String(http.StatusInternalServerError, "load settings failed")
		return
	}

	if c.Request.Method == http.MethodGet {
		c.HTML(http.StatusOK, "tg_settings.html", gin.H{
			"Title":   "TG Settings",
			"ApiID":   settings["telegram_api_id"],
			"ApiHash": settings["telegram_api_hash"],
		})
		return
	}

	apiID := strings.TrimSpace(c.PostForm("api_id"))
	apiHash := strings.TrimSpace(c.PostForm("api_hash"))

	var errMsg string
	var succMsg string
	if apiID == "" || apiHash == "" {
		errMsg = "API ID 和 API Hash 不能为空。"
	}

	if errMsg == "" {
		if err := store.SetSetting(h.dbConn, "telegram_api_id", apiID); err != nil {
			errMsg = "保存 API ID 失败。"
		}
	}
	if errMsg == "" {
		if err := store.SetSetting(h.dbConn, "telegram_api_hash", apiHash); err != nil {
			errMsg = "保存 API Hash 失败。"
		}
	}

	if errMsg != "" {
		c.HTML(http.StatusOK, "tg_settings.html", gin.H{
			"Title":   "TG Settings",
			"ApiID":   apiID,
			"ApiHash": apiHash,
			"Error":   errMsg,
		})
		return
	}

	succMsg = "API 设置已保存"
	c.HTML(http.StatusOK, "tg_settings.html", gin.H{
		"Title":   "TG Settings",
		"ApiID":   apiID,
		"ApiHash": apiHash,
		"Message": succMsg,
	})
}

func (h *Handler) tgBotSettings(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	settings, err := store.GetSettings(h.dbConn, []string{"telegram_api_id", "telegram_api_hash", "tg_bot_token", "tg_bot_admin_id", "tg_bot_webhook_secret"})
	if err != nil {
		c.String(http.StatusInternalServerError, "load settings failed")
		return
	}

	type AdminCandidate struct {
		ID   string
		Name string
	}
	var adminCandidates []AdminCandidate

	username := h.currentUser(c)
	accounts, _ := store.ListTGAccounts(h.dbConn, username)

	for _, acc := range accounts {
		uid := acc.TGUserID
		if uid == 0 {
			// Transparently fetch ID from token without forcing re-login
			apiIDInt, _ := strconv.Atoi(settings["telegram_api_id"])
			if apiIDInt > 0 && settings["telegram_api_hash"] != "" {
				storage := tg.NewAccountSessionStorage(h.dbConn, acc.Owner, acc.ID)
				ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
				user, err := tg.GetAccountSelf(ctx, apiIDInt, settings["telegram_api_hash"], storage, settings["tg_all_proxy"])
				cancel()
				if err == nil && user != nil {
					uid = user.ID
					_ = store.UpdateTGAccountUserID(h.dbConn, acc.ID, uid)
				}
			}
		}
		if uid > 0 {
			adminCandidates = append(adminCandidates, AdminCandidate{
				ID:   strconv.FormatInt(uid, 10),
				Name: acc.AccountName + " (" + strconv.FormatInt(uid, 10) + ")",
			})
		}
	}

	botConfigured := settings["tg_bot_token"] != "" && settings["tg_bot_admin_id"] != ""

	if c.Request.Method == http.MethodGet {
		c.HTML(http.StatusOK, "tg_bot_settings.html", gin.H{
			"Title":            "Bot Settings",
			"BotToken":         settings["tg_bot_token"],
			"BotAdminID":       settings["tg_bot_admin_id"],
			"BotWebhookSecret": settings["tg_bot_webhook_secret"],
			"AdminCandidates":  adminCandidates,
			"BotConfigured":    botConfigured,
		})
		return
	}

	botToken := strings.TrimSpace(c.PostForm("tg_bot_token"))
	botAdmin := strings.TrimSpace(c.PostForm("tg_bot_admin_id"))
	webhookSecret := strings.TrimSpace(c.PostForm("tg_bot_webhook_secret"))

	var errMsg string
	var succMsg string

	_ = store.SetSetting(h.dbConn, "tg_bot_token", botToken)
	_ = store.SetSetting(h.dbConn, "tg_bot_admin_id", botAdmin)

	if webhookSecret == "" && botToken != "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err == nil {
			webhookSecret = fmt.Sprintf("tg_%x", b)
		} else {
			webhookSecret = fmt.Sprintf("tg_%d", time.Now().UnixNano()) // fallback
		}
	}
	_ = store.SetSetting(h.dbConn, "tg_bot_webhook_secret", webhookSecret)

	if botToken != "" && webhookSecret != "" {
		host := c.Request.Host
		scheme := "http"
		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" || c.GetHeader("Cf-Visitor") != "" {
			scheme = "https"
		}
		if !strings.Contains(host, "localhost") && !strings.Contains(host, "127.0.0.1") {
			scheme = "https"
		}

		hookURL := fmt.Sprintf("%s://%s/api/%s", scheme, host, webhookSecret)
		err := tgbot.SetWebhook(botToken, hookURL, webhookSecret)
		if err != nil {
			errMsg = "自动注册 Webhook 失败: " + err.Error()
		} else {
			succMsg = "Bot 设置已保存，且 Webhook 注册成功。"
			botConfigured = true
		}
	} else if botToken == "" {
		succMsg = "BotToken 已清空，当前 Bot 功能处于停用状态。"
		botConfigured = false
	} else {
		succMsg = "配置已保存，但缺少信息未能注册 Webhook。"
	}

	c.HTML(http.StatusOK, "tg_bot_settings.html", gin.H{
		"Title":            "Bot Settings",
		"BotToken":         botToken,
		"BotAdminID":       botAdmin,
		"BotWebhookSecret": webhookSecret,
		"AdminCandidates":  adminCandidates,
		"Error":            errMsg,
		"Message":          succMsg,
		"BotConfigured":    botConfigured,
	})
}

func (h *Handler) tgBotTestMessage(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false, "error": "not logged in"})
		return
	}

	settings, err := store.GetSettings(h.dbConn, []string{"tg_bot_admin_id"})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": "load settings failed"})
		return
	}

	adminIDStr := settings["tg_bot_admin_id"]
	if adminIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "Bot Admin ID 未配置"})
		return
	}
	chatID, err := strconv.ParseInt(adminIDStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "Bot Admin ID 格式错误"})
		return
	}

	err = tgbot.SendMessage(h.dbConn, chatID, "你好！这是一条来自 VpsHelper 面板的测试消息。🚀\n如果你能收到该消息，说明双向交互已全面打通！")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *Handler) tgBotWebhookInfo(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false, "error": "not logged in"})
		return
	}

	settings, err := store.GetSettings(h.dbConn, []string{"tg_bot_token"})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": "load settings failed"})
		return
	}

	botToken := settings["tg_bot_token"]
	if botToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "Bot Token 未配置"})
		return
	}

	info, err := tgbot.GetWebhookInfo(botToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "data": info})
}

func (h *Handler) tgAccounts(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	accounts, err := store.ListTGAccounts(h.dbConn, username)
	if err != nil {
		c.String(http.StatusInternalServerError, "load accounts failed")
		return
	}

	selectedAccountID := int64(0)
	if len(accounts) > 0 {
		selectedAccountID = accounts[0].ID
	}
	if idText := strings.TrimSpace(c.Query("account_id")); idText != "" {
		if id, err := strconv.ParseInt(idText, 10, 64); err == nil && id > 0 {
			selectedAccountID = id
		}
	}
	if c.Request.Method == http.MethodPost {
		if idText := strings.TrimSpace(c.PostForm("account_id")); idText != "" {
			if id, err := strconv.ParseInt(idText, 10, 64); err == nil && id > 0 {
				selectedAccountID = id
			}
		}
	}

	message := strings.TrimSpace(c.Query("message"))
	msgOK := c.Query("status") == "ok"
	if c.Request.Method == http.MethodPost {
		action := strings.TrimSpace(c.PostForm("action"))
		if action == "" {
			if strings.TrimSpace(c.PostForm("id")) != "" {
				action = "delete"
			} else if strings.TrimSpace(c.PostForm("account_id")) != "" {
				action = "refresh_dialogs"
			}
		}
		switch action {
		case "delete":
			idText := strings.TrimSpace(c.PostForm("id"))
			id, err := strconv.ParseInt(idText, 10, 64)
			if err != nil || id <= 0 {
				message = "参数错误。"
				break
			}
			if err := store.DeleteTGAccount(h.dbConn, username, id); err != nil {
				message = "删除失败。"
			} else {
				message = "已删除账号。"
				msgOK = true
			}
		case "refresh_dialogs":
			if selectedAccountID <= 0 {
				message = "请先选择账号。"
				break
			}
			if _, err := store.GetTGAccountByID(h.dbConn, username, selectedAccountID); err != nil {
				message = "账号不存在或不属于当前用户。"
				break
			}

			settings, err := store.GetSettings(h.dbConn, []string{"telegram_api_id", "telegram_api_hash", "tg_all_proxy"})
			if err != nil {
				message = "读取 API 配置失败。"
				break
			}
			apiIDText := strings.TrimSpace(settings["telegram_api_id"])
			apiHash := strings.TrimSpace(settings["telegram_api_hash"])
			allProxy := strings.TrimSpace(settings["tg_all_proxy"])
			apiID, err := strconv.Atoi(apiIDText)
			if err != nil || apiHash == "" {
				message = "请先在 API 设置里配置 Telegram API ID/Hash。"
				break
			}

			ctx, cancel := context.WithTimeout(c.Request.Context(), 120*time.Second)
			defer cancel()
			n, msg := tg.RefreshDialogs(ctx, h.dbConn, username, selectedAccountID, apiID, apiHash, allProxy, nil)
			if msg != "ok" {
				message = "刷新失败：" + msg
				break
			}
			migrated, migrateErr := tg.NormalizeStoredTargetsByDialogs(h.dbConn, username, selectedAccountID)
			if migrateErr != nil {
				message = fmt.Sprintf("已刷新会话列表：%d 条（已保存会话ID）。任务迁移失败：%s", n, migrateErr.Error())
				break
			}
			if migrated > 0 {
				message = fmt.Sprintf("已刷新会话列表：%d 条，已迁移 %d 条任务目标为会话ID。", n, migrated)
				msgOK = true
			} else {
				message = fmt.Sprintf("已刷新会话列表：%d 条（已保存会话ID）。", n)
				msgOK = true
			}
		default:
			message = "未知操作。"
		}
		redirectURL := fmt.Sprintf("/tg/accounts?account_id=%d", selectedAccountID)
		if message != "" {
			redirectURL += "&message=" + url.QueryEscape(message)
			if msgOK {
				redirectURL += "&status=ok"
			}
		}
		c.Redirect(http.StatusSeeOther, redirectURL)
		return
	}

	dialogs := []store.TGDialog{}
	if selectedAccountID > 0 {
		if d, err := store.ListTGDialogs(h.dbConn, selectedAccountID); err == nil {
			dialogs = d
		}
	}

	c.HTML(http.StatusOK, "tg_accounts.html", gin.H{
		"Title":             "TG 账号管理",
		"Message":           message,
		"MsgOK":             msgOK,
		"Accounts":          accounts,
		"HasAccounts":       len(accounts) > 0,
		"SelectedAccountID": selectedAccountID,
		"Dialogs":           dialogs,
	})
}

func (h *Handler) tgProxy(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	_ = username

	settings, err := store.GetSettings(h.dbConn, []string{"tg_all_proxy"})
	if err != nil {
		c.String(http.StatusInternalServerError, "load settings failed")
		return
	}
	allProxy := settings["tg_all_proxy"]
	message := ""
	msgOK := false

	if c.Request.Method == http.MethodPost {
		action := strings.TrimSpace(c.PostForm("action"))
		switch action {
		case "save":
			allProxy = strings.TrimSpace(c.PostForm("all_proxy"))
			_ = store.SetSetting(h.dbConn, "tg_all_proxy", allProxy)
			message = "已保存。"
			msgOK = true
		case "clear":
			allProxy = ""
			_ = store.SetSetting(h.dbConn, "tg_all_proxy", "")
			message = "已清空。"
			msgOK = true
		default:
			message = "未知操作。"
		}
	}

	c.HTML(http.StatusOK, "tg_proxy.html", gin.H{
		"Title":    "TG 代理设置",
		"Message":  message,
		"MsgOK":    msgOK,
		"AllProxy": allProxy,
	})
}

func (h *Handler) tgDialogs(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	accounts, err := store.ListTGAccounts(h.dbConn, username)
	if err != nil {
		c.String(http.StatusInternalServerError, "load accounts failed")
		return
	}
	if len(accounts) == 0 {
		c.HTML(http.StatusOK, "tg_dialogs.html", gin.H{
			"Title":     "会话列表",
			"Message":   "请先登录添加一个 TG 账号。",
			"Accounts":  accounts,
			"AccountID": int64(0),
			"Dialogs":   []store.TGDialog{},
		})
		return
	}

	accountID := accounts[0].ID
	if idText := strings.TrimSpace(c.Query("account_id")); idText != "" {
		if id, err := strconv.ParseInt(idText, 10, 64); err == nil && id > 0 {
			accountID = id
		}
	}
	if c.Request.Method == http.MethodPost {
		idText := strings.TrimSpace(c.PostForm("account_id"))
		if id, err := strconv.ParseInt(idText, 10, 64); err == nil && id > 0 {
			accountID = id
		}
	}

	message := strings.TrimSpace(c.Query("message"))
	msgOK := c.Query("status") == "ok"
	if c.Request.Method == http.MethodPost {
		action := strings.TrimSpace(c.PostForm("action"))
		if action == "" && strings.TrimSpace(c.PostForm("account_id")) != "" {
			action = "refresh"
		}
		if action == "refresh" {
			settings, err := store.GetSettings(h.dbConn, []string{"telegram_api_id", "telegram_api_hash", "tg_all_proxy"})
			if err != nil {
				message = "读取 API 配置失败。"
			} else {
				apiIDText := strings.TrimSpace(settings["telegram_api_id"])
				apiHash := strings.TrimSpace(settings["telegram_api_hash"])
				allProxy := strings.TrimSpace(settings["tg_all_proxy"])
				apiID, err := strconv.Atoi(apiIDText)
				if err != nil || apiHash == "" {
					message = "请先在 API 设置里配置 Telegram API ID/Hash。"
				} else {
					ctx, cancel := context.WithTimeout(c.Request.Context(), 120*time.Second)
					defer cancel()
					n, msg := tg.RefreshDialogs(ctx, h.dbConn, username, accountID, apiID, apiHash, allProxy, nil)
					if msg != "ok" {
						message = "刷新失败: " + msg
					} else {
						migrated, migrateErr := tg.NormalizeStoredTargetsByDialogs(h.dbConn, username, accountID)
						if migrateErr != nil {
							message = fmt.Sprintf("已刷新会话列表：%d 条（已保存会话ID）。任务迁移失败：%s", n, migrateErr.Error())
						} else if migrated > 0 {
							message = fmt.Sprintf("已刷新会话列表：%d 条，已迁移 %d 条任务目标为会话ID。", n, migrated)
							msgOK = true
						} else {
							message = fmt.Sprintf("已刷新会话列表：%d 条（已保存会话ID）。", n)
							msgOK = true
						}
					}
				}
			}
		} else {
			message = "未知操作。"
		}
		redirectURL := fmt.Sprintf("/tg/dialogs?account_id=%d", accountID)
		if message != "" {
			redirectURL += "&message=" + url.QueryEscape(message)
			if msgOK {
				redirectURL += "&status=ok"
			}
		}
		c.Redirect(http.StatusSeeOther, redirectURL)
		return
	}

	// JSON branch: called by client-side after SSE refresh to reload just the table.
	if c.Query("_json") == "1" {
		dialogs, err := store.ListTGDialogs(h.dbConn, accountID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"ok": false})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "dialogs": dialogs})
		return
	}

	dialogs, err := store.ListTGDialogs(h.dbConn, accountID)
	if err != nil {
		c.String(http.StatusInternalServerError, "load dialogs failed")
		return
	}

	c.HTML(http.StatusOK, "tg_dialogs.html", gin.H{
		"Title":     "会话列表",
		"Message":   message,
		"MsgOK":     msgOK,
		"Accounts":  accounts,
		"AccountID": accountID,
		"Dialogs":   dialogs,
	})
}

func (h *Handler) tgDialogsRefreshStream(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"ok": false, "error": "not logged in"})
		return
	}

	flusher, ok := dbStreamHeaders(c)
	if !ok {
		return
	}

	send := func(percent int, msg string, done bool, success bool) bool {
		return dbStreamSend(c, flusher, percent, msg, done, success)
	}
	fail := func(msg string) { _ = send(0, msg, true, false) }

	// Parse account_id from POST body.
	accountIDText := strings.TrimSpace(c.PostForm("account_id"))
	accountID, err := strconv.ParseInt(accountIDText, 10, 64)
	if err != nil || accountID <= 0 {
		fail("account_id 无效。")
		return
	}

	if !send(5, "正在读取 API 配置...", false, false) {
		return
	}

	settings, err := store.GetSettings(h.dbConn, []string{"telegram_api_id", "telegram_api_hash", "tg_all_proxy"})
	if err != nil {
		fail("读取 API 配置失败：" + err.Error())
		return
	}
	apiIDText := strings.TrimSpace(settings["telegram_api_id"])
	apiHash := strings.TrimSpace(settings["telegram_api_hash"])
	allProxy := strings.TrimSpace(settings["tg_all_proxy"])
	apiID, err := strconv.Atoi(apiIDText)
	if err != nil || apiHash == "" {
		fail("请先在 API 设置里配置 Telegram API ID/Hash。")
		return
	}

	if !send(15, "正在连接 Telegram，拉取会话列表...", false, false) {
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 120*time.Second)
	defer cancel()

	n, msg := tg.RefreshDialogs(ctx, h.dbConn, username, accountID, apiID, apiHash, allProxy, func(count int, info string) {
		pct := 15 + count/100
		if pct > 75 {
			pct = 75
		}
		send(pct, fmt.Sprintf("拉取中：已获取 %d 条会话...", count), false, false)
	})
	if msg != "ok" {
		fail("刷新失败：" + msg)
		return
	}

	if !send(80, fmt.Sprintf("已获取 %d 条会话，正在迁移旧任务目标...", n), false, false) {
		return
	}

	migrated, migrateErr := tg.NormalizeStoredTargetsByDialogs(h.dbConn, username, accountID)
	if migrateErr != nil {
		_ = send(100, fmt.Sprintf("已刷新 %d 条会话，任务迁移失败：%s", n, migrateErr.Error()), true, false)
		return
	}

	var finalMsg string
	if migrated > 0 {
		finalMsg = fmt.Sprintf("刷新完成：%d 条会话，已迁移 %d 条任务目标为会话ID。", n, migrated)
	} else {
		finalMsg = fmt.Sprintf("刷新完成：%d 条会话（已保存会话ID）。", n)
	}
	_ = send(100, finalMsg, true, true)
}

func (h *Handler) tgAutoReply(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	message := ""
	msgOK := false
	accounts, err := store.ListTGAccounts(h.dbConn, username)
	if err != nil {
		c.String(http.StatusInternalServerError, "load accounts failed")
		return
	}

	accountIDText := strings.TrimSpace(c.Query("account_id"))
	if c.Request.Method == http.MethodPost {
		if v := strings.TrimSpace(c.PostForm("account_id")); v != "" {
			accountIDText = v
		}
	}

	var accountID int64
	if accountIDText != "" {
		if v, err := strconv.ParseInt(accountIDText, 10, 64); err == nil {
			accountID = v
		}
	}
	if accountID == 0 && len(accounts) > 0 {
		accountID = accounts[0].ID
	}

	if c.Request.Method == http.MethodPost {
		action := strings.TrimSpace(c.PostForm("action"))
		switch action {
		case "add":
			matchText := strings.TrimSpace(c.PostForm("match_text"))
			replyText := strings.TrimSpace(c.PostForm("reply_text"))
			if accountID <= 0 {
				message = "请先选择账号。"
			} else if matchText == "" || replyText == "" {
				message = "匹配文本和回复内容不能为空。"
			} else {
				acct, acctErr := store.GetTGAccountByID(h.dbConn, username, accountID)
				tgCfg, _ := store.GetSettings(h.dbConn, []string{"telegram_api_id", "telegram_api_hash", "tg_all_proxy"})
				var sessionText, apiID, apiHash, allProxy, accountName string
				if acctErr == nil {
					sessionText = acct.SessionText
					accountName = acct.AccountName
				}
				apiID = strings.TrimSpace(tgCfg["telegram_api_id"])
				apiHash = strings.TrimSpace(tgCfg["telegram_api_hash"])
				allProxy = strings.TrimSpace(tgCfg["tg_all_proxy"])
				if err := store.CreateAutoReplyRule(h.dbConn, username, accountID, accountName, matchText, replyText, true, sessionText, apiID, apiHash, allProxy); err != nil {
					message = "创建失败。"
				} else {
					message = "已创建并启用。"
					msgOK = true
				}
			}
		case "enable", "disable", "delete":
			idText := strings.TrimSpace(c.PostForm("id"))
			id, err := strconv.ParseInt(idText, 10, 64)
			if err != nil || id <= 0 {
				message = "参数错误。"
				break
			}
			switch action {
			case "enable":
				if err := store.SetAutoReplyRuleEnabled(h.dbConn, username, id, true); err != nil {
					message = "启用失败。"
				} else {
					message = "已启用。"
					msgOK = true
				}
			case "disable":
				if err := store.SetAutoReplyRuleEnabled(h.dbConn, username, id, false); err != nil {
					message = "停用失败。"
				} else {
					message = "已停用。"
					msgOK = true
				}
			case "delete":
				if err := store.DeleteAutoReplyRule(h.dbConn, username, id); err != nil {
					message = "删除失败。"
				} else {
					message = "已删除。"
					msgOK = true
				}
			}
		default:
			message = "未知操作。"
		}
	}

	rules := []store.AutoReplyRule{}
	if accountID > 0 {
		if rr, err := store.ListAutoReplyRules(h.dbConn, username, accountID); err == nil {
			rules = rr
		}
	}

	settings, _ := store.GetSettings(h.dbConn, []string{"telegram_api_id", "telegram_api_hash"})
	hasAPI := strings.TrimSpace(settings["telegram_api_id"]) != "" && strings.TrimSpace(settings["telegram_api_hash"]) != ""

	c.HTML(http.StatusOK, "tg_auto_reply.html", gin.H{
		"Title":     "自动回复",
		"Message":   message,
		"MsgOK":     msgOK,
		"HasAPI":    hasAPI,
		"Accounts":  accounts,
		"AccountID": accountID,
		"Rules":     rules,
	})
}

func (h *Handler) tgAutoSend(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	message := ""
	msgOK := false
	if c.Request.Method == http.MethodPost {
		action := strings.TrimSpace(c.PostForm("action"))
		idText := strings.TrimSpace(c.PostForm("id"))
		id, err := strconv.ParseInt(idText, 10, 64)
		if err != nil || id <= 0 {
			message = "参数错误。"
		} else {
			switch action {
			case "enable":
				if err := store.SetAutoSendTaskEnabled(h.dbConn, username, id, true); err != nil {
					message = "启用失败。"
				} else {
					message = "已启用。"
					msgOK = true
				}
			case "disable":
				if err := store.SetAutoSendTaskEnabled(h.dbConn, username, id, false); err != nil {
					message = "停用失败。"
				} else {
					message = "已停用。"
					msgOK = true
				}
			case "delete":
				if err := store.DeleteAutoSendTask(h.dbConn, username, id); err != nil {
					message = "删除失败。"
				} else {
					message = "已删除。"
					msgOK = true
				}
			case "run":
				runCtx, cancel := context.WithTimeout(c.Request.Context(), 50*time.Second)
				defer cancel()
				ok, msg := tg.RunAutoSendTaskNow(runCtx, h.dbConn, username, id)
				if ok {
					message = "已立即执行。"
					msgOK = true
				} else {
					message = "立即执行失败: " + msg
				}
			case "edit":
				newMsg := strings.TrimSpace(c.PostForm("message"))
				schedType := strings.TrimSpace(c.PostForm("schedule_type"))
				timeOfDay := strings.TrimSpace(c.PostForm("time_of_day"))
				intervalText := strings.TrimSpace(c.PostForm("interval_seconds"))
				jitterText := strings.TrimSpace(c.PostForm("jitter_seconds"))
				intervalSec, _ := strconv.Atoi(intervalText)
				jitterSec, _ := strconv.Atoi(jitterText)
				if newMsg == "" {
					message = "发送内容不能为空。"
				} else if schedType == "daily" {
					if _, err := time.Parse("15:04", timeOfDay); err != nil {
						message = "定时时间格式不正确（HH:MM）。"
					} else {
						err = store.UpdateAutoSendTask(h.dbConn, username, id, newMsg, schedType, timeOfDay, 0, jitterSec)
						if err != nil {
							message = "更新失败：" + err.Error()
						} else {
							message = "已更新。"
							msgOK = true
						}
					}
				} else {
					schedType = "interval"
					if intervalSec <= 0 {
						message = "间隔秒数必须 > 0。"
					} else {
						err = store.UpdateAutoSendTask(h.dbConn, username, id, newMsg, schedType, "", intervalSec, jitterSec)
						if err != nil {
							message = "更新失败：" + err.Error()
						} else {
							message = "已更新。"
							msgOK = true
						}
					}
				}
			default:
				message = "未知操作。"
			}
		}
	}

	tasks, err := store.ListAutoSendTasks(h.dbConn, username)
	if err != nil {
		c.String(http.StatusInternalServerError, "load tasks failed")
		return
	}

	c.HTML(http.StatusOK, "tg_auto_send.html", gin.H{
		"Title":   "自动发送",
		"Message": message,
		"MsgOK":   msgOK,
		"Tasks":   tasks,
	})
}

// tgAutoSendHistory returns the JSON execution history of a task (max 1000 entries).
func (h *Handler) tgAutoSendHistory(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false, "error": "not logged in"})
		return
	}
	idText := strings.TrimSpace(c.Query("task_id"))
	taskID, err := strconv.ParseInt(idText, 10, 64)
	if err != nil || taskID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "invalid task_id"})
		return
	}
	entries, err := store.ListSendHistory(h.dbConn, taskID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": err.Error()})
		return
	}
	if entries == nil {
		entries = []store.SendHistoryEntry{}
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "entries": entries})
}

func (h *Handler) tgAutoSendNew(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	accounts, err := store.ListTGAccounts(h.dbConn, username)
	if err != nil {
		c.String(http.StatusInternalServerError, "load accounts failed")
		return
	}

	selectedAccountID := int64(0)
	if len(accounts) > 0 {
		selectedAccountID = accounts[0].ID
	}

	accountIDText := strings.TrimSpace(c.Query("account_id"))
	if c.Request.Method == http.MethodPost {
		if v := strings.TrimSpace(c.PostForm("account_id")); v != "" {
			accountIDText = v
		}
	}
	if accountIDText != "" {
		if id, err := strconv.ParseInt(accountIDText, 10, 64); err == nil && id > 0 {
			selectedAccountID = id
		}
	}

	accountOwned := false
	for _, a := range accounts {
		if a.ID == selectedAccountID {
			accountOwned = true
			break
		}
	}
	if !accountOwned && len(accounts) > 0 {
		selectedAccountID = accounts[0].ID
		accountOwned = true
	}

	dialogs := []store.TGDialog{}
	if accountOwned {
		if d, err := store.ListTGDialogs(h.dbConn, selectedAccountID); err == nil {
			dialogs = d
		}
	}

	view := gin.H{
		"Title":           "新建自动发送任务",
		"Error":           "",
		"Accounts":        accounts,
		"AccountID":       selectedAccountID,
		"Dialogs":         dialogs,
		"DialogID":        "",
		"Message":         "",
		"ScheduleType":    "interval",
		"IntervalSeconds": "3600",
		"TimeOfDay":       "03:30",
		"JitterSeconds":   "0",
		"Enabled":         true,
	}

	if c.Request.Method == http.MethodGet {
		c.HTML(http.StatusOK, "tg_auto_send_new.html", view)
		return
	}

	dialogID := strings.TrimSpace(c.PostForm("dialog_id"))
	msg := strings.TrimSpace(c.PostForm("message"))
	scheduleType := strings.TrimSpace(c.PostForm("schedule_type"))
	intervalText := strings.TrimSpace(c.PostForm("interval_seconds"))
	timeOfDay := strings.TrimSpace(c.PostForm("time_of_day"))
	jitterText := strings.TrimSpace(c.PostForm("jitter_seconds"))
	enabled := c.PostForm("enabled") == "on"

	view["AccountID"] = selectedAccountID
	view["DialogID"] = dialogID
	view["Message"] = msg
	view["ScheduleType"] = scheduleType
	view["IntervalSeconds"] = intervalText
	view["TimeOfDay"] = timeOfDay
	view["JitterSeconds"] = jitterText
	view["Enabled"] = enabled

	if len(accounts) == 0 {
		view["Error"] = "请先添加 TG 账号。"
		c.HTML(http.StatusOK, "tg_auto_send_new.html", view)
		return
	}
	if !accountOwned || selectedAccountID <= 0 {
		view["Error"] = "账号不存在或不属于当前用户。"
		c.HTML(http.StatusOK, "tg_auto_send_new.html", view)
		return
	}
	account, err := store.GetTGAccountByID(h.dbConn, username, selectedAccountID)
	if err != nil {
		view["Error"] = "账号不存在或不属于当前用户。"
		c.HTML(http.StatusOK, "tg_auto_send_new.html", view)
		return
	}

	if dialogID == "" {
		view["Error"] = "请选择会话ID。"
		c.HTML(http.StatusOK, "tg_auto_send_new.html", view)
		return
	}
	resolveCtx, resolveCancel := context.WithTimeout(c.Request.Context(), 35*time.Second)
	resolvedDialogID, resolveErr := tg.ResolveDialogIDForAccount(resolveCtx, h.dbConn, username, selectedAccountID, dialogID)
	resolveCancel()
	if resolveErr != nil {
		view["Error"] = "目标解析失败: " + resolveErr.Error()
		c.HTML(http.StatusOK, "tg_auto_send_new.html", view)
		return
	}
	dialogID = resolvedDialogID
	view["DialogID"] = dialogID

	dialogOwned := false
	for _, d := range dialogs {
		if d.DialogID == dialogID {
			dialogOwned = true
			break
		}
	}
	if !dialogOwned {
		view["Error"] = "会话ID不存在或不属于当前账号。"
		c.HTML(http.StatusOK, "tg_auto_send_new.html", view)
		return
	}
	if msg == "" {
		view["Error"] = "消息内容不能为空。"
		c.HTML(http.StatusOK, "tg_auto_send_new.html", view)
		return
	}

	intervalSeconds, err := strconv.Atoi(intervalText)
	if err != nil {
		intervalSeconds = 0
	}
	jitterSeconds, err := strconv.Atoi(jitterText)
	if err != nil {
		jitterSeconds = 0
	}
	if jitterSeconds < 0 {
		jitterSeconds = 0
	}

	if scheduleType == "daily" {
		if _, err := time.Parse("15:04", timeOfDay); err != nil {
			view["Error"] = "daily 模式下 time_of_day 必须是 HH:MM。"
			c.HTML(http.StatusOK, "tg_auto_send_new.html", view)
			return
		}
	} else {
		scheduleType = "interval"
		if intervalSeconds <= 0 {
			view["Error"] = "interval 模式下 interval_seconds 必须 > 0。"
			c.HTML(http.StatusOK, "tg_auto_send_new.html", view)
			return
		}
	}

	// Load global TG settings to embed in the task.
	tgSettings, _ := store.GetSettings(h.dbConn, []string{"telegram_api_id", "telegram_api_hash", "tg_all_proxy"})
	apiID := strings.TrimSpace(tgSettings["telegram_api_id"])
	apiHash := strings.TrimSpace(tgSettings["telegram_api_hash"])
	allProxy := strings.TrimSpace(tgSettings["tg_all_proxy"])

	next := time.Now().Format(time.RFC3339)
	if err := store.CreateAutoSendTask(
		h.dbConn, username, selectedAccountID, account.AccountName,
		dialogID, msg, intervalSeconds, jitterSeconds, scheduleType, timeOfDay, enabled, next,
		account.SessionText, apiID, apiHash, allProxy,
	); err != nil {
		view["Error"] = "创建失败。"
		c.HTML(http.StatusOK, "tg_auto_send_new.html", view)
		return
	}

	c.Redirect(http.StatusFound, "/tg/auto/send")
}

func (h *Handler) currentUser(c *gin.Context) string {
	sess := sessions.Default(c)
	user, ok := sess.Get("user").(string)
	if !ok {
		return ""
	}
	return user
}

func (h *Handler) databaseSettings(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	keys := []string{
		"cf_api_token",
		"cf_account_id",
		"cf_d1_database_name",
		"cf_d1_database_id",
		"db_auto_backup_enabled",
		"db_auto_backup_time",
		"db_auto_backup_last_result",
	}
	settings, err := store.GetSettings(h.dbConn, keys)
	if err != nil {
		c.String(http.StatusInternalServerError, "load settings failed")
		return
	}

	// localDBName: the on-disk SQLite filename, always fixed.
	localDBName := config.UnifiedDBName
	// d1Name: the Cloudflare D1 database name, editable by the user.
	d1Name := strings.TrimSpace(settings["cf_d1_database_name"])
	if d1Name == "" {
		d1Name = config.UnifiedD1DBName
		_ = store.SetSetting(h.dbConn, "cf_d1_database_name", d1Name)
	}

	cfToken := settings["cf_api_token"]
	accountID := settings["cf_account_id"]
	dbID := settings["cf_d1_database_id"]
	autoEnabled := settings["db_auto_backup_enabled"] == "1"
	autoTime := settings["db_auto_backup_time"]
	if autoTime == "" {
		autoTime = "03:30"
	}
	lastAuto := settings["db_auto_backup_last_result"]

	message := strings.TrimSpace(c.Query("message"))
	msgOK := c.Query("status") == "ok"
	if c.Request.Method == http.MethodPost {
		action := strings.TrimSpace(c.PostForm("action"))
		if action == "" {
			switch {
			case strings.TrimSpace(c.PostForm("do_backup")) == "1":
				action = "backup"
			case strings.TrimSpace(c.PostForm("do_pull")) == "1":
				action = "pull"
			case c.PostForm("db_auto_backup_enabled") == "on" || strings.TrimSpace(c.PostForm("db_auto_backup_time")) != "":
				action = "auto_backup"
			case c.PostForm("cf_d1_database_name") != "":
				action = "save"
			}
		}
		switch action {
		case "save":
			if cfToken == "" {
				message = "请先在 Cloudflare 设置中配置 API Token。"
				break
			}
			if newD1Name := strings.TrimSpace(c.PostForm("cf_d1_database_name")); newD1Name != "" {
				d1Name = newD1Name
				_ = store.SetSetting(h.dbConn, "cf_d1_database_name", d1Name)
			}
			message = "设置已保存。"
			msgOK = true
		case "create":
			if cfToken == "" {
				message = "请先在 Cloudflare 设置中配置 API Token。"
				break
			}
			if newD1Name := strings.TrimSpace(c.PostForm("cf_d1_database_name")); newD1Name != "" {
				d1Name = newD1Name
				_ = store.SetSetting(h.dbConn, "cf_d1_database_name", d1Name)
			}
			_ = store.SetSetting(h.dbConn, "cf_api_token", cfToken)

			ctx, cancel := context.WithTimeout(c.Request.Context(), 40*time.Second)
			defer cancel()
			cf := d1.Client{Token: cfToken}
			ok, msg, acc := cf.TestToken(ctx)
			if !ok {
				message = msg
				break
			}
			accountID = acc
			_ = store.SetSetting(h.dbConn, "cf_account_id", accountID)

			okFind, _, foundID := cf.FindD1ByName(ctx, accountID, d1Name)
			if okFind && foundID != "" {
				dbID = foundID
				_ = store.SetSetting(h.dbConn, "cf_d1_database_id", dbID)
				message = "已绑定云端 D1 数据库。"
				msgOK = true
				break
			}

			okCreate, msgCreate, createdID := cf.CreateD1(ctx, accountID, d1Name)
			if !okCreate || createdID == "" {
				message = msgCreate
				break
			}
			dbID = createdID
			_ = store.SetSetting(h.dbConn, "cf_d1_database_id", dbID)
			message = "已创建并绑定云端 D1 数据库。"
			msgOK = true
		case "backup":
			if cfToken == "" || accountID == "" || dbID == "" {
				message = "请先执行“自动创建并绑定”。"
				break
			}
			ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Minute)
			defer cancel()
			cf := d1.Client{Token: cfToken}
			ok, msg := d1.BackupLocalToD1(ctx, cf, accountID, dbID, h.dbConn)
			message = msg
			msgOK = ok
		case "pull":
			if cfToken == "" || accountID == "" || dbID == "" {
				message = "请先执行“自动创建并绑定”。"
				break
			}
			ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Minute)
			defer cancel()
			cf := d1.Client{Token: cfToken}
			ok, msg := d1.PullD1ToLocal(ctx, cf, accountID, dbID, h.dbConn)
			message = msg
			msgOK = ok
		case "auto_backup":
			autoEnabled = c.PostForm("db_auto_backup_enabled") == "on"
			autoTime = strings.TrimSpace(c.PostForm("db_auto_backup_time"))
			if autoTime == "" {
				autoTime = "03:30"
			}
			if autoEnabled {
				_ = store.SetSetting(h.dbConn, "db_auto_backup_enabled", "1")
			} else {
				_ = store.SetSetting(h.dbConn, "db_auto_backup_enabled", "0")
			}
			_ = store.SetSetting(h.dbConn, "db_auto_backup_time", autoTime)
			message = "已保存自动备份设置。"
			msgOK = true
		default:
			message = "未知操作。"
		}
		redirectURL := "/cloudflare/database"
		if message != "" {
			redirectURL += "?message=" + url.QueryEscape(message)
			if msgOK {
				redirectURL += "&status=ok"
			}
		}
		c.Redirect(http.StatusSeeOther, redirectURL)
		return
	}

	c.HTML(http.StatusOK, "database_settings.html", gin.H{
		"Title":                "数据库管理",
		"Message":              message,
		"MsgOK":                msgOK,
		"CFToken":              cfToken,
		"DBName":               localDBName,
		"D1Name":               d1Name,
		"DBID":                 dbID,
		"AutoBackupEnabled":    autoEnabled,
		"AutoBackupTime":       autoTime,
		"LastAutoBackupResult": lastAuto,
	})
}

// localUserTables returns all user-defined table names from the local SQLite database.
// System tables (sqlite_*) are excluded.
func localUserTables(dbConn *sql.DB) ([]string, error) {
	rows, err := dbConn.Query(
		"SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err == nil && name != "" {
			tables = append(tables, name)
		}
	}
	return tables, nil
}

// databaseTableList returns the names of all user tables in the local SQLite DB or Cloudflare D1.
func (h *Handler) databaseTableList(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false, "error": "not logged in"})
		return
	}

	source := c.Query("source")
	if source == "d1" {
		settings, _ := store.GetSettings(h.dbConn, []string{"cf_api_token", "cf_account_id", "cf_d1_database_id", "cf_d1_database_name"})
		cfToken := strings.TrimSpace(settings["cf_api_token"])
		accountID := strings.TrimSpace(settings["cf_account_id"])
		dbID := strings.TrimSpace(settings["cf_d1_database_id"])
		d1Name := strings.TrimSpace(settings["cf_d1_database_name"])
		if d1Name == "" {
			d1Name = config.UnifiedD1DBName
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
		defer cancel()
		cf := d1.Client{Token: cfToken}

		// Actively look up current AccountID and DB ID
		if ok, _, acc := cf.TestToken(ctx); ok && acc != "" {
			accountID = acc
			_ = store.SetSetting(h.dbConn, "cf_account_id", accountID)
		}
		if accountID != "" {
			if ok, _, foundID := cf.FindD1ByName(ctx, accountID, d1Name); ok && foundID != "" {
				dbID = foundID
				_ = store.SetSetting(h.dbConn, "cf_d1_database_id", dbID)
			}
		}

		if cfToken == "" || accountID == "" || dbID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "请先绑定并配置 D1 数据库"})
			return
		}

		ok, rows, msg := cf.D1Query(ctx, accountID, dbID, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name", nil)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": msg})
			return
		}

		var tables []string
		for _, row := range rows {
			if name, ok := row["name"].(string); ok && name != "" {
				tables = append(tables, name)
			}
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "tables": tables})
		return
	}

	tables, err := localUserTables(h.dbConn)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "tables": tables})
}

// obsoleteTables lists tables that have been removed from the application but may
// still exist in older databases. databaseCleanup will DROP them if present.
// Add entries here whenever a table is retired.
var obsoleteTables = []string{
	"tg_sign_tasks",           // merged into tg_auto_send_tasks
	"tg_login_flows",          // moved to in-memory store
	"tg_dialogs",              // moved to tg_data.db (local DB, not backed up to D1)
	"tg_auto_reply_rules_old", // placeholder for future retirements
}

// autoDatabaseCleanup drops any obsolete tables that still exist in the local SQLite DB,
// then synchronises Cloudflare D1 by dropping any tables present in D1 but absent locally.
// Executed silently in the background on startup.
func (h *Handler) autoDatabaseCleanup() {
	// ── Step 1: local SQLite cleanup ─────────────────────────────
	existing, err := localUserTables(h.dbConn)
	if err != nil {
		return
	}
	existSet := make(map[string]bool, len(existing))
	for _, t := range existing {
		existSet[t] = true
	}

	for _, t := range obsoleteTables {
		if !existSet[t] {
			continue
		}
		if _, err := h.dbConn.Exec("DROP TABLE IF EXISTS " + t); err == nil {
			delete(existSet, t)
		}
	}

	// Re-fetch local table list after cleanup
	localTables, _ := localUserTables(h.dbConn)

	// ── Step 2: D1 sync – drop tables that are in D1 but not local ──
	settings, _ := store.GetSettings(h.dbConn, []string{"cf_api_token", "cf_account_id", "cf_d1_database_id"})
	cfToken := strings.TrimSpace(settings["cf_api_token"])
	accountID := strings.TrimSpace(settings["cf_account_id"])
	dbID := strings.TrimSpace(settings["cf_d1_database_id"])

	if cfToken != "" && accountID != "" && dbID != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cf := d1.Client{Token: cfToken}
		_, _ = d1.SyncDropExtraD1Tables(ctx, cf, accountID, dbID, localTables)
	}
}

// databaseTableData returns JSON-encoded rows for a given local SQLite table or Cloudflare D1 table.
// The allowlist is dynamically built from sqlite_master, so ALL user tables are accessible.
func (h *Handler) databaseTableData(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false, "error": "not logged in"})
		return
	}

	tableName := strings.TrimSpace(c.Query("table"))
	if tableName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "table parameter required"})
		return
	}

	source := c.Query("source")
	if source == "d1" {
		settings, _ := store.GetSettings(h.dbConn, []string{"cf_api_token", "cf_account_id", "cf_d1_database_id"})
		cfToken := strings.TrimSpace(settings["cf_api_token"])
		accountID := strings.TrimSpace(settings["cf_account_id"])
		dbID := strings.TrimSpace(settings["cf_d1_database_id"])
		if cfToken == "" || accountID == "" || dbID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "请先绑定并配置 D1 数据库"})
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
		defer cancel()
		cf := d1.Client{Token: cfToken}

		// Allowlist check via D1 sqlite_master
		okCheck, checkRows, msgCheck := cf.D1Query(ctx, accountID, dbID, "SELECT name FROM sqlite_master WHERE type='table' AND name = ?", []any{tableName})
		if !okCheck {
			c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": "查询云端表结构出错: " + msgCheck})
			return
		}
		if len(checkRows) == 0 {
			c.JSON(http.StatusForbidden, gin.H{"ok": false, "error": "table not found in D1: " + tableName})
			return
		}

		okData, dataRows, msgData := cf.D1Query(ctx, accountID, dbID, "SELECT * FROM "+tableName+" LIMIT 500", nil)
		if !okData {
			c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": "查询云端数据出错: " + msgData})
			return
		}

		var cols []string
		if len(dataRows) > 0 {
			for k := range dataRows[0] {
				cols = append(cols, k)
			}
			sort.Strings(cols)
		} else {
			okPragma, pragmaRows, _ := cf.D1Query(ctx, accountID, dbID, "PRAGMA table_info("+tableName+")", nil)
			if okPragma {
				type colInfo struct {
					cid  int
					name string
				}
				var pCols []colInfo
				for _, pRow := range pragmaRows {
					cidNum := 0
					switch v := pRow["cid"].(type) {
					case float64:
						cidNum = int(v)
					case int:
						cidNum = v
					}
					if name, ok := pRow["name"].(string); ok && name != "" {
						pCols = append(pCols, colInfo{cid: cidNum, name: name})
					}
				}
				sort.Slice(pCols, func(i, j int) bool { return pCols[i].cid < pCols[j].cid })
				for _, c := range pCols {
					cols = append(cols, c.name)
				}
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"ok":      true,
			"table":   tableName,
			"columns": cols,
			"rows":    dataRows,
		})
		return
	}

	// Dynamic allowlist for local DB
	tables, err := localUserTables(h.dbConn)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": err.Error()})
		return
	}
	allowed := false
	for _, t := range tables {
		if t == tableName {
			allowed = true
			break
		}
	}
	if !allowed {
		c.JSON(http.StatusForbidden, gin.H{"ok": false, "error": "table not found: " + tableName})
		return
	}

	rows, err := h.dbConn.QueryContext(c.Request.Context(), "SELECT * FROM "+tableName+" LIMIT 500")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": err.Error()})
		return
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": err.Error()})
		return
	}

	result := make([]map[string]any, 0)
	for rows.Next() {
		values := make([]any, len(cols))
		valuePtrs := make([]any, len(cols))
		for i := range valuePtrs {
			valuePtrs[i] = &values[i]
		}
		if err := rows.Scan(valuePtrs...); err != nil {
			continue
		}
		row := make(map[string]any, len(cols))
		for i, col := range cols {
			if b, ok := values[i].([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = values[i]
			}
		}
		result = append(result, row)
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":      true,
		"table":   tableName,
		"columns": cols,
		"rows":    result,
	})
}

// dbStreamHeaders writes the NDJSON streaming response headers.
func dbStreamHeaders(c *gin.Context) (http.Flusher, bool) {
	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"ok": false, "error": "streaming not supported"})
		return nil, false
	}
	c.Header("Content-Type", "application/x-ndjson; charset=utf-8")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	return flusher, true
}

// dbStreamSend sends a single NDJSON progress event.
func dbStreamSend(c *gin.Context, flusher http.Flusher, percent int, message string, done bool, ok bool) bool {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	b, err := json.Marshal(updateStreamEvent{Percent: percent, Message: message, Done: done, OK: ok})
	if err != nil {
		return false
	}
	if _, err := c.Writer.Write(append(b, '\n')); err != nil {
		return false
	}
	flusher.Flush()
	return true
}

func (h *Handler) databaseBackupStream(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"ok": false, "error": "not logged in"})
		return
	}

	flusher, ok := dbStreamHeaders(c)
	if !ok {
		return
	}

	send := func(percent int, msg string, done bool, success bool) bool {
		return dbStreamSend(c, flusher, percent, msg, done, success)
	}
	fail := func(msg string) { _ = send(0, msg, true, false) }

	keys := []string{"cf_api_token", "cf_account_id", "cf_d1_database_id", "cf_d1_database_name"}
	settings, err := store.GetSettings(h.dbConn, keys)
	if err != nil {
		fail("读取配置失败：" + err.Error())
		return
	}
	cfToken := settings["cf_api_token"]
	accountID := settings["cf_account_id"]
	dbID := settings["cf_d1_database_id"]
	d1Name := settings["cf_d1_database_name"]
	if d1Name == "" {
		d1Name = config.UnifiedD1DBName
	}

	if !send(5, "正在验证配置...", false, false) {
		return
	}
	if cfToken == "" {
		fail("请先保存 API Token。")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Minute)
	defer cancel()
	cf := d1.Client{Token: cfToken}

	// Actively look up current AccountID and D1 Database ID to ignore stale caches
	if ok, _, acc := cf.TestToken(ctx); ok && acc != "" {
		accountID = acc
		_ = store.SetSetting(h.dbConn, "cf_account_id", accountID)
	}
	if accountID != "" {
		if ok, _, foundID := cf.FindD1ByName(ctx, accountID, d1Name); ok && foundID != "" {
			dbID = foundID
			_ = store.SetSetting(h.dbConn, "cf_d1_database_id", dbID)
		}
	}

	if accountID == "" || dbID == "" {
		fail("请先执行「自动创建/绑定」数据库。")
		return
	}

	if !send(10, "开始备份，正在同步表结构...", false, false) {
		return
	}

	// progress callback — called after every table, keeps SSE alive
	progFn := d1.ProgressFunc(func(pct int, msg string) {
		_ = send(pct, msg, false, false)
	})

	okBackup, backupMsg := d1.BackupLocalToD1WithProgress(ctx, cf, accountID, dbID, h.dbConn, progFn)
	if !okBackup {
		fail("备份失败：" + backupMsg)
		return
	}
	_ = send(100, backupMsg, true, true)
}

func (h *Handler) databasePullStream(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"ok": false, "error": "not logged in"})
		return
	}

	flusher, ok := dbStreamHeaders(c)
	if !ok {
		return
	}

	send := func(percent int, msg string, done bool, success bool) bool {
		return dbStreamSend(c, flusher, percent, msg, done, success)
	}
	fail := func(msg string) { _ = send(0, msg, true, false) }

	keys := []string{"cf_api_token", "cf_account_id", "cf_d1_database_id", "cf_d1_database_name"}
	settings, err := store.GetSettings(h.dbConn, keys)
	if err != nil {
		fail("读取配置失败：" + err.Error())
		return
	}
	cfToken := settings["cf_api_token"]
	accountID := settings["cf_account_id"]
	dbID := settings["cf_d1_database_id"]
	d1Name := settings["cf_d1_database_name"]
	if d1Name == "" {
		d1Name = config.UnifiedD1DBName
	}

	if !send(5, "正在验证配置...", false, false) {
		return
	}
	if cfToken == "" {
		fail("请先保存 API Token。")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Minute)
	defer cancel()
	cf := d1.Client{Token: cfToken}

	// Actively look up current AccountID and D1 Database ID to ignore stale caches
	if ok, _, acc := cf.TestToken(ctx); ok && acc != "" {
		accountID = acc
		_ = store.SetSetting(h.dbConn, "cf_account_id", accountID)
	}
	if accountID != "" {
		if ok, _, foundID := cf.FindD1ByName(ctx, accountID, d1Name); ok && foundID != "" {
			dbID = foundID
			_ = store.SetSetting(h.dbConn, "cf_d1_database_id", dbID)
		}
	}

	if accountID == "" || dbID == "" {
		fail("请先执行「自动创建/绑定」数据库。")
		return
	}

	if !send(10, "开始从云端拉取数据...", false, false) {
		return
	}

	// progress callback — called after every table, keeps SSE alive
	progFn := d1.ProgressFunc(func(pct int, msg string) {
		_ = send(pct, msg, false, false)
	})

	okPull, pullMsg := d1.PullD1ToLocalWithProgress(ctx, cf, accountID, dbID, h.dbConn, progFn)
	if !okPull {
		fail("拉取失败：" + pullMsg)
		return
	}
	_ = send(100, pullMsg, true, true)
}

// systemSettings renders the layout container containing the system settings tabs.
func (h *Handler) systemSettings(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}
	tab := c.Query("tab")
	if tab == "" {
		tab = "update" // default tab
	}
	c.HTML(http.StatusOK, "system_settings_layout.html", gin.H{
		"Title": "系统设置",
		"Tab":   tab,
	})
}

func (h *Handler) systemUpdate(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	message := ""
	msgOK := false

	ghInfo := update.GitHubReleaseInfo{OK: false, TagName: "-", Name: "-", PublishedAt: "-", AssetName: "-", Note: ""}
	ghOwner := "fengzhanhuaer"
	ghRepo := "VpsHelper"
	ghToken := ""
	ghAsset := ""

	if settings, err := store.GetSettings(h.dbConn, []string{"github_release_token", "github_release_asset"}); err == nil {
		ghToken = settings["github_release_token"]
		ghAsset = settings["github_release_asset"]
	}

	goappDir := h.cfg.BaseDir

	if c.Request.Method == http.MethodPost {
		action := c.PostForm("action")
		switch action {
		case "restart":
			message = "服务将在 1 秒后自动重启，请稍后刷新页面。"
			msgOK = true
			update.RestartDelayed(1 * time.Second)
		case "gh_save":
			ghToken = strings.TrimSpace(c.PostForm("gh_token"))
			ghAsset = strings.TrimSpace(c.PostForm("gh_asset"))

			_ = store.SetSetting(h.dbConn, "github_release_token", ghToken)
			_ = store.SetSetting(h.dbConn, "github_release_asset", ghAsset)
			message = "已保存配置。"
			msgOK = true
		case "gh_check", "gh_update":
			ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
			defer cancel()

			info, rel, err := update.FetchLatestGitHubRelease(ctx, ghOwner, ghRepo, ghToken)
			if err != nil && strings.TrimSpace(ghToken) != "" {
				// Fallback for public repos when saved token is invalid/expired.
				if info2, rel2, err2 := update.FetchLatestGitHubRelease(ctx, ghOwner, ghRepo, ""); err2 == nil {
					info, rel, err = info2, rel2, nil
					ghToken = ""
				}
			}
			if err != nil {
				ghInfo = info
				if ghInfo.Note == "" {
					ghInfo.Note = "检查 Release 失败。"
				}
				message = ghInfo.Note
				break
			}

			asset, err := update.SelectReleaseAsset(rel, ghAsset)
			if err != nil {
				ghInfo = info
				ghInfo.Note = "选择 Release asset 失败: " + err.Error()
				message = ghInfo.Note
				break
			}

			ghInfo = info
			ghInfo.AssetName = asset.Name
			if action == "gh_check" {
				message = "已获取最新 Release 信息。"
				msgOK = true
				break
			}

			// Download and restart.
			ext := ""
			if runtime.GOOS == "windows" {
				ext = ".exe"
			}
			dest := filepath.Join(goappDir, "bin", "vpshelper-release-next"+ext)
			// Under systemd, replace the current executable in-place so the
			// service restart uses the new binary path (ExecStart).
			if update.IsSystemdManaged() {
				if currentExe, e := os.Executable(); e == nil && currentExe != "" {
					dest = currentExe
				}
			}

			dlCtx, dlCancel := context.WithTimeout(c.Request.Context(), 15*time.Minute)
			defer dlCancel()
			bin, err := update.DownloadReleaseAsset(dlCtx, asset, ghToken, dest)
			if err != nil {
				message = "从 Release 下载失败: " + err.Error()
				break
			}
			// If downloaded asset is a zip, final binary path may differ from
			// ExecStart path. Move it back to current executable for systemd.
			if update.IsSystemdManaged() {
				if currentExe, e := os.Executable(); e == nil && currentExe != "" {
					if filepath.Clean(bin) != filepath.Clean(currentExe) {
						_ = os.Remove(currentExe)
						if err := os.Rename(bin, currentExe); err != nil {
							message = "替换可执行文件失败：" + err.Error()
							break
						}
						_ = os.Chmod(currentExe, 0o755)
						bin = currentExe
					}
				}
			}
			message = "已下载 Release(" + ghInfo.TagName + " / " + ghInfo.AssetName + "), 服务将在 1 秒后自动重启。"
			msgOK = true
			update.RestartToDelayed(bin, os.Args[1:], 1*time.Second)
		default:
			message = "未知操作。"
		}
	}

	c.HTML(http.StatusOK, "update_manager.html", gin.H{
		"Title":          "程序更新",
		"Message":        message,
		"MsgOK":          msgOK,
		"CurrentVersion": version.Version,
		"GH":             ghInfo,
		"GHToken":        ghToken,
		"GHAsset":        ghAsset,
	})
}

type updateStreamEvent struct {
	Percent int    `json:"percent"`
	Message string `json:"message"`
	Done    bool   `json:"done"`
	OK      bool   `json:"ok"`
}

func (h *Handler) systemUpdateStream(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"ok": false, "error": "not logged in"})
		return
	}

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"ok": false, "error": "stream not supported"})
		return
	}

	ghOwner := "fengzhanhuaer"
	ghRepo := "VpsHelper"
	ghToken := ""
	ghAsset := ""
	if settings, err := store.GetSettings(h.dbConn, []string{"github_release_token", "github_release_asset"}); err == nil {
		ghToken = settings["github_release_token"]
		ghAsset = settings["github_release_asset"]
	}
	if v, ok := c.GetPostForm("gh_token"); ok {
		ghToken = strings.TrimSpace(v)
	}
	if v, ok := c.GetPostForm("gh_asset"); ok {
		ghAsset = strings.TrimSpace(v)
	}

	c.Header("Content-Type", "application/x-ndjson; charset=utf-8")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	send := func(percent int, message string, done bool, success bool) bool {
		if percent < 0 {
			percent = 0
		}
		if percent > 100 {
			percent = 100
		}
		b, err := json.Marshal(updateStreamEvent{
			Percent: percent,
			Message: message,
			Done:    done,
			OK:      success,
		})
		if err != nil {
			return false
		}
		if _, err := c.Writer.Write(append(b, '\n')); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	fail := func(percent int, message string) {
		_ = send(percent, message, true, false)
	}

	if !send(3, "开始检查更新配置...", false, false) {
		return
	}

	if strings.TrimSpace(ghOwner) == "" || strings.TrimSpace(ghRepo) == "" {
		fail(5, "缺少 GitHub owner/repo，请先填写并保存配置。")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()
	if !send(10, "正在获取最新 Release 信息...", false, false) {
		return
	}

	info, rel, err := update.FetchLatestGitHubRelease(ctx, ghOwner, ghRepo, ghToken)
	if err != nil && strings.TrimSpace(ghToken) != "" {
		if !send(12, "Token 鉴权失败，尝试匿名获取 Release...", false, false) {
			return
		}
		if info2, rel2, err2 := update.FetchLatestGitHubRelease(ctx, ghOwner, ghRepo, ""); err2 == nil {
			info, rel, err = info2, rel2, nil
			ghToken = ""
		}
	}
	if err != nil {
		msg := "检查 Release 失败"
		if info.Note != "" {
			msg = info.Note
		}
		fail(15, msg)
		return
	}

	if !send(22, "已获取 Release: "+info.TagName, false, false) {
		return
	}

	if version.Version != "dev" && info.TagName == version.Version {
		_ = send(100, "当前已是最新版本，无需升级！", true, true)
		return
	}

	asset, err := update.SelectReleaseAsset(rel, ghAsset)
	if err != nil {
		fail(25, "选择 Release Asset 失败: "+err.Error())
		return
	}
	if !send(30, "已选择 Asset: "+asset.Name, false, false) {
		return
	}

	goappDir := h.cfg.BaseDir
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	dest := filepath.Join(goappDir, "bin", "vpshelper-release-next"+ext)
	if update.IsSystemdManaged() {
		if currentExe, e := os.Executable(); e == nil && currentExe != "" {
			dest = currentExe
		}
	}

	if !send(35, "开始下载更新包...", false, false) {
		return
	}

	dlCtx, dlCancel := context.WithTimeout(c.Request.Context(), 15*time.Minute)
	defer dlCancel()

	bin, err := update.DownloadReleaseAssetWithProgress(dlCtx, asset, ghToken, dest, func(p update.DownloadProgress) {
		percent := 70
		progressText := "下载中..."
		if p.Total > 0 {
			delta := int((p.Received * 55) / p.Total)
			if delta < 0 {
				delta = 0
			}
			if delta > 55 {
				delta = 55
			}
			percent = 35 + delta
			progressText = "下载中：" + formatSize(p.Received) + " / " + formatSize(p.Total)
		} else {
			progressText = "下载中：" + formatSize(p.Received)
		}
		_ = send(percent, progressText, false, false)
	})
	if err != nil {
		fail(40, "从 Release 下载失败: "+err.Error())
		return
	}

	if !send(92, "下载完成，正在触发新版本预启动自检 (拦截崩溃或异常)...", false, false) {
		return
	}

	ctxTest, cancelTest := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelTest()
	cmd := exec.CommandContext(ctxTest, bin, os.Args[1:]...)
	cmd.Env = append(os.Environ(), "VPSHELPER_UPDATE_TEST=1")
	out, errTest := cmd.CombinedOutput()

	if errTest != nil || ctxTest.Err() == context.DeadlineExceeded {
		failMsg := "新版本自检失败，已自动回滚并保持当前原版运行! 原因: "
		if errTest != nil {
			failMsg += errTest.Error()
		} else {
			failMsg += "心跳存活超时"
		}
		_ = os.Remove(bin) // Rollback: do not use the corrupted binary
		fail(93, failMsg+". 输出记录: "+string(out))
		return
	}

	if !send(94, "启动自检通过，开始无缝替换可执行文件...", false, false) {
		return
	}

	if update.IsSystemdManaged() {
		if currentExe, e := os.Executable(); e == nil && currentExe != "" {
			if filepath.Clean(bin) != filepath.Clean(currentExe) {
				_ = os.Remove(currentExe)
				if err := os.Rename(bin, currentExe); err != nil {
					fail(94, "替换可执行文件失败："+err.Error())
					return
				}
				_ = os.Chmod(currentExe, 0o755)
				bin = currentExe
			}
		}
	}

	finalMsg := "更新完成(" + info.TagName + " / " + asset.Name + ")，服务将在 1 秒后自动重启。"
	if !send(100, finalMsg, true, true) {
		return
	}

	// Clean up legacy on-disk static/ and templates/ directories so they
	// do not shadow the embedded assets in the new binary.
	for _, dir := range []string{"static", "templates"} {
		target := filepath.Join(goappDir, dir)
		if err := os.RemoveAll(target); err != nil {
			// Non-fatal: log to progress but continue with restart.
			_ = send(100, "提示：清理旧目录 "+dir+" 失败（"+err.Error()+"），但不影响更新结果。", true, true)
		}
	}

	update.RestartToDelayed(bin, os.Args[1:], 1*time.Second)
}

func formatSize(bytes int64) string {
	if bytes < 0 {
		return "0 B"
	}
	const kb = int64(1024)
	const mb = kb * 1024
	const gb = mb * 1024
	const tb = gb * 1024

	switch {
	case bytes >= tb:
		return fmt.Sprintf("%.2f TB", float64(bytes)/float64(tb))
	case bytes >= gb:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(gb))
	case bytes >= mb:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(mb))
	case bytes >= kb:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(kb))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func (h *Handler) sshSettings(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	message := ""
	msgOK := false
	if c.Request.Method == http.MethodPost {
		action := strings.TrimSpace(c.PostForm("action"))
		switch action {
		case "install_fail2ban":
			ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Minute)
			defer cancel()
			ok, msg := ssh.InstallFail2ban(ctx)
			if ok {
				message = msg
				msgOK = true
			} else {
				message = "安装失败: " + msg
			}
		case "disable_fail2ban":
			ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
			defer cancel()
			ok, msg := ssh.DisableFail2ban(ctx)
			if ok {
				message = msg
				msgOK = true
			} else {
				message = "操作失败: " + msg
			}
		case "diagnose_ssh":
			portText := strings.TrimSpace(c.PostForm("ssh_port"))
			p, _ := strconv.Atoi(portText)
			message = ssh.Diagnose(p)
		default:
			portText := strings.TrimSpace(c.PostForm("ssh_port"))
			pub := strings.TrimSpace(c.PostForm("ssh_public_key"))
			listenAddrsRaw := strings.TrimSpace(c.PostForm("ssh_listen_address"))
			allowPass := c.PostForm("allow_password_login") == "on"
			allowKey := c.PostForm("allow_key_login") == "on"
			p, err := strconv.Atoi(portText)
			if err != nil || p < 1 || p > 65535 {
				message = "SSH 端口范围必须在 1-65535。"
				break
			}

			// Only store public key and listen address in database (for backup)
			_ = store.SetSetting(h.dbConn, "ssh_public_key", pub)
			_ = store.SetSetting(h.dbConn, "ssh_listen_address", listenAddrsRaw)

			ctx, cancel := context.WithTimeout(c.Request.Context(), 45*time.Second)
			defer cancel()
			ok, msg := ssh.ApplySettings(ctx, p, allowPass, allowKey, pub)
			if ok {
				message = "SSH 设置已应用到系统。"
				msgOK = true

				fwType := firewall.DetectType()
				if fwType != "未知" && fwType != "" && listenAddrsRaw != "" && firewall.IsActive(fwType) {
					fwMsgs := []string{}
					parts := regexp.MustCompile(`[,\s]+`).Split(listenAddrsRaw, -1)
					for _, part := range parts {
						if part == "" {
							continue
						}
						base := part
						suffix := ""
						if idx := strings.LastIndex(part, "/"); idx != -1 {
							base = part[:idx]
							suffix = part[idx:]
						}

						ips, err := firewall.ResolveIPWithCIDR(base, suffix)
						if err == nil && len(ips) > 0 {
							for _, ip := range ips {
								fwOk, fwMsg := firewall.OpenPort(fwType, p, "tcp", ip)
								if fwOk {
									fwMsgs = append(fwMsgs, fwMsg)
								}
							}
							if err := firewall.AddDomainRule(h.dbConn, base, suffix, p, "tcp", ips); err == nil {
								fwMsgs = append(fwMsgs, fmt.Sprintf("规则 %s 的防火墙联动放行均已提交并录入", part))
							}
						}
					}
					if len(fwMsgs) > 0 {
						message += " (附: 防火墙已联动开放对应源IP，您可以在防火墙页面查看并管理这些规则。)"
					}
				}
			} else {
				message = "系统应用失败：" + msg
			}
		}
	}

	// Read port, password/key auth from actual system config
	sysCfg := ssh.ReadSystemConfig()

	// Read public key and listener configs from database (backup & editable)
	dbSettings, _ := store.GetSettings(h.dbConn, []string{"ssh_public_key", "ssh_listen_address"})
	pubKey := dbSettings["ssh_public_key"]
	listenDbValue := dbSettings["ssh_listen_address"]
	// If database has no public key stored yet, show system authorized_keys
	if pubKey == "" {
		pubKey = sysCfg.AuthorizedKeys
	}
	if listenDbValue == "" && len(sysCfg.ListenAddress) > 0 {
		listenDbValue = strings.Join(sysCfg.ListenAddress, ", ")
	}

	fail2banStat := ssh.Fail2banStatus(c.Request.Context())

	// Try fetching Last Logs (Fallback depending on platform)
	loginRecords := getLoginRecords()

	c.HTML(http.StatusOK, "ssh_settings.html", gin.H{
		"Title":              "SSH 设置与安防",
		"Message":            message,
		"MsgOK":              msgOK,
		"SSHPort":            strconv.Itoa(sysCfg.Port),
		"ListenAddress":      listenDbValue,
		"SSHPublicKey":       pubKey,
		"AllowPasswordLogin": sysCfg.AllowPassword,
		"AllowKeyLogin":      sysCfg.AllowPubkey,
		"Fail2banStatus":     fail2banStat,
		"LoginRecords":       loginRecords,
	})
}

func getLoginRecords() string {
	if runtime.GOOS == "windows" {
		return "Windows 系统不支持读取 auth log"
	}
	// Try last command
	cmd := exec.Command("last", "-n", "10", "-i")
	out, err := cmd.Output()
	if err == nil && len(out) > 0 {
		return string(out)
	}
	return "无最近登录记录或最后登陆读取失败。"
}

func bool01(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func (h *Handler) serverStatus(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	data := status.Collect()
	c.HTML(http.StatusOK, "server_status.html", gin.H{
		"Title":  "服务器状态",
		"Status": data,
	})
}

func (h *Handler) serverStatusData(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false, "message": "未登录或会话已过期。"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "data": status.Collect()})
}

func (h *Handler) systemLog(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}
	c.HTML(http.StatusOK, "system_log.html", gin.H{
		"Title": "运行日志",
	})
}

func (h *Handler) systemLogData(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false, "message": "未登录或会话已过期。"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "data": logger.GetLogs()})
}

type shortcutItem struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Command string `json:"command"`
}

func (h *Handler) shellConsole(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	sess := sessions.Default(c)
	cwd, _ := sess.Get("shell_cwd").(string)
	cwd = shell.ResolveCWD(cwd)
	sess.Set("shell_cwd", cwd)
	_ = sess.Save()

	history := shell.LoadHistory(h.cfg.DataDir, username)
	shortcuts, _ := h.loadShellShortcuts(username)

	historyJSON, _ := json.Marshal(history)
	shortcutsJSON, _ := json.Marshal(shortcuts)

	c.HTML(http.StatusOK, "shell_console.html", gin.H{
		"Title":         "Shell 交互",
		"CWD":           cwd,
		"HistoryJSON":   string(historyJSON),
		"ShortcutsJSON": string(shortcutsJSON),
		"Shortcuts":     shortcuts,
		"History":       history,
	})
}

func (h *Handler) shellExec(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false, "output": "未登录或会话已过期。", "cwd": ""})
		return
	}

	command := strings.TrimSpace(c.PostForm("command"))
	sess := sessions.Default(c)
	cwd, _ := sess.Get("shell_cwd").(string)
	cwd = shell.ResolveCWD(cwd)

	if command == "" {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "output": "命令不能为空。", "cwd": cwd})
		return
	}

	shell.AppendHistory(h.cfg.DataDir, username, command)

	if newCWD, ok, msg := shell.ApplyCD(cwd, command); ok {
		sess.Set("shell_cwd", newCWD)
		_ = sess.Save()
		c.JSON(http.StatusOK, gin.H{"ok": true, "output": msg, "cwd": newCWD})
		return
	}

	ok, out, err := shell.Run(c.Request.Context(), cwd, command)
	if err != nil && errors.Is(err, context.DeadlineExceeded) {
		c.JSON(http.StatusRequestTimeout, gin.H{"ok": false, "output": out, "cwd": cwd})
		return
	}

	sess.Set("shell_cwd", cwd)
	_ = sess.Save()

	status := http.StatusOK
	if !ok {
		status = http.StatusOK
	}
	c.JSON(status, gin.H{"ok": ok, "output": out, "cwd": cwd})
}

func (h *Handler) shellShortcutsAdd(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false, "message": "未登录或会话已过期。"})
		return
	}

	name := strings.TrimSpace(c.PostForm("name"))
	command := strings.TrimSpace(c.PostForm("command"))
	if name == "" || command == "" {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "message": "名称和命令不能为空。"})
		return
	}

	_, err := h.dbConn.Exec(
		"INSERT INTO shell_shortcuts (owner, name, command, created_at) VALUES (?, ?, ?, ?)",
		username,
		name,
		command,
		time.Now().Format(time.RFC3339),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "message": "保存失败。"})
		return
	}

	row := h.dbConn.QueryRow("SELECT last_insert_rowid()")
	var id int64
	_ = row.Scan(&id)
	c.JSON(http.StatusOK, gin.H{"ok": true, "item": shortcutItem{ID: id, Name: name, Command: command}})
}

func (h *Handler) shellShortcutsDelete(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false, "message": "未登录或会话已过期。"})
		return
	}

	idText := c.Param("id")
	id, _ := strconv.ParseInt(idText, 10, 64)
	_, _ = h.dbConn.Exec("DELETE FROM shell_shortcuts WHERE id = ? AND owner = ?", id, username)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *Handler) shellShortcutsClear(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false, "message": "未登录或会话已过期。"})
		return
	}
	_, _ = h.dbConn.Exec("DELETE FROM shell_shortcuts WHERE owner = ?", username)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *Handler) loadShellShortcuts(owner string) ([]shortcutItem, error) {
	rows, err := h.dbConn.Query("SELECT id, name, command FROM shell_shortcuts WHERE owner = ? ORDER BY id ASC", owner)
	if err != nil {
		return []shortcutItem{}, err
	}
	defer rows.Close()

	items := make([]shortcutItem, 0)
	for rows.Next() {
		var it shortcutItem
		if err := rows.Scan(&it.ID, &it.Name, &it.Command); err != nil {
			continue
		}
		items = append(items, it)
	}
	return items, nil
}

func (h *Handler) firewallPage(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	message := ""
	msgOK := false
	fwType := firewall.DetectType()

	if c.Request.Method == http.MethodPost {
		action := strings.TrimSpace(c.PostForm("action"))
		switch action {
		case "enable_firewall":
			ok, msg := firewall.Enable(fwType)
			if ok {
				message = msg
				msgOK = true
			} else {
				message = "操作失败: " + msg
			}
		case "disable_firewall":
			ok, msg := firewall.Disable(fwType)
			if ok {
				message = msg
				msgOK = true
				fwType = firewall.DetectType()
			} else {
				message = "操作失败: " + msg
			}
		case "open_port":
			portText := strings.TrimSpace(c.PostForm("port"))
			proto := strings.TrimSpace(c.PostForm("protocol"))
			sourceInput := strings.TrimSpace(c.PostForm("source_ip"))
			port, err := strconv.Atoi(portText)
			if err != nil {
				message = "端口必须是数字。"
				break
			}

			if sourceInput == "" {
				// Global open
				ok, msg := firewall.OpenPort(fwType, port, proto, "")
				if ok {
					message = msg
					msgOK = true
				} else {
					message = "操作失败: " + msg
				}
				break
			}

			// Supports multiples separated by comma or space
			sources := regexp.MustCompile(`[,\s]+`).Split(sourceInput, -1)
			var successMsgs []string
			var errorMsgs []string

			for _, src := range sources {
				src = strings.TrimSpace(src)
				if src == "" {
					continue
				}

				// separate possible CIDR from src
				baseDomain := src
				suffix := ""
				if idx := strings.LastIndex(src, "/"); idx != -1 {
					baseDomain = src[:idx]
					suffix = src[idx:]
				}

				if net.ParseIP(baseDomain) != nil {
					// Static IP or IP with CIDR
					ok, msg := firewall.OpenPort(fwType, port, proto, src)
					if ok {
						successMsgs = append(successMsgs, msg)
					} else {
						errorMsgs = append(errorMsgs, msg)
					}
				} else {
					// Treat as Domain
					initialIPs, err := firewall.ResolveIPWithCIDR(baseDomain, suffix)
					if err == nil && len(initialIPs) > 0 {
						// Open current IPs directly
						for _, initialIP := range initialIPs {
							firewall.OpenPort(fwType, port, proto, initialIP)
						}
					}
					// Add to Watcher Loop
					if err := firewall.AddDomainRule(h.dbConn, baseDomain, suffix, port, proto, initialIPs); err != nil {
						errorMsgs = append(errorMsgs, src+" 保存动态域名观察队列失败: "+err.Error())
					} else {
						msg := fmt.Sprintf("域名 %s 已加入防护观察。", src)
						if len(initialIPs) > 0 {
							msg += " (当前 IP: " + strings.Join(initialIPs, ", ") + ")"
						} else {
							msg += " (当前无法解析，稍后后台将自动重试)"
						}
						successMsgs = append(successMsgs, msg)
					}
				}
			}

			if len(errorMsgs) > 0 {
				message = "有部分操作失败: " + strings.Join(errorMsgs, "；")
			} else if len(successMsgs) > 0 {
				message = strings.Join(successMsgs, "；")
				msgOK = true
			}
		case "close_port":
			portText := strings.TrimSpace(c.PostForm("port"))
			proto := strings.TrimSpace(c.PostForm("protocol"))
			sourceIP := strings.TrimSpace(c.PostForm("source_ip"))
			port, err := strconv.Atoi(portText)
			if err != nil {
				message = "端口必须是数字。"
				break
			}
			ok, msg := firewall.DeletePort(fwType, port, proto, sourceIP)
			if ok {
				message = msg
				msgOK = true
			} else {
				message = "关闭端口失败: " + msg
			}
		}
	}

	// Handle domain rule deletion outside the switch so fresh data is read after any add
	if c.Request.Method == http.MethodPost && strings.TrimSpace(c.PostForm("action")) == "delete_domain_rule" {
		idxText := strings.TrimSpace(c.PostForm("rule_idx"))
		idx, err := strconv.Atoi(idxText)
		if err == nil {
			settings, _ := store.GetSettings(h.dbConn, []string{"fw_domain_rules"})
			var rules []firewall.DomainRule
			if settings["fw_domain_rules"] != "" {
				_ = json.Unmarshal([]byte(settings["fw_domain_rules"]), &rules)
			}
			if idx >= 0 && idx < len(rules) {
				rule := rules[idx]
				cacheKey := fmt.Sprintf("fw_cache_%s_%s_%d_%s", rule.Domain, rule.Suffix, rule.Port, rule.Protocol)
				lastIPsStr := store.GetLocalSetting(cacheKey)
				if lastIPsStr != "" {
					var oldIPs []string
					_ = json.Unmarshal([]byte(lastIPsStr), &oldIPs)
					for _, ip := range oldIPs {
						firewall.DeletePort(fwType, rule.Port, rule.Protocol, ip)
					}
					_ = store.SetLocalSetting(cacheKey, "")
				}
				rules = append(rules[:idx], rules[idx+1:]...)
				newJSON, _ := json.Marshal(rules)
				_ = store.SetSetting(h.dbConn, "fw_domain_rules", string(newJSON))
				message = fmt.Sprintf("已删除规则 %s%s、端口 %d/%s", rule.Domain, rule.Suffix, rule.Port, rule.Protocol)
				msgOK = true
			}
		}
	}

	openPorts, fwStatus, note := firewall.CollectOpenPortsAndStatus(fwType)
	bindings := firewall.CollectListeningBindings()
	procMap := firewall.CollectPortProcesses()
	listeningRows := firewall.CollectListeningRows()

	portRows := make([]map[string]any, 0)
	for _, item := range openPorts {
		port := item["port"]
		proto := item["protocol"]
		source := item["source"]
		key := proto + ":" + port
		bindIPs := keysFromSet(bindings[key])
		procNames := keysFromSet(procMap[key])
		if len(bindIPs) == 0 {
			bindIPs = []string{"未监听"}
		}
		if len(procNames) == 0 {
			procNames = []string{"未知"}
		}
		portRows = append(portRows, map[string]any{
			"port":          port,
			"protocol":      proto,
			"source":        source,
			"bind_ips":      bindIPs,
			"process_names": procNames,
		})
	}

	// Load domain rules for display
	dbRulesSettings, _ := store.GetSettings(h.dbConn, []string{"fw_domain_rules"})
	var domainRules []map[string]any
	if dbRulesSettings["fw_domain_rules"] != "" {
		var rules []firewall.DomainRule
		if err := json.Unmarshal([]byte(dbRulesSettings["fw_domain_rules"]), &rules); err == nil {
			for i, r := range rules {
				cacheKey := fmt.Sprintf("fw_cache_%s_%s_%d_%s", r.Domain, r.Suffix, r.Port, r.Protocol)
				cachedIPs := ""
				if raw := store.GetLocalSetting(cacheKey); raw != "" {
					var ips []string
					if json.Unmarshal([]byte(raw), &ips) == nil {
						cachedIPs = strings.Join(ips, ", ")
					}
				}
				domainRules = append(domainRules, map[string]any{
					"idx":      i,
					"domain":   r.Domain + r.Suffix,
					"port":     r.Port,
					"protocol": r.Protocol,
					"cur_ips":  cachedIPs,
				})
			}
		}
	}

	c.HTML(http.StatusOK, "firewall.html", gin.H{
		"Title":          "防火墙",
		"Message":        message,
		"MsgOK":          msgOK,
		"FirewallType":   fwType,
		"FirewallStatus": fwStatus,
		"Note":           note,
		"PortRows":       portRows,
		"ListeningRows":  listeningRows,
		"DomainRules":    domainRules,
	})
}

func keysFromSet(m map[string]struct{}) []string {
	if len(m) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// tgChat renders the chat history page (Telegram Web–style UI).
func (h *Handler) tgChat(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	accounts, err := store.ListTGAccounts(h.dbConn, username)
	if err != nil {
		c.String(http.StatusInternalServerError, "load accounts failed")
		return
	}

	selectedAccountID := int64(0)
	if len(accounts) > 0 {
		selectedAccountID = accounts[0].ID
	}
	if v := strings.TrimSpace(c.Query("account_id")); v != "" {
		if id, err2 := strconv.ParseInt(v, 10, 64); err2 == nil && id > 0 {
			selectedAccountID = id
		}
	}

	var dialogs []store.TGDialog
	if selectedAccountID > 0 {
		dialogs, _ = store.ListTGDialogs(h.dbConn, selectedAccountID)
	}

	c.HTML(http.StatusOK, "tg_chat.html", gin.H{
		"Title":     "会话历史",
		"Accounts":  accounts,
		"AccountID": selectedAccountID,
		"Dialogs":   dialogs,
	})
}

// tgChatMessages returns JSON chat messages for a given account + dialog.
// If no local messages are stored yet, automatically fetches recent history from Telegram.
func (h *Handler) tgChatMessages(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false, "error": "not logged in"})
		return
	}
	accountIDText := strings.TrimSpace(c.Query("account_id"))
	dialogID := strings.TrimSpace(c.Query("dialog_id"))
	accountID, err := strconv.ParseInt(accountIDText, 10, 64)
	if err != nil || accountID <= 0 || dialogID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "invalid params"})
		return
	}

	msgs, err := store.ListChatMessages(accountID, dialogID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": err.Error()})
		return
	}

	fetched := false
	if len(msgs) == 0 {
		// Nothing stored locally — pull from Telegram directly.
		ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
		defer cancel()
		pulled, fetchErr := tg.FetchAndStoreDialogHistory(ctx, h.dbConn, username, accountID, dialogID, 100)
		if fetchErr == nil && len(pulled) > 0 {
			msgs = pulled
			fetched = true
		}
	}

	if msgs == nil {
		msgs = []store.ChatMessage{}
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "messages": msgs, "fetched": fetched})
}

// tgChatSearch serves as a JSON API to search across all chat messages for a specific account.
func (h *Handler) tgChatSearch(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false, "error": "not logged in"})
		return
	}
	accountIDText := strings.TrimSpace(c.Query("account_id"))
	query := strings.TrimSpace(c.Query("q"))

	accountID, err := strconv.ParseInt(accountIDText, 10, 64)
	if err != nil || accountID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "invalid account_id"})
		return
	}
	if query == "" {
		c.JSON(http.StatusOK, gin.H{"ok": true, "results": []store.SearchResult{}})
		return
	}

	// Fetch dialog titles for better display in search results.
	dialogs, _ := store.ListTGDialogs(h.dbConn, accountID)
	titleMap := make(map[string]string)
	for _, d := range dialogs {
		titleMap[d.DialogID] = d.Title
	}

	results, err := store.SearchChatMessages(accountID, query, titleMap, 100)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": "search failed: " + err.Error()})
		return
	}
	if results == nil {
		results = []store.SearchResult{}
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "results": results})
}

// tgChatSend sends a text message to a dialog on behalf of the logged-in user.
func (h *Handler) tgChatSend(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false, "error": "not logged in"})
		return
	}
	accountIDText := strings.TrimSpace(c.PostForm("account_id"))
	dialogID := strings.TrimSpace(c.PostForm("dialog_id"))
	text := strings.TrimSpace(c.PostForm("text"))

	accountID, err := strconv.ParseInt(accountIDText, 10, 64)
	if err != nil || accountID <= 0 || dialogID == "" || text == "" {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "invalid params"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	sent, err := tg.SendChatMessageFromPage(ctx, h.dbConn, username, accountID, dialogID, text)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": sent})
}
