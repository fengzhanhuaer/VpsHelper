package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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
	"vpshelper-go/internal/shell"
	"vpshelper-go/internal/ssh"
	"vpshelper-go/internal/status"
	"vpshelper-go/internal/store"
	"vpshelper-go/internal/tg"
	"vpshelper-go/internal/update"
	"vpshelper-go/internal/version"
)

type Handler struct {
	cfg    config.Config
	dbConn *sql.DB
}

func Register(router *gin.Engine, cfg config.Config, dbConn *sql.DB) {
	h := &Handler{cfg: cfg, dbConn: dbConn}

	router.GET("/", h.index)
	router.GET("/home", h.home)
	router.GET("/login", h.login)
	router.POST("/login", h.login)
	router.GET("/register", h.register)
	router.POST("/register", h.register)
	router.GET("/logout", h.logout)
	router.GET("/change_password", h.changePassword)
	router.POST("/change_password", h.changePassword)
	router.GET("/tg_helper", h.tgHelper)
	router.GET("/tg/settings", h.tgSettings)
	router.POST("/tg/settings", h.tgSettings)
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
	router.GET("/tg/sign", h.tgSign)
	router.POST("/tg/sign", h.tgSign)
	router.GET("/tg/auto/reply", h.tgAutoReply)
	router.POST("/tg/auto/reply", h.tgAutoReply)
	router.GET("/tg/auto/send", h.tgAutoSend)
	router.POST("/tg/auto/send", h.tgAutoSend)
	router.GET("/tg/auto/send/new", h.tgAutoSendNew)
	router.POST("/tg/auto/send/new", h.tgAutoSendNew)
	router.GET("/settings/database", h.databaseSettings)
	router.POST("/settings/database", h.databaseSettings)
	router.GET("/settings/ssh", h.sshSettings)
	router.POST("/settings/ssh", h.sshSettings)
	router.GET("/system/update", h.systemUpdate)
	router.POST("/system/update", h.systemUpdate)
	router.POST("/system/update/stream", h.systemUpdateStream)
	router.GET("/server/status", h.serverStatus)
	router.GET("/server/status/data", h.serverStatusData)
	router.GET("/shell", h.shellConsole)
	router.POST("/shell/exec", h.shellExec)
	router.POST("/shell/shortcuts/add", h.shellShortcutsAdd)
	router.POST("/shell/shortcuts/delete/:id", h.shellShortcutsDelete)
	router.POST("/shell/shortcuts/clear", h.shellShortcutsClear)
	router.GET("/firewall", h.firewallPage)
	router.POST("/firewall", h.firewallPage)
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
	if hasUsers && h.currentUser(c) != "" {
		c.Redirect(http.StatusFound, "/home")
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
			}
		}
	}

	c.HTML(http.StatusOK, "change_password.html", gin.H{
		"Title":    "修改密码",
		"Username": username,
		"Message":  msg,
	})
}

func (h *Handler) tgHelper(c *gin.Context) {
	if h.currentUser(c) == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}
	settings, err := store.GetSettings(h.dbConn, []string{"telegram_api_id", "telegram_api_hash"})
	if err != nil {
		c.String(http.StatusInternalServerError, "load settings failed")
		return
	}

	apiID := settings["telegram_api_id"]
	apiHash := settings["telegram_api_hash"]
	configured := apiID != "" && apiHash != ""

	c.HTML(http.StatusOK, "tg_helper.html", gin.H{
		"Title":      "TgHelper",
		"Configured": configured,
	})
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

	if err := store.CreateTGAccount(h.dbConn, username, accountName, updatedFlow.SessionText); err != nil {
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

	c.Redirect(http.StatusFound, "/tg_helper")
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

	message := ""
	if c.Request.Method == http.MethodPost {
		action := strings.TrimSpace(c.PostForm("action"))
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
			n, msg := tg.RefreshDialogs(ctx, h.dbConn, username, selectedAccountID, apiID, apiHash, allProxy)
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
			} else {
				message = fmt.Sprintf("已刷新会话列表：%d 条（已保存会话ID）。", n)
			}
		default:
			message = "未知操作。"
		}
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

	if c.Request.Method == http.MethodPost {
		action := strings.TrimSpace(c.PostForm("action"))
		switch action {
		case "save":
			allProxy = strings.TrimSpace(c.PostForm("all_proxy"))
			_ = store.SetSetting(h.dbConn, "tg_all_proxy", allProxy)
			message = "已保存。"
		case "clear":
			allProxy = ""
			_ = store.SetSetting(h.dbConn, "tg_all_proxy", "")
			message = "已清空。"
		default:
			message = "未知操作。"
		}
	}

	c.HTML(http.StatusOK, "tg_proxy.html", gin.H{
		"Title":    "TG 代理设置",
		"Message":  message,
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

	message := ""
	if c.Request.Method == http.MethodPost {
		action := strings.TrimSpace(c.PostForm("action"))
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
					n, msg := tg.RefreshDialogs(ctx, h.dbConn, username, accountID, apiID, apiHash, allProxy)
					if msg != "ok" {
						message = "刷新失败: " + msg
					} else {
						migrated, migrateErr := tg.NormalizeStoredTargetsByDialogs(h.dbConn, username, accountID)
						if migrateErr != nil {
							message = fmt.Sprintf("已刷新会话列表：%d 条（已保存会话ID）。任务迁移失败：%s", n, migrateErr.Error())
						} else if migrated > 0 {
							message = fmt.Sprintf("已刷新会话列表：%d 条，已迁移 %d 条任务目标为会话ID。", n, migrated)
						} else {
							message = fmt.Sprintf("已刷新会话列表：%d 条（已保存会话ID）。", n)
						}
					}
				}
			}
		} else {
			message = "未知操作。"
		}
	}

	dialogs, err := store.ListTGDialogs(h.dbConn, accountID)
	if err != nil {
		c.String(http.StatusInternalServerError, "load dialogs failed")
		return
	}

	c.HTML(http.StatusOK, "tg_dialogs.html", gin.H{
		"Title":     "会话列表",
		"Message":   message,
		"Accounts":  accounts,
		"AccountID": accountID,
		"Dialogs":   dialogs,
	})
}

func (h *Handler) tgSign(c *gin.Context) {
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
		c.HTML(http.StatusOK, "tg_sign.html", gin.H{
			"Title":       "签到任务",
			"Message":     "请先登录添加一个 TG 账号。",
			"Accounts":    accounts,
			"AccountID":   int64(0),
			"Dialogs":     []store.TGDialog{},
			"DialogID":    "",
			"SignMessage": "",
			"CreatedAt":   "",
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

	dialogs, _ := store.ListTGDialogs(h.dbConn, accountID)

	saved, okSaved, _ := store.GetSignTask(h.dbConn, username, accountID)
	dialogID := ""
	signMsg := ""
	createdAt := ""
	if okSaved {
		dialogID = saved.DialogID
		signMsg = saved.Message
		createdAt = saved.CreatedAt
	}

	message := ""
	autoLast := ""
	if s, err := store.GetSettings(h.dbConn, []string{"tg_sign_auto_last_result"}); err == nil {
		autoLast = s["tg_sign_auto_last_result"]
	}
	if c.Request.Method == http.MethodPost {
		action := strings.TrimSpace(c.PostForm("action"))
		pick := strings.TrimSpace(c.PostForm("dialog_pick"))
		input := strings.TrimSpace(c.PostForm("dialog_id"))
		if pick != "" {
			dialogID = pick
		} else {
			dialogID = input
		}
		signMsg = strings.TrimSpace(c.PostForm("msg"))

		switch action {
		case "save":
			if dialogID == "" {
				message = "请选择/填写目标。"
				break
			}
			resolveCtx, resolveCancel := context.WithTimeout(c.Request.Context(), 35*time.Second)
			resolvedDialogID, resolveErr := tg.ResolveDialogIDForAccount(resolveCtx, h.dbConn, username, accountID, dialogID)
			resolveCancel()
			if resolveErr != nil {
				message = "目标解析失败: " + resolveErr.Error()
				break
			}
			dialogID = resolvedDialogID
			if err := store.UpsertSignTask(h.dbConn, username, accountID, dialogID, signMsg); err != nil {
				message = "保存失败。"
			} else {
				message = "已保存。"
			}
		case "delete":
			if err := store.DeleteSignTask(h.dbConn, username, accountID); err != nil {
				message = "删除失败。"
			} else {
				message = "已删除。"
				dialogID = ""
				signMsg = ""
				createdAt = ""
			}
		case "run":
			if dialogID == "" {
				message = "请选择/填写目标。"
				break
			}
			submittedDialogID := dialogID
			ctx, cancel := context.WithTimeout(c.Request.Context(), 40*time.Second)
			defer cancel()
			ok, msg, resolvedDialogID := tg.SendOnceWithResolvedDialogID(ctx, h.dbConn, username, accountID, dialogID, signMsg)
			if ok {
				message = msg
				if resolvedDialogID != "" {
					dialogID = resolvedDialogID
					if savedTask, okSavedNow, _ := store.GetSignTask(h.dbConn, username, accountID); okSavedNow {
						sameTarget := strings.TrimSpace(savedTask.DialogID) == strings.TrimSpace(submittedDialogID) ||
							strings.EqualFold(tg.NormalizeUsername(savedTask.DialogID), tg.NormalizeUsername(submittedDialogID))
						if sameTarget && strings.TrimSpace(savedTask.DialogID) != strings.TrimSpace(resolvedDialogID) {
							_ = store.UpsertSignTask(h.dbConn, username, accountID, resolvedDialogID, savedTask.Message)
						}
					}
				}
			} else {
				message = "执行失败: " + msg
			}
		default:
			message = "未知操作。"
		}

		// reload saved
		if t2, ok2, _ := store.GetSignTask(h.dbConn, username, accountID); ok2 {
			saved = t2
			createdAt = t2.CreatedAt
		}
	}

	c.HTML(http.StatusOK, "tg_sign.html", gin.H{
		"Title":       "签到任务",
		"Message":     message,
		"AutoLast":    autoLast,
		"Accounts":    accounts,
		"AccountID":   accountID,
		"Dialogs":     dialogs,
		"DialogID":    dialogID,
		"SignMessage": signMsg,
		"CreatedAt":   createdAt,
	})
}

func (h *Handler) tgAutoReply(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	message := ""
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
			} else if err := store.CreateAutoReplyRule(h.dbConn, username, accountID, matchText, replyText, true); err != nil {
				message = "创建失败。"
			} else {
				message = "已创建并启用。"
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
				}
			case "disable":
				if err := store.SetAutoReplyRuleEnabled(h.dbConn, username, id, false); err != nil {
					message = "停用失败。"
				} else {
					message = "已停用。"
				}
			case "delete":
				if err := store.DeleteAutoReplyRule(h.dbConn, username, id); err != nil {
					message = "删除失败。"
				} else {
					message = "已删除。"
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
				}
			case "disable":
				if err := store.SetAutoSendTaskEnabled(h.dbConn, username, id, false); err != nil {
					message = "停用失败。"
				} else {
					message = "已停用。"
				}
			case "delete":
				if err := store.DeleteAutoSendTask(h.dbConn, username, id); err != nil {
					message = "删除失败。"
				} else {
					message = "已删除。"
				}
			case "run":
				runCtx, cancel := context.WithTimeout(c.Request.Context(), 50*time.Second)
				defer cancel()
				ok, msg := tg.RunAutoSendTaskNow(runCtx, h.dbConn, username, id)
				if ok {
					message = "已立即执行。"
				} else {
					message = "立即执行失败: " + msg
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
		"Tasks":   tasks,
	})
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
	if _, err := store.GetTGAccountByID(h.dbConn, username, selectedAccountID); err != nil {
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

	next := time.Now().Format(time.RFC3339)
	if err := store.CreateAutoSendTask(h.dbConn, username, selectedAccountID, dialogID, msg, intervalSeconds, jitterSeconds, scheduleType, timeOfDay, enabled, next); err != nil {
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

	dbName := config.UnifiedD1DBName
	if settings["cf_d1_database_name"] != dbName {
		_ = store.SetSetting(h.dbConn, "cf_d1_database_name", dbName)
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

	message := ""
	if c.Request.Method == http.MethodPost {
		action := strings.TrimSpace(c.PostForm("action"))
		switch action {
		case "save":
			cfToken = strings.TrimSpace(c.PostForm("cf_api_token"))
			if cfToken == "" {
				message = "Token 不能为空。"
				break
			}
			_ = store.SetSetting(h.dbConn, "cf_api_token", cfToken)
			message = "已保存 Token。"
		case "create":
			cfToken = strings.TrimSpace(c.PostForm("cf_api_token"))
			if cfToken == "" {
				message = "Token 不能为空。"
				break
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

			okFind, _, foundID := cf.FindD1ByName(ctx, accountID, dbName)
			if okFind && foundID != "" {
				dbID = foundID
				_ = store.SetSetting(h.dbConn, "cf_d1_database_id", dbID)
				message = "已绑定云端 D1 数据库。"
				break
			}

			okCreate, msgCreate, createdID := cf.CreateD1(ctx, accountID, dbName)
			if !okCreate || createdID == "" {
				message = msgCreate
				break
			}
			dbID = createdID
			_ = store.SetSetting(h.dbConn, "cf_d1_database_id", dbID)
			message = "已创建并绑定云端 D1 数据库。"
		case "backup":
			if cfToken == "" || accountID == "" || dbID == "" {
				message = "请先保存 Token 并执行“自动创建并绑定”。"
				break
			}
			ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Minute)
			defer cancel()
			cf := d1.Client{Token: cfToken}
			ok, msg := d1.BackupLocalToD1(ctx, cf, accountID, dbID, h.dbConn)
			if ok {
				message = msg
			} else {
				message = msg
			}
		case "pull":
			if cfToken == "" || accountID == "" || dbID == "" {
				message = "请先保存 Token 并执行“自动创建并绑定”。"
				break
			}
			ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Minute)
			defer cancel()
			cf := d1.Client{Token: cfToken}
			ok, msg := d1.PullD1ToLocal(ctx, cf, accountID, dbID, h.dbConn)
			if ok {
				message = msg
			} else {
				message = msg
			}
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
		default:
			message = "未知操作。"
		}
	}

	c.HTML(http.StatusOK, "database_settings.html", gin.H{
		"Title":                "数据库管理",
		"Message":              message,
		"CFToken":              cfToken,
		"DBName":               dbName,
		"DBID":                 dbID,
		"AutoBackupEnabled":    autoEnabled,
		"AutoBackupTime":       autoTime,
		"LastAutoBackupResult": lastAuto,
	})
}

func (h *Handler) systemUpdate(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	message := ""

	ghInfo := update.GitHubReleaseInfo{OK: false, TagName: "-", Name: "-", PublishedAt: "-", AssetName: "-", Note: ""}
	ghOwner := ""
	ghRepo := ""
	ghToken := ""
	ghAsset := ""

	if settings, err := store.GetSettings(h.dbConn, []string{"github_release_owner", "github_release_repo", "github_release_token", "github_release_asset"}); err == nil {
		ghOwner = settings["github_release_owner"]
		ghRepo = settings["github_release_repo"]
		ghToken = settings["github_release_token"]
		ghAsset = settings["github_release_asset"]
	}

	goappDir := h.cfg.BaseDir

	if c.Request.Method == http.MethodPost {
		action := c.PostForm("action")
		switch action {
		case "restart":
			message = "服务将在 1 秒后自动重启，请稍后刷新页面。"
			update.RestartDelayed(1 * time.Second)
		case "gh_save":
			ghOwner = strings.TrimSpace(c.PostForm("gh_owner"))
			ghRepo = strings.TrimSpace(c.PostForm("gh_repo"))
			ghToken = strings.TrimSpace(c.PostForm("gh_token"))
			ghAsset = strings.TrimSpace(c.PostForm("gh_asset"))

			_ = store.SetSetting(h.dbConn, "github_release_owner", ghOwner)
			_ = store.SetSetting(h.dbConn, "github_release_repo", ghRepo)
			_ = store.SetSetting(h.dbConn, "github_release_token", ghToken)
			_ = store.SetSetting(h.dbConn, "github_release_asset", ghAsset)
			message = "已保存 GitHub Release 配置。"
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
			update.RestartToDelayed(bin, os.Args[1:], 1*time.Second)
		default:
			message = "未知操作。"
		}
	}

	// If user didn't click gh_check, still show a hint.
	if ghOwner == "" || ghRepo == "" {
		ghInfo.Note = "未配置 GitHub owner/repo。"
	}

	c.HTML(http.StatusOK, "update_manager.html", gin.H{
		"Title":          "程序更新",
		"Message":        message,
		"CurrentVersion": version.Version,
		"GH":             ghInfo,
		"GHOwner":        ghOwner,
		"GHRepo":         ghRepo,
		"GHToken":        ghToken,
		"GHAsset":        ghAsset,
		"User":           username,
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

	ghOwner := ""
	ghRepo := ""
	ghToken := ""
	ghAsset := ""
	if settings, err := store.GetSettings(h.dbConn, []string{"github_release_owner", "github_release_repo", "github_release_token", "github_release_asset"}); err == nil {
		ghOwner = settings["github_release_owner"]
		ghRepo = settings["github_release_repo"]
		ghToken = settings["github_release_token"]
		ghAsset = settings["github_release_asset"]
	}
	if v, ok := c.GetPostForm("gh_owner"); ok {
		ghOwner = strings.TrimSpace(v)
	}
	if v, ok := c.GetPostForm("gh_repo"); ok {
		ghRepo = strings.TrimSpace(v)
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

	if !send(92, "下载完成，正在替换可执行文件...", false, false) {
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
	_ = username

	message := ""
	if c.Request.Method == http.MethodPost {
		action := strings.TrimSpace(c.PostForm("action"))
		switch action {
		case "install_fail2ban":
			ctx, cancel := context.WithTimeout(c.Request.Context(), 3*time.Minute)
			defer cancel()
			ok, msg := ssh.InstallFail2ban(ctx)
			if ok {
				message = msg
			} else {
				message = "安装失败: " + msg
			}
		case "diagnose_ssh":
			portText := strings.TrimSpace(c.PostForm("ssh_port"))
			p, _ := strconv.Atoi(portText)
			message = ssh.Diagnose(p)
		default:
			portText := strings.TrimSpace(c.PostForm("ssh_port"))
			pub := strings.TrimSpace(c.PostForm("ssh_public_key"))
			allowPass := c.PostForm("allow_password_login") == "on"
			allowKey := c.PostForm("allow_key_login") == "on"
			p, err := strconv.Atoi(portText)
			if err != nil || p < 1 || p > 65535 {
				message = "SSH 端口范围必须在 1-65535。"
				break
			}

			_ = store.SetSetting(h.dbConn, "ssh_port", strconv.Itoa(p))
			_ = store.SetSetting(h.dbConn, "ssh_allow_password_login", bool01(allowPass))
			_ = store.SetSetting(h.dbConn, "ssh_allow_key_login", bool01(allowKey))
			_ = store.SetSetting(h.dbConn, "ssh_public_key", pub)

			ctx, cancel := context.WithTimeout(c.Request.Context(), 45*time.Second)
			defer cancel()
			ok, msg := ssh.ApplySettings(ctx, p, allowPass, allowKey, pub)
			if ok {
				message = "SSH 设置已保存，并已自动应用到系统。"
			} else {
				message = "SSH 设置已保存，但系统应用失败：" + msg
			}
		}
	}

	settings, err := store.GetSettings(h.dbConn, []string{"ssh_port", "ssh_allow_password_login", "ssh_allow_key_login", "ssh_public_key"})
	if err != nil {
		c.String(http.StatusInternalServerError, "load settings failed")
		return
	}

	sshPort := settings["ssh_port"]
	if sshPort == "" {
		sshPort = "22"
	}
	allowPass := settings["ssh_allow_password_login"]
	if allowPass == "" {
		allowPass = "1"
	}
	allowKey := settings["ssh_allow_key_login"]
	if allowKey == "" {
		allowKey = "1"
	}

	c.HTML(http.StatusOK, "ssh_settings.html", gin.H{
		"Title":              "SSH 设置",
		"Message":            message,
		"SSHPort":            sshPort,
		"SSHPublicKey":       settings["ssh_public_key"],
		"AllowPasswordLogin": allowPass == "1",
		"AllowKeyLogin":      allowKey == "1",
	})
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
	fwType := firewall.DetectType()

	if c.Request.Method == http.MethodPost {
		action := strings.TrimSpace(c.PostForm("action"))
		switch action {
		case "enable_firewall":
			ok, msg := firewall.Enable(fwType)
			if ok {
				message = msg
			} else {
				message = "操作失败: " + msg
			}
		case "open_port":
			portText := strings.TrimSpace(c.PostForm("port"))
			proto := strings.TrimSpace(c.PostForm("protocol"))
			port, err := strconv.Atoi(portText)
			if err != nil {
				message = "端口必须是数字。"
				break
			}
			ok, msg := firewall.OpenPort(fwType, port, proto)
			if ok {
				message = msg
			} else {
				message = "操作失败: " + msg
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
			"bind_ips":      bindIPs,
			"process_names": procNames,
		})
	}

	c.HTML(http.StatusOK, "firewall.html", gin.H{
		"Title":          "防火墙",
		"Message":        message,
		"FirewallType":   fwType,
		"FirewallStatus": fwStatus,
		"Note":           note,
		"PortRows":       portRows,
		"ListeningRows":  listeningRows,
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
