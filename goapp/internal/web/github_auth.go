package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"

	"vpshelper-go/internal/store"
)

func (h *Handler) getGithubOauthConfig() (*oauth2.Config, string, error) {
	settings, err := store.GetSettings(h.dbConn, []string{"github_client_id", "github_client_secret", "github_allowed_user"})
	if err != nil {
		return nil, "", err
	}
	clientID := strings.TrimSpace(settings["github_client_id"])
	clientSecret := strings.TrimSpace(settings["github_client_secret"])
	allowedUser := strings.TrimSpace(settings["github_allowed_user"])

	if clientID == "" || clientSecret == "" || allowedUser == "" {
		return nil, "", fmt.Errorf("github auth not fully configured")
	}

	conf := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     github.Endpoint,
	}
	return conf, allowedUser, nil
}

func (h *Handler) githubSettings(c *gin.Context) {
	username := h.currentUser(c)
	if username == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	if c.Request.Method == http.MethodGet {
		settings, _ := store.GetSettings(h.dbConn, []string{"github_client_id", "github_client_secret", "github_allowed_user", "github_session_days", "github_auth_enabled", "github_whitelist"})
		
		sessionDays := settings["github_session_days"]
		if sessionDays == "" {
			sessionDays = "0"
		}

		c.HTML(http.StatusOK, "github_settings.html", gin.H{
			"Title":        "GitHub 安全登录",
			"ClientID":     settings["github_client_id"],
			"ClientSecret": settings["github_client_secret"],
			"AllowedUser":  settings["github_allowed_user"],
			"Whitelist":    settings["github_whitelist"],
			"SessionDays":  sessionDays,
			"AuthEnabled":  settings["github_auth_enabled"] == "true",
			"TestSuccess":  c.Query("test") == "success",
			"TestError":    c.Query("test") == "error",
			"ErrorMsg":     c.Query("msg"),
		})
		return
	}

	clientID := strings.TrimSpace(c.PostForm("client_id"))
	clientSecret := strings.TrimSpace(c.PostForm("client_secret"))
	allowedUser := strings.TrimSpace(c.PostForm("allowed_user"))
	whitelist := strings.TrimSpace(c.PostForm("whitelist"))
	sessionDays := strings.TrimSpace(c.PostForm("session_days"))
	authEnabled := c.PostForm("auth_enabled") == "on" || c.PostForm("auth_enabled") == "true"

	_ = store.SetSetting(h.dbConn, "github_client_id", clientID)
	_ = store.SetSetting(h.dbConn, "github_client_secret", clientSecret)
	_ = store.SetSetting(h.dbConn, "github_allowed_user", allowedUser)
	_ = store.SetSetting(h.dbConn, "github_whitelist", whitelist)
	_ = store.SetSetting(h.dbConn, "github_session_days", sessionDays)
	_ = store.SetSetting(h.dbConn, "github_auth_enabled", fmt.Sprintf("%v", authEnabled))

	if c.PostForm("action") == "test" {
		c.Redirect(http.StatusFound, "/auth/github/login?type=test")
		return
	}

	msg := "配置已更新！"
	if authEnabled {
		if clientID == "" || clientSecret == "" || allowedUser == "" {
			msg = "注意：配置部分留空，GitHub 鉴权防护将无法生效。"
		} else {
			msg += " 现在访问主页将受到 GitHub 授权防护。"
		}
	} else {
		msg += " GitHub 鉴权防护处于禁用状态。"
	}

	c.HTML(http.StatusOK, "github_settings.html", gin.H{
		"Title":        "GitHub 安全登录",
		"ClientID":     clientID,
		"ClientSecret": clientSecret,
		"AllowedUser":  allowedUser,
		"Whitelist":    whitelist,
		"SessionDays":  sessionDays,
		"AuthEnabled":  authEnabled,
		"Message":      msg,
		"MsgOK":        true,
	})
}

func (h *Handler) githubLogin(c *gin.Context) {
	conf, _, err := h.getGithubOauthConfig()
	if err != nil {
		c.String(http.StatusForbidden, "GitHub Authentication is disabled or misconfigured.")
		return
	}

	state, err := generateProbeSecret()
	if err != nil {
		c.String(http.StatusInternalServerError, "error generating state")
		return
	}

	sess := sessions.Default(c)
	sess.Set("oauth_state", state)
	if c.Query("type") == "test" {
		sess.Set("github_login_type", "test")
	} else {
		sess.Set("github_login_type", "login")
	}
	_ = sess.Save()

	url := conf.AuthCodeURL(state)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (h *Handler) githubCallback(c *gin.Context) {
	sess := sessions.Default(c)
	savedState := sess.Get("oauth_state")
	if savedState == nil {
		c.String(http.StatusBadRequest, "invalid oauth state from session")
		return
	}

	queryState := c.Query("state")
	if queryState != savedState.(string) {
		c.String(http.StatusBadRequest, "oauth state mismatch")
		return
	}

	sess.Delete("oauth_state")
	_ = sess.Save()

	code := c.Query("code")
	conf, allowedUser, err := h.getGithubOauthConfig()
	if err != nil {
		c.String(http.StatusInternalServerError, "GitHub config error")
		return
	}

	tok, err := conf.Exchange(context.Background(), code)
	if err != nil {
		c.String(http.StatusBadRequest, "Exchange token failed: "+err.Error())
		return
	}

	client := conf.Client(context.Background(), tok)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to get user info: "+err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.String(http.StatusInternalServerError, "GitHub API returned error")
		return
	}

	var user struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		c.String(http.StatusInternalServerError, "Failed to decode user info")
		return
	}

	loginType := sess.Get("github_login_type")
	if !strings.EqualFold(user.Login, allowedUser) {
		if loginType == "test" {
			c.Redirect(http.StatusFound, "/settings/github?test=error&msg=用户名不匹配")
			return
		}
		c.String(http.StatusForbidden, fmt.Sprintf("Access Denied: You are logged in as %s, but only %s is allowed.", user.Login, allowedUser))
		return
	}

	if loginType == "test" {
		sess.Set("github_test_passed", true)
		sess.Delete("github_login_type")
		_ = sess.Save()
		c.Redirect(http.StatusFound, "/settings/github?test=success")
		return
	}

	// OK, mark session as GH authorized
	settings, _ := store.GetSettings(h.dbConn, []string{"github_session_days"})
	days, _ := strconv.Atoi(settings["github_session_days"])
	if days > 0 {
		sess.Options(sessions.Options{
			Path:     "/",
			HttpOnly: true,
			MaxAge:   days * 86400, // days to seconds
		})
	}

	sess.Set("github_authorized", true)
	_ = sess.Save()

	c.Redirect(http.StatusFound, "/login")
}
