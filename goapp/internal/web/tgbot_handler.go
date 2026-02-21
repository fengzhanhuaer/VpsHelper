package web

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"vpshelper-go/internal/store"
	"vpshelper-go/internal/tgbot"
)

// tgBotWebhook processes incoming Telegram Bot Webhook requests.
func (h *Handler) tgBotWebhook(c *gin.Context) {
	settings, err := store.GetSettings(h.dbConn, []string{"tg_bot_token", "tg_bot_admin_id", "tg_bot_webhook_secret"})
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	secret := settings["tg_bot_webhook_secret"]
	adminIDStr := settings["tg_bot_admin_id"]

	if secret == "" || adminIDStr == "" {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	// Double protection: Path secret AND X-Telegram-Bot-Api-Secret-Token
	pathSecret := c.Param("secret")
	if pathSecret != secret {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	headerSecret := c.GetHeader("X-Telegram-Bot-Api-Secret-Token")
	if headerSecret != secret {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	adminID, err := strconv.ParseInt(adminIDStr, 10, 64)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	var update struct {
		Message struct {
			Text string `json:"text"`
			From struct {
				ID int64 `json:"id"`
			} `json:"from"`
			Chat struct {
				ID int64 `json:"id"`
			} `json:"chat"`
		} `json:"message"`
	}

	if err := json.Unmarshal(body, &update); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	msgText := strings.TrimSpace(update.Message.Text)
	senderID := update.Message.From.ID
	chatID := update.Message.Chat.ID

	// Whitelist check
	if senderID != adminID {
		c.AbortWithStatus(http.StatusOK) // Silent drop
		return
	}

	if msgText == "" {
		c.AbortWithStatus(http.StatusOK)
		return
	}

	// Simple command dispatcher
	go h.handleBotCommand(chatID, msgText)

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) handleBotCommand(chatID int64, text string) {
	parts := strings.Fields(text)
	cmd := strings.ToLower(parts[0])

	var reply string

	switch cmd {
	case "/ping":
		reply = "pong! VpsHelper is alive 🚀"
	case "/status":
		reply = "Server Status:\nNot implemented fully yet, but probe is active."
	default:
		reply = "Unknown command. Try /ping or /status"
	}

	_ = tgbot.SendMessage(h.dbConn, chatID, reply)
}
