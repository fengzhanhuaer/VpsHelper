package tgbot

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"vpshelper-go/internal/store"
)

// SendMessage sends a plain text message to the specified chat via Bot API.
func SendMessage(dbConn *sql.DB, chatID int64, text string) error {
	settings, err := store.GetSettings(dbConn, []string{"tg_bot_token"})
	if err != nil {
		return err
	}
	token := strings.TrimSpace(settings["tg_bot_token"])
	if token == "" {
		return fmt.Errorf("bot token not configured")
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "HTML",
	}
	body, _ := json.Marshal(payload)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("bot api error: status=%d body=%s", resp.StatusCode, respBody)
	}

	return nil
}

// SetWebhook configures the Webhook URL for the bot.
func SetWebhook(token, webhookURL, secretToken string) error {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/setWebhook", token)
	payload := map[string]interface{}{
		"url":          webhookURL,
		"secret_token": secretToken,
	}
	body, _ := json.Marshal(payload)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("set webhook error: status=%d body=%s", resp.StatusCode, respBody)
	}

	return nil
}

// GetWebhookInfo proxy gets the webhook info from Telegram.
func GetWebhookInfo(token string) (map[string]interface{}, error) {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/getWebhookInfo", token)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bot api error: status=%d body=%s", resp.StatusCode, body)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	return data, nil
}
