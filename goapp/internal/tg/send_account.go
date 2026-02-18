package tg

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/gotd/td/telegram"

	"vpshelper-go/internal/store"
)

func SendOnce(ctx context.Context, dbConn *sql.DB, owner string, accountID int64, dialogID, message string) (bool, string) {
	ok, msg, _ := SendOnceWithResolvedDialogID(ctx, dbConn, owner, accountID, dialogID, message)
	return ok, msg
}

func SendOnceWithResolvedDialogID(ctx context.Context, dbConn *sql.DB, owner string, accountID int64, dialogID, message string) (bool, string, string) {
	dialogID = strings.TrimSpace(dialogID)
	message = strings.TrimSpace(message)
	if dialogID == "" {
		return false, "目标不能为空", ""
	}
	if message == "" {
		message = "签到"
	}

	settings, err := store.GetSettings(dbConn, []string{"telegram_api_id", "telegram_api_hash", "tg_all_proxy"})
	if err != nil {
		return false, "读取 TG API 配置失败", ""
	}
	apiIDText := strings.TrimSpace(settings["telegram_api_id"])
	apiHash := strings.TrimSpace(settings["telegram_api_hash"])
	allProxy := strings.TrimSpace(settings["tg_all_proxy"])
	if apiIDText == "" || apiHash == "" {
		return false, "请先配置 Telegram API ID/Hash", ""
	}

	apiID, err := parseInt(apiIDText)
	if err != nil {
		return false, "API ID 格式不正确", ""
	}

	storage := NewAccountSessionStorage(dbConn, owner, accountID)
	opts, err := newTelegramOptions(storage, true, allProxy)
	if err != nil {
		return false, "初始化 Telegram 客户端失败", ""
	}

	client := telegram.NewClient(apiID, apiHash, opts)
	callCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()

	resolvedDialogID := dialogID
	err = client.Run(callCtx, func(ctx context.Context) error {
		usedDialogID, err := SendMessageToTarget(ctx, client, dialogID, message)
		if err != nil {
			return err
		}
		resolvedDialogID = strings.TrimSpace(usedDialogID)
		return nil
	})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return false, "发送超时", ""
		}
		return false, err.Error(), ""
	}

	if normalized, ok := NormalizeDialogID(resolvedDialogID); ok {
		resolvedDialogID = normalized
	}
	return true, "已发送", resolvedDialogID
}
