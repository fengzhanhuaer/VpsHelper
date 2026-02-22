package tg

import (
	"context"
	"database/sql"
	"strconv"
	"strings"

	"github.com/gotd/td/telegram"
	gotdtg "github.com/gotd/td/tg"

	"vpshelper-go/internal/store"
)

// FetchAndStoreDialogHistory pulls up to limit recent messages for dialogID
// from Telegram via a short-lived connection, stores them locally, and returns them.
// Used on-demand when the chat history page finds no local records.
func FetchAndStoreDialogHistory(ctx context.Context, dbConn *sql.DB, owner string, accountID int64, dialogID string, limit int) ([]store.ChatMessage, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}

	acct, err := store.GetTGAccountByID(dbConn, owner, accountID)
	if err != nil {
		return nil, err
	}

	settings, _ := store.GetSettings(dbConn, []string{"telegram_api_id", "telegram_api_hash", "tg_all_proxy"})
	apiIDText := strings.TrimSpace(settings["telegram_api_id"])
	apiHash := strings.TrimSpace(settings["telegram_api_hash"])
	allProxy := strings.TrimSpace(settings["tg_all_proxy"])
	apiID, err := parseInt(apiIDText)
	if err != nil || apiID == 0 || apiHash == "" {
		return nil, err
	}

	var storage telegram.SessionStorage
	if acct.SessionText != "" {
		data, err := decodeSessionText(acct.SessionText)
		if err != nil {
			return nil, err
		}
		storage = &inMemorySessionStorage{data: data}
	} else {
		storage = NewAccountSessionStorage(dbConn, owner, accountID)
	}

	opts, err := buildOptions(storage, allProxy)
	if err != nil {
		return nil, err
	}
	client := telegram.NewClient(apiID, apiHash, opts)

	var msgs []store.ChatMessage
	runErr := client.Run(ctx, func(ctx context.Context) error {
		api := client.API()
		resolved, err := resolveTarget(ctx, api, dialogID)
		if err != nil {
			return err
		}
		res, err := messagesGetHistoryWithRetry(ctx, api, &gotdtg.MessagesGetHistoryRequest{
			Peer:  resolved.peer,
			Limit: limit,
		})
		if err != nil {
			return err
		}
		raw := historyMessagesFromResponse(res)
		// Telegram returns newest-first; store oldest-first.
		for i := len(raw) - 1; i >= 0; i-- {
			m, ok := raw[i].(*gotdtg.Message)
			if !ok || strings.TrimSpace(m.Message) == "" {
				continue
			}
			from := "me"
			if !m.Out {
				if fid, ok := m.FromID.(*gotdtg.PeerUser); ok {
					from = strconv.FormatInt(fid.UserID, 10)
				}
			}
			cm := store.ChatMessage{
				MsgID: m.ID,
				From:  from,
				Text:  m.Message,
				Date:  int64(m.Date),
				Out:   m.Out,
			}
			msgs = append(msgs, cm)
			_ = store.AppendChatMessage(accountID, dialogID, cm)
		}
		return nil
	})
	return msgs, runErr
}
