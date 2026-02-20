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

func ResolveDialogIDForAccount(ctx context.Context, dbConn *sql.DB, owner string, accountID int64, target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", errors.New("empty target")
	}

	if dialogID, ok := NormalizeDialogID(target); ok {
		return dialogID, nil
	}

	if dialogID, ok, err := resolveDialogIDFromStoredDialogs(dbConn, accountID, target); err != nil {
		return "", err
	} else if ok {
		return dialogID, nil
	}

	settings, err := store.GetSettings(dbConn, []string{"telegram_api_id", "telegram_api_hash", "tg_all_proxy"})
	if err != nil {
		return "", err
	}
	apiIDText := strings.TrimSpace(settings["telegram_api_id"])
	apiHash := strings.TrimSpace(settings["telegram_api_hash"])
	allProxy := strings.TrimSpace(settings["tg_all_proxy"])
	if apiIDText == "" || apiHash == "" {
		return "", errors.New("telegram api settings missing")
	}

	apiID, err := parseInt(apiIDText)
	if err != nil {
		return "", err
	}

	storage := NewAccountSessionStorage(dbConn, owner, accountID)
	opts, err := newTelegramOptions(storage, true, allProxy)
	if err != nil {
		return "", err
	}
	client := telegram.NewClient(apiID, apiHash, opts)

	callCtx := ctx
	if callCtx == nil {
		callCtx = context.Background()
	}
	if _, hasDeadline := callCtx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(callCtx, 35*time.Second)
		defer cancel()
	}

	var dialogID string
	err = client.Run(callCtx, func(ctx context.Context) error {
		out, err := ResolveDialogID(ctx, client, target)
		if err != nil {
			return err
		}
		dialogID = out
		return nil
	})
	if err != nil {
		return "", err
	}
	if dialogID == "" {
		return "", errors.New("resolve target empty")
	}
	return dialogID, nil
}

func NormalizeStoredTargetsByDialogs(dbConn *sql.DB, owner string, accountID int64) (int, error) {
	dialogs, err := store.ListTGDialogs(dbConn, accountID)
	if err != nil {
		return 0, err
	}

	usernameToID := map[string]string{}
	for _, d := range dialogs {
		dialogID, ok := NormalizeDialogID(d.DialogID)
		if !ok {
			continue
		}
		username := strings.ToLower(strings.TrimSpace(d.Username))
		if username != "" {
			usernameToID[username] = dialogID
		}
	}

	migrated := 0
	if len(usernameToID) == 0 {
		return migrated, nil
	}

	if signTask, ok, err := store.GetSignTask(dbConn, owner, accountID); err != nil {
		return migrated, err
	} else if ok && !IsDialogID(signTask.DialogID) {
		key := strings.ToLower(NormalizeUsername(signTask.DialogID))
		if dialogID, ok := usernameToID[key]; ok && dialogID != strings.TrimSpace(signTask.DialogID) {
			if err := store.UpsertSignTask(dbConn, owner, accountID, dialogID, signTask.Message); err != nil {
				return migrated, err
			}
			migrated++
		}
	}

	autoTasks, err := store.ListAutoSendTasks(dbConn, owner)
	if err != nil {
		return migrated, err
	}
	for _, t := range autoTasks {
		if t.AccountID != accountID || IsDialogID(t.DialogID) {
			continue
		}
		key := strings.ToLower(NormalizeUsername(t.DialogID))
		dialogID, ok := usernameToID[key]
		if !ok || dialogID == strings.TrimSpace(t.DialogID) {
			continue
		}
		if err := store.UpdateAutoSendTaskDialogID(dbConn, owner, t.ID, dialogID); err != nil {
			return migrated, err
		}
		migrated++
	}

	return migrated, nil
}

func resolveDialogIDFromStoredDialogs(dbConn *sql.DB, accountID int64, target string) (string, bool, error) {
	username := strings.ToLower(NormalizeUsername(target))
	if !isProbableUsername(username) {
		return "", false, nil
	}

	dialogs, err := store.ListTGDialogs(dbConn, accountID)
	if err != nil {
		return "", false, err
	}
	for _, d := range dialogs {
		if !strings.EqualFold(strings.TrimSpace(d.Username), username) {
			continue
		}
		if dialogID, ok := NormalizeDialogID(d.DialogID); ok {
			return dialogID, true, nil
		}
	}
	return "", false, nil
}
