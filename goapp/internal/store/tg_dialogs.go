package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// TGDialog represents one Telegram conversation entry.
type TGDialog struct {
	ID        int64  `json:"id,omitempty"` // legacy field
	AccountID int64  `json:"account_id"`
	DialogID  string `json:"dialog_id"`
	Title     string `json:"title"`
	Username  string `json:"username"`
	UpdatedAt string `json:"updated_at"`
	LastMsgAt int64  `json:"last_msg_at,omitempty"` // unix; set by listener
}

// dialogsDir returns the directory where dialog JSON files are stored.
func dialogsDir() string {
	base := os.Getenv("VPSHELPER_DATA_DIR")
	if base == "" {
		wd, _ := os.Getwd()
		base = filepath.Join(wd, "..", "userdata")
	}
	return filepath.Join(base, "dialogs")
}

func dialogFilePath(accountID int64) string {
	return filepath.Join(dialogsDir(), fmt.Sprintf("%d.json", accountID))
}

var dialogFileMu sync.Mutex

// ListTGDialogs reads all dialogs for accountID, sorted by LastMsgAt DESC
// (most recently active first). If LastMsgAt is 0, falls back to UpdatedAt.
func ListTGDialogs(_ *sql.DB, accountID int64) ([]TGDialog, error) {
	path := dialogFilePath(accountID)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read dialogs file: %w", err)
	}
	var dialogs []TGDialog
	if err := json.Unmarshal(data, &dialogs); err != nil {
		return nil, fmt.Errorf("parse dialogs file: %w", err)
	}
	// Sort by LastMsgAt DESC (most recent first).
	sort.Slice(dialogs, func(i, j int) bool {
		ai, aj := dialogs[i].LastMsgAt, dialogs[j].LastMsgAt
		if ai != aj {
			return ai > aj
		}
		// Fallback: lexicographic UpdatedAt (RFC3339 → comparable).
		return dialogs[i].UpdatedAt > dialogs[j].UpdatedAt
	})
	return dialogs, nil
}

// ReplaceTGDialogs atomically replaces all dialogs for accountID.
func ReplaceTGDialogs(_ *sql.DB, accountID int64, dialogs []TGDialog) error {
	dir := dialogsDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create dialogs dir: %w", err)
	}

	data, err := json.MarshalIndent(dialogs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal dialogs: %w", err)
	}

	target := dialogFilePath(accountID)
	tmp := target + ".tmp"

	dialogFileMu.Lock()
	defer dialogFileMu.Unlock()

	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write dialogs tmp: %w", err)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename dialogs file: %w", err)
	}
	return nil
}

// UpdateDialogLastMsgAt updates (or creates) the dialog entry's LastMsgAt timestamp.
// Called by the auto-reply listener whenever a message arrives.
func UpdateDialogLastMsgAt(accountID int64, dialogID string, msgAt int64) error {
	dialogFileMu.Lock()
	defer dialogFileMu.Unlock()

	path := dialogFilePath(accountID)
	var dialogs []TGDialog
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &dialogs)
	}

	found := false
	for i := range dialogs {
		if dialogs[i].DialogID == dialogID {
			if msgAt > dialogs[i].LastMsgAt {
				dialogs[i].LastMsgAt = msgAt
				dialogs[i].UpdatedAt = time.Unix(msgAt, 0).UTC().Format(time.RFC3339)
			}
			found = true
			break
		}
	}
	if !found {
		// New dialog seen by listener that's not in the list yet.
		dialogs = append(dialogs, TGDialog{
			AccountID: accountID,
			DialogID:  dialogID,
			Title:     dialogID, // title unknown; will be filled on next refresh
			UpdatedAt: time.Unix(msgAt, 0).UTC().Format(time.RFC3339),
			LastMsgAt: msgAt,
		})
	}

	data, err := json.MarshalIndent(dialogs, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// DeleteTGDialogsFile removes the JSON file for accountID.
func DeleteTGDialogsFile(accountID int64) {
	_ = os.Remove(dialogFilePath(accountID))
}
