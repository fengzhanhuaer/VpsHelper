package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// TGDialog represents one Telegram conversation entry.
type TGDialog struct {
	ID        int64  `json:"id,omitempty"` // legacy field, unused in file storage
	AccountID int64  `json:"account_id"`
	DialogID  string `json:"dialog_id"`
	Title     string `json:"title"`
	Username  string `json:"username"`
	UpdatedAt string `json:"updated_at"`
}

// dialogsDir returns the directory where dialog JSON files are stored.
// Respects VPSHELPER_DATA_DIR, otherwise defaults to ../userdata relative
// to the process working directory (identical logic to config.Load).
func dialogsDir() string {
	base := os.Getenv("VPSHELPER_DATA_DIR")
	if base == "" {
		wd, _ := os.Getwd()
		base = filepath.Join(wd, "..", "userdata")
	}
	return filepath.Join(base, "dialogs")
}

// dialogFilePath returns the JSON file path for a given account.
func dialogFilePath(accountID int64) string {
	return filepath.Join(dialogsDir(), fmt.Sprintf("%d.json", accountID))
}

// dialogFileMu serialises concurrent writes to the same file.
var dialogFileMu sync.Mutex

// ListTGDialogs reads all dialogs for accountID from its JSON file.
// The dbConn parameter is retained for signature compatibility but is not used.
func ListTGDialogs(_ *sql.DB, accountID int64) ([]TGDialog, error) {
	path := dialogFilePath(accountID)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil // empty list – normal for a fresh account
	}
	if err != nil {
		return nil, fmt.Errorf("read dialogs file: %w", err)
	}
	var dialogs []TGDialog
	if err := json.Unmarshal(data, &dialogs); err != nil {
		return nil, fmt.Errorf("parse dialogs file: %w", err)
	}
	return dialogs, nil
}

// ReplaceTGDialogs atomically replaces all dialogs for accountID with dialogs.
// The dbConn parameter is retained for signature compatibility but is not used.
func ReplaceTGDialogs(_ *sql.DB, accountID int64, dialogs []TGDialog) error {
	dir := dialogsDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create dialogs dir: %w", err)
	}

	data, err := json.MarshalIndent(dialogs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal dialogs: %w", err)
	}

	// Write atomically: temp file → rename.
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

// DeleteTGDialogsFile removes the JSON file for accountID.
// Called when a TG account is deleted.
func DeleteTGDialogsFile(accountID int64) {
	_ = os.Remove(dialogFilePath(accountID))
}
