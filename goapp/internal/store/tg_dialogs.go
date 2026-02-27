package store

import (
	"database/sql"
	"fmt"
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

// ListTGDialogs returns all dialogs for accountID sorted by LastMsgAt DESC
// (most recently active first). The dbConn parameter is kept for interface
// compatibility but is unused; localDB is used instead.
func ListTGDialogs(_ *sql.DB, accountID int64) ([]TGDialog, error) {
	rows, err := localDB.Query(
		`SELECT account_id, dialog_id, title, username, updated_at, last_msg_at
		   FROM tg_dialogs
		  WHERE account_id = ?
		  ORDER BY last_msg_at DESC, updated_at DESC`,
		accountID,
	)
	if err != nil {
		return nil, fmt.Errorf("list tg dialogs: %w", err)
	}
	defer rows.Close()

	var out []TGDialog
	for rows.Next() {
		var d TGDialog
		if err := rows.Scan(&d.AccountID, &d.DialogID, &d.Title, &d.Username, &d.UpdatedAt, &d.LastMsgAt); err != nil {
			return nil, fmt.Errorf("scan tg dialog: %w", err)
		}
		out = append(out, d)
	}
	return out, nil
}

// ReplaceTGDialogs atomically replaces all dialogs for accountID.
// The dbConn parameter is kept for interface compatibility but is unused.
func ReplaceTGDialogs(_ *sql.DB, accountID int64, dialogs []TGDialog) error {
	tx, err := localDB.Begin()
	if err != nil {
		return fmt.Errorf("begin replace dialogs tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec("DELETE FROM tg_dialogs WHERE account_id = ?", accountID); err != nil {
		return fmt.Errorf("delete dialogs: %w", err)
	}

	for _, d := range dialogs {
		updatedAt := d.UpdatedAt
		if updatedAt == "" {
			updatedAt = time.Now().UTC().Format(time.RFC3339)
		}
		title := d.Title
		if title == "" {
			title = d.DialogID
		}
		if _, err := tx.Exec(
			`INSERT OR REPLACE INTO tg_dialogs (account_id, dialog_id, title, username, updated_at, last_msg_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			d.AccountID, d.DialogID, title, d.Username, updatedAt, d.LastMsgAt,
		); err != nil {
			return fmt.Errorf("insert dialog: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit replace dialogs: %w", err)
	}
	return nil
}

// UpdateDialogLastMsgAt updates (or creates) the dialog entry's LastMsgAt timestamp.
// title is the human-readable peer name; pass "" to keep the existing title unchanged.
// Called by the auto-reply listener whenever a message arrives.
func UpdateDialogLastMsgAt(accountID int64, dialogID, title string, msgAt int64) error {
	updatedAt := time.Unix(msgAt, 0).UTC().Format(time.RFC3339)
	displayTitle := title
	if displayTitle == "" {
		displayTitle = dialogID
	}

	// Upsert: insert or update only if the new msgAt is newer.
	_, err := localDB.Exec(
		`INSERT INTO tg_dialogs (account_id, dialog_id, title, username, updated_at, last_msg_at)
		 VALUES (?, ?, ?, '', ?, ?)
		 ON CONFLICT(account_id, dialog_id) DO UPDATE SET
		   last_msg_at = CASE WHEN excluded.last_msg_at > last_msg_at THEN excluded.last_msg_at ELSE last_msg_at END,
		   updated_at  = CASE WHEN excluded.last_msg_at > last_msg_at THEN excluded.updated_at  ELSE updated_at  END,
		   title       = CASE WHEN excluded.title != '' AND excluded.title != dialog_id THEN excluded.title ELSE title END`,
		accountID, dialogID, displayTitle, updatedAt, msgAt,
	)
	if err != nil {
		return fmt.Errorf("upsert dialog last_msg_at: %w", err)
	}
	return nil
}

// DeleteTGDialogsFile removes all dialog entries for accountID from localDB.
// The name is kept for backward compatibility with callers.
func DeleteTGDialogsFile(accountID int64) {
	_, _ = localDB.Exec("DELETE FROM tg_dialogs WHERE account_id = ?", accountID)
}
