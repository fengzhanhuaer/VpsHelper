package store

import (
	"database/sql"
	"fmt"
	"time"
)

type TGDialog struct {
	ID        int64
	AccountID int64
	DialogID  string
	Title     string
	Username  string
	UpdatedAt string
}

func ListTGDialogs(dbConn *sql.DB, accountID int64) ([]TGDialog, error) {
	rows, err := dbConn.Query(
		"SELECT id, account_id, dialog_id, COALESCE(title,''), COALESCE(username,''), updated_at FROM tg_dialogs WHERE account_id = ? ORDER BY title ASC",
		accountID,
	)
	if err != nil {
		return nil, fmt.Errorf("list tg dialogs: %w", err)
	}
	defer rows.Close()

	var out []TGDialog
	for rows.Next() {
		var d TGDialog
		if err := rows.Scan(&d.ID, &d.AccountID, &d.DialogID, &d.Title, &d.Username, &d.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan tg dialog: %w", err)
		}
		out = append(out, d)
	}
	return out, nil
}

func ReplaceTGDialogs(dbConn *sql.DB, accountID int64, dialogs []TGDialog) error {
	tx, err := dbConn.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec("DELETE FROM tg_dialogs WHERE account_id = ?", accountID); err != nil {
		return fmt.Errorf("clear dialogs: %w", err)
	}

	stmt, err := tx.Prepare("INSERT INTO tg_dialogs (account_id, dialog_id, title, username, updated_at) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	for _, d := range dialogs {
		updated := d.UpdatedAt
		if updated == "" {
			updated = time.Now().Format(time.RFC3339)
		}
		if _, err := stmt.Exec(accountID, d.DialogID, d.Title, d.Username, updated); err != nil {
			return fmt.Errorf("insert dialog: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}
