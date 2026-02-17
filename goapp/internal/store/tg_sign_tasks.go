package store

import (
	"database/sql"
	"fmt"
	"time"
)

type SignTask struct {
	Owner     string
	AccountID int64
	DialogID  string
	Message   string
	CreatedAt string
}

func ListAllSignTasks(dbConn *sql.DB) ([]SignTask, error) {
	rows, err := dbConn.Query(
		"SELECT owner, account_id, dialog_id, COALESCE(message,''), created_at FROM tg_sign_tasks ORDER BY owner, account_id",
	)
	if err != nil {
		return nil, fmt.Errorf("list all sign tasks: %w", err)
	}
	defer rows.Close()

	var out []SignTask
	for rows.Next() {
		var t SignTask
		if err := rows.Scan(&t.Owner, &t.AccountID, &t.DialogID, &t.Message, &t.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan sign task: %w", err)
		}
		out = append(out, t)
	}
	return out, nil
}

func GetSignTask(dbConn *sql.DB, owner string, accountID int64) (SignTask, bool, error) {
	var t SignTask
	err := dbConn.QueryRow(
		"SELECT owner, account_id, dialog_id, COALESCE(message,''), created_at FROM tg_sign_tasks WHERE owner = ? AND account_id = ?",
		owner,
		accountID,
	).Scan(&t.Owner, &t.AccountID, &t.DialogID, &t.Message, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return SignTask{}, false, nil
	}
	if err != nil {
		return SignTask{}, false, fmt.Errorf("get sign task: %w", err)
	}
	return t, true, nil
}

func UpsertSignTask(dbConn *sql.DB, owner string, accountID int64, dialogID, message string) error {
	stamp := time.Now().Format(time.RFC3339)
	_, err := dbConn.Exec(
		`INSERT INTO tg_sign_tasks (owner, account_id, dialog_id, message, created_at)
          VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(owner, account_id)
          DO UPDATE SET dialog_id = excluded.dialog_id, message = excluded.message, created_at = excluded.created_at`,
		owner,
		accountID,
		dialogID,
		message,
		stamp,
	)
	if err != nil {
		return fmt.Errorf("upsert sign task: %w", err)
	}
	return nil
}

func DeleteSignTask(dbConn *sql.DB, owner string, accountID int64) error {
	if _, err := dbConn.Exec("DELETE FROM tg_sign_tasks WHERE owner = ? AND account_id = ?", owner, accountID); err != nil {
		return fmt.Errorf("delete sign task: %w", err)
	}
	return nil
}
