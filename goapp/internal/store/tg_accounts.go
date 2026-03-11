package store

import (
	"database/sql"
	"fmt"
	"time"
)

type TGAccount struct {
	ID          int64
	Owner       string
	AccountName string
	SessionText string
	TGUserID    int64
	CreatedAt   string
}

func CreateTGAccount(dbConn *sql.DB, owner, accountName, sessionText string, tgUserID int64) error {
	createdAt := time.Now().Format(time.RFC3339)
	_, err := dbConn.Exec(
		"INSERT INTO tg_accounts (owner, account_name, session_text, tg_user_id, created_at) VALUES (?, ?, ?, ?, ?)",
		owner,
		accountName,
		sessionText,
		tgUserID,
		createdAt,
	)
	if err != nil {
		return fmt.Errorf("create tg account: %w", err)
	}
	return nil
}

func ListTGAccounts(dbConn *sql.DB, owner string) ([]TGAccount, error) {
	rows, err := dbConn.Query(
		"SELECT id, owner, account_name, tg_user_id, created_at FROM tg_accounts WHERE owner = ? ORDER BY id DESC",
		owner,
	)
	if err != nil {
		return nil, fmt.Errorf("list tg accounts: %w", err)
	}
	defer rows.Close()

	var out []TGAccount
	for rows.Next() {
		var a TGAccount
		if err := rows.Scan(&a.ID, &a.Owner, &a.AccountName, &a.TGUserID, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan tg account: %w", err)
		}
		out = append(out, a)
	}
	return out, nil
}

func GetTGAccountByID(dbConn *sql.DB, owner string, accountID int64) (TGAccount, error) {
	var a TGAccount
	row := dbConn.QueryRow(
		"SELECT id, owner, account_name, session_text, tg_user_id, created_at FROM tg_accounts WHERE id = ? AND owner = ?",
		accountID,
		owner,
	)
	if err := row.Scan(&a.ID, &a.Owner, &a.AccountName, &a.SessionText, &a.TGUserID, &a.CreatedAt); err != nil {
		return TGAccount{}, fmt.Errorf("get tg account: %w", err)
	}
	return a, nil
}

func DeleteTGAccount(dbConn *sql.DB, owner string, accountID int64) error {
	if _, err := dbConn.Exec("DELETE FROM tg_accounts WHERE id = ? AND owner = ?", accountID, owner); err != nil {
		return fmt.Errorf("delete tg account: %w", err)
	}
	// best-effort cleanup
	DeleteTGDialogsFile(accountID) // JSON file, no error handling needed
	_, _ = dbConn.Exec("DELETE FROM tg_auto_send_tasks WHERE owner = ? AND account_id = ?", owner, accountID)
	_, _ = dbConn.Exec("DELETE FROM tg_auto_reply_rules WHERE owner = ? AND account_id = ?", owner, accountID)
	return nil
}

func UpdateTGAccountUserID(dbConn *sql.DB, accountID int64, tgUserID int64) error {
	_, err := dbConn.Exec("UPDATE tg_accounts SET tg_user_id = ? WHERE id = ?", tgUserID, accountID)
	return err
}

// UpdateTGAccountSession replaces only the session_text (and optionally tg_user_id)
// for an existing account. All other fields (account_name, tasks, rules, …) are untouched.
func UpdateTGAccountSession(dbConn *sql.DB, owner string, accountID int64, sessionText string, tgUserID int64) error {
	_, err := dbConn.Exec(
		"UPDATE tg_accounts SET session_text = ?, tg_user_id = ? WHERE id = ? AND owner = ?",
		sessionText, tgUserID, accountID, owner,
	)
	if err != nil {
		return fmt.Errorf("update tg account session: %w", err)
	}
	return nil
}
