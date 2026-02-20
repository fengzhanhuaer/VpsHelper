package store

import (
	"database/sql"
	"fmt"
	"time"
)

type AutoReplyRule struct {
	ID        int64
	Owner     string
	AccountID int64
	Enabled   bool
	MatchText string
	ReplyText string
	CreatedAt string
	UpdatedAt string
}

type OwnerAccount struct {
	Owner     string
	AccountID int64
}

func CreateAutoReplyRule(dbConn *sql.DB, owner string, accountID int64, matchText, replyText string, enabled bool) error {
	now := time.Now().Format(time.RFC3339)
	en := 0
	if enabled {
		en = 1
	}
	_, err := dbConn.Exec(
		"INSERT INTO tg_auto_reply_rules (owner, account_id, enabled, match_text, reply_text, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		owner,
		accountID,
		en,
		matchText,
		replyText,
		now,
		now,
	)
	if err != nil {
		return fmt.Errorf("create auto reply rule: %w", err)
	}
	return nil
}

func ListAutoReplyRules(dbConn *sql.DB, owner string, accountID int64) ([]AutoReplyRule, error) {
	rows, err := dbConn.Query(
		"SELECT id, owner, account_id, enabled, match_text, reply_text, created_at, updated_at FROM tg_auto_reply_rules WHERE owner = ? AND account_id = ? ORDER BY id DESC",
		owner,
		accountID,
	)
	if err != nil {
		return nil, fmt.Errorf("list auto reply rules: %w", err)
	}
	defer rows.Close()

	var out []AutoReplyRule
	for rows.Next() {
		var r AutoReplyRule
		var enabled int
		if err := rows.Scan(&r.ID, &r.Owner, &r.AccountID, &enabled, &r.MatchText, &r.ReplyText, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan auto reply rule: %w", err)
		}
		r.Enabled = enabled != 0
		out = append(out, r)
	}
	return out, nil
}

func ListEnabledAutoReplyRules(dbConn *sql.DB, owner string, accountID int64) ([]AutoReplyRule, error) {
	rows, err := dbConn.Query(
		"SELECT id, owner, account_id, enabled, match_text, reply_text, created_at, updated_at FROM tg_auto_reply_rules WHERE owner = ? AND account_id = ? AND enabled = 1 ORDER BY id ASC",
		owner,
		accountID,
	)
	if err != nil {
		return nil, fmt.Errorf("list enabled auto reply rules: %w", err)
	}
	defer rows.Close()

	var out []AutoReplyRule
	for rows.Next() {
		var r AutoReplyRule
		var enabled int
		if err := rows.Scan(&r.ID, &r.Owner, &r.AccountID, &enabled, &r.MatchText, &r.ReplyText, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan enabled auto reply rule: %w", err)
		}
		r.Enabled = enabled != 0
		out = append(out, r)
	}
	return out, nil
}

func SetAutoReplyRuleEnabled(dbConn *sql.DB, owner string, id int64, enabled bool) error {
	en := 0
	if enabled {
		en = 1
	}
	now := time.Now().Format(time.RFC3339)
	if _, err := dbConn.Exec(
		"UPDATE tg_auto_reply_rules SET enabled = ?, updated_at = ? WHERE id = ? AND owner = ?",
		en,
		now,
		id,
		owner,
	); err != nil {
		return fmt.Errorf("set auto reply rule enabled: %w", err)
	}
	return nil
}

func DeleteAutoReplyRule(dbConn *sql.DB, owner string, id int64) error {
	if _, err := dbConn.Exec("DELETE FROM tg_auto_reply_rules WHERE id = ? AND owner = ?", id, owner); err != nil {
		return fmt.Errorf("delete auto reply rule: %w", err)
	}
	return nil
}

func ListEnabledAutoReplyAccounts(dbConn *sql.DB) ([]OwnerAccount, error) {
	rows, err := dbConn.Query(
		"SELECT DISTINCT owner, account_id FROM tg_auto_reply_rules WHERE enabled = 1",
	)
	if err != nil {
		return nil, fmt.Errorf("list enabled auto reply accounts: %w", err)
	}
	defer rows.Close()

	var out []OwnerAccount
	for rows.Next() {
		var oa OwnerAccount
		if err := rows.Scan(&oa.Owner, &oa.AccountID); err != nil {
			return nil, fmt.Errorf("scan enabled auto reply accounts: %w", err)
		}
		out = append(out, oa)
	}
	return out, nil
}
