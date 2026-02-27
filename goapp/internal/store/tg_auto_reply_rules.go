package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// AutoReplyRule is a single keyword-matching rule for auto-reply.
// It carries the account credentials so the listener is self-contained.
type AutoReplyRule struct {
	ID          int64
	Owner       string
	AccountID   int64
	AccountName string
	Enabled     bool
	MatchText   string
	ReplyText   string
	CreatedAt   string
	UpdatedAt   string
	// Embedded credentials (same pattern as AutoSendTask).
	SessionText string
	APIID       string
	APIHash     string
	AllProxy    string
}

// OwnerAccount identifies a unique (owner, accountID) listener.
// It carries the credentials needed to start the listener without extra DB queries.
type OwnerAccount struct {
	Owner       string
	AccountID   int64
	AccountName string
	SessionText string
	APIID       string
	APIHash     string
	AllProxy    string
}

const autoReplyCols = `id, owner, account_id, COALESCE(account_name,''), enabled,
	match_text, reply_text, created_at, updated_at,
	COALESCE(session_text,''), COALESCE(api_id,''), COALESCE(api_hash,''), COALESCE(all_proxy,'')`

func scanAutoReplyRule(row interface{ Scan(...any) error }) (AutoReplyRule, error) {
	var r AutoReplyRule
	var en int
	if err := row.Scan(
		&r.ID, &r.Owner, &r.AccountID, &r.AccountName, &en,
		&r.MatchText, &r.ReplyText, &r.CreatedAt, &r.UpdatedAt,
		&r.SessionText, &r.APIID, &r.APIHash, &r.AllProxy,
	); err != nil {
		return AutoReplyRule{}, err
	}
	r.Enabled = en != 0
	return r, nil
}

func CreateAutoReplyRule(dbConn *sql.DB, owner string, accountID int64, accountName, matchText, replyText string, enabled bool, sessionText, apiID, apiHash, allProxy string) error {
	now := time.Now().Format(time.RFC3339)
	en := 0
	if enabled {
		en = 1
	}
	_, err := dbConn.Exec(
		`INSERT INTO tg_auto_reply_rules
		    (owner, account_id, account_name, enabled, match_text, reply_text, created_at, updated_at,
		     session_text, api_id, api_hash, all_proxy)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		owner, accountID, accountName, en, matchText, replyText, now, now,
		sessionText, apiID, apiHash, allProxy,
	)
	if err != nil {
		return fmt.Errorf("create auto reply rule: %w", err)
	}
	return nil
}

func ListAutoReplyRules(dbConn *sql.DB, owner string, accountID int64) ([]AutoReplyRule, error) {
	rows, err := dbConn.Query(
		`SELECT `+autoReplyCols+`
           FROM tg_auto_reply_rules
          WHERE owner = ? AND account_id = ?
          ORDER BY id DESC`,
		owner, accountID,
	)
	if err != nil {
		return nil, fmt.Errorf("list auto reply rules: %w", err)
	}
	defer rows.Close()

	var out []AutoReplyRule
	for rows.Next() {
		r, err := scanAutoReplyRule(rows)
		if err != nil {
			return nil, fmt.Errorf("scan auto reply rule: %w", err)
		}
		out = append(out, r)
	}
	return out, nil
}

func ListEnabledAutoReplyRules(dbConn *sql.DB, owner string, accountID int64) ([]AutoReplyRule, error) {
	rows, err := dbConn.Query(
		`SELECT `+autoReplyCols+`
           FROM tg_auto_reply_rules
          WHERE owner = ? AND account_id = ? AND enabled = 1
          ORDER BY id ASC`,
		owner, accountID,
	)
	if err != nil {
		return nil, fmt.Errorf("list enabled auto reply rules: %w", err)
	}
	defer rows.Close()

	var out []AutoReplyRule
	for rows.Next() {
		r, err := scanAutoReplyRule(rows)
		if err != nil {
			return nil, fmt.Errorf("scan enabled auto reply rule: %w", err)
		}
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
		en, now, id, owner,
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

// ListEnabledAutoReplyAccounts returns each distinct (owner, accountID) that has at least
// one enabled rule, along with the credentials stored in the first such rule.
// The listener uses these credentials directly without querying tg_accounts or app_settings.
func ListEnabledAutoReplyAccounts(dbConn *sql.DB) ([]OwnerAccount, error) {
	rows, err := dbConn.Query(
		`SELECT owner, account_id,
		        COALESCE(MAX(account_name),''),
		        COALESCE(MAX(session_text),''),
		        COALESCE(MAX(api_id),''),
		        COALESCE(MAX(api_hash),''),
		        COALESCE(MAX(all_proxy),'')
		   FROM tg_auto_reply_rules
		  WHERE enabled = 1
		  GROUP BY owner, account_id`,
	)
	if err != nil {
		return nil, fmt.Errorf("list enabled auto reply accounts: %w", err)
	}
	defer rows.Close()

	var out []OwnerAccount
	for rows.Next() {
		var oa OwnerAccount
		if err := rows.Scan(&oa.Owner, &oa.AccountID, &oa.AccountName, &oa.SessionText, &oa.APIID, &oa.APIHash, &oa.AllProxy); err != nil {
			return nil, fmt.Errorf("scan enabled auto reply accounts: %w", err)
		}
		out = append(out, oa)
	}
	return out, nil
}

// ListAllTGAccountsAsOwnerAccounts returns every TG account as an OwnerAccount,
// with API credentials loaded from the global app_settings.
// Used by StartAutoReply so the listener runs for ALL accounts (not just ones with rules).
func ListAllTGAccountsAsOwnerAccounts(dbConn *sql.DB) ([]OwnerAccount, error) {
	settings, _ := GetSettings(dbConn, []string{"telegram_api_id", "telegram_api_hash", "tg_all_proxy"})
	apiID := strings.TrimSpace(settings["telegram_api_id"])
	apiHash := strings.TrimSpace(settings["telegram_api_hash"])
	allProxy := strings.TrimSpace(settings["tg_all_proxy"])

	rows, err := dbConn.Query(
		"SELECT owner, id, COALESCE(account_name,''), COALESCE(session_text,'') FROM tg_accounts",
	)
	if err != nil {
		return nil, fmt.Errorf("list all tg accounts: %w", err)
	}
	defer rows.Close()

	var out []OwnerAccount
	for rows.Next() {
		var oa OwnerAccount
		if err := rows.Scan(&oa.Owner, &oa.AccountID, &oa.AccountName, &oa.SessionText); err != nil {
			return nil, fmt.Errorf("scan tg account: %w", err)
		}
		oa.APIID = apiID
		oa.APIHash = apiHash
		oa.AllProxy = allProxy
		out = append(out, oa)
	}
	return out, nil
}
