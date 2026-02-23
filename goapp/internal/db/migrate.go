package db

import (
	"database/sql"
	"fmt"
)

func Migrate(dbConn *sql.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )`,
		`CREATE TABLE IF NOT EXISTS tg_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            account_name TEXT NOT NULL,
            session_text TEXT NOT NULL,
			tg_user_id INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )`,
		`CREATE TABLE IF NOT EXISTS tg_dialogs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            dialog_id TEXT NOT NULL,
            title TEXT,
            username TEXT,
            updated_at TEXT NOT NULL
        )`,
		`CREATE TABLE IF NOT EXISTS tg_sign_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            account_id INTEGER NOT NULL,
            dialog_id TEXT NOT NULL,
            message TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(owner, account_id)
        )`,
		`CREATE TABLE IF NOT EXISTS tg_auto_send_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            account_id INTEGER NOT NULL,
            dialog_id TEXT NOT NULL,
            message TEXT NOT NULL,
            interval_seconds INTEGER NOT NULL,
            jitter_seconds INTEGER NOT NULL,
            schedule_type TEXT NOT NULL,
            time_of_day TEXT,
            enabled INTEGER NOT NULL,
            next_run_at TEXT NOT NULL,
            last_run_at TEXT,
            last_result TEXT,
            last_reply TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )`,
		`CREATE TABLE IF NOT EXISTS tg_login_flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            phone TEXT NOT NULL,
            account_name TEXT,
            session_text TEXT NOT NULL,
            phone_code_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )`,
		`CREATE TABLE IF NOT EXISTS tg_auto_reply_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            account_id INTEGER NOT NULL,
            enabled INTEGER NOT NULL,
            match_text TEXT NOT NULL,
            reply_text TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )`,
		`CREATE INDEX IF NOT EXISTS idx_tg_auto_reply_rules_enabled_owner_account ON tg_auto_reply_rules (enabled, owner, account_id)`,
		`CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )`,
		`CREATE TABLE IF NOT EXISTS shell_shortcuts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            name TEXT NOT NULL,
            command TEXT NOT NULL,
            created_at TEXT NOT NULL
        )`,
	}

	for _, stmt := range statements {
		if _, err := dbConn.Exec(stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}

	_ = dbConn.QueryRow("SELECT tg_user_id FROM tg_accounts LIMIT 1").Scan(new(int))
	_, _ = dbConn.Exec("ALTER TABLE tg_accounts ADD COLUMN tg_user_id INTEGER DEFAULT 0;")

	// v2: embed credentials directly into auto-send tasks so tasks are self-contained.
	_, _ = dbConn.Exec("ALTER TABLE tg_auto_send_tasks ADD COLUMN session_text TEXT NOT NULL DEFAULT '';")
	_, _ = dbConn.Exec("ALTER TABLE tg_auto_send_tasks ADD COLUMN api_id TEXT NOT NULL DEFAULT '';")
	_, _ = dbConn.Exec("ALTER TABLE tg_auto_send_tasks ADD COLUMN api_hash TEXT NOT NULL DEFAULT '';")
	_, _ = dbConn.Exec("ALTER TABLE tg_auto_send_tasks ADD COLUMN all_proxy TEXT NOT NULL DEFAULT '';")
	_, _ = dbConn.Exec("ALTER TABLE tg_auto_send_tasks ADD COLUMN account_name TEXT NOT NULL DEFAULT '';")

	// v2: same for auto-reply rules.
	_, _ = dbConn.Exec("ALTER TABLE tg_auto_reply_rules ADD COLUMN session_text TEXT NOT NULL DEFAULT '';")
	_, _ = dbConn.Exec("ALTER TABLE tg_auto_reply_rules ADD COLUMN api_id TEXT NOT NULL DEFAULT '';")
	_, _ = dbConn.Exec("ALTER TABLE tg_auto_reply_rules ADD COLUMN api_hash TEXT NOT NULL DEFAULT '';")
	_, _ = dbConn.Exec("ALTER TABLE tg_auto_reply_rules ADD COLUMN all_proxy TEXT NOT NULL DEFAULT '';")
	_, _ = dbConn.Exec("ALTER TABLE tg_auto_reply_rules ADD COLUMN account_name TEXT NOT NULL DEFAULT '';")

	// ── probe nodes (identity only — backed up to D1) ─────────────────────────
	_, _ = dbConn.Exec(`CREATE TABLE IF NOT EXISTS probe_nodes (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		name       TEXT    NOT NULL,
		note       TEXT    NOT NULL DEFAULT '',
		secret     TEXT    NOT NULL UNIQUE,
		created_at TEXT    NOT NULL DEFAULT ''
	)`)

	// v2: add configurable report interval per node (seconds, default 60)
	_, _ = dbConn.Exec("ALTER TABLE probe_nodes ADD COLUMN report_interval INTEGER NOT NULL DEFAULT 60;")

	return nil
}
