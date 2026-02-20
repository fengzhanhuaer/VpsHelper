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

	return nil
}
