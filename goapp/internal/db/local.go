package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// LocalDBName is the filename for the local TG data database.
const LocalDBName = "tg_data.db"

// OpenLocal opens (or creates) the per-deployment tg_data.db which stores
// TG dialogs, chat messages, and send history. This database is intentionally
// kept separate from the main app DB so it is NOT included in D1 cloud backups.
func OpenLocal(dataDir string) (*sql.DB, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	path := filepath.Join(dataDir, LocalDBName)
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)")
	if err != nil {
		return nil, fmt.Errorf("open local db: %w", err)
	}
	db.SetMaxOpenConns(1) // sqlite WAL: single writer is enough
	if err := MigrateLocal(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// MigrateLocal creates/updates all tables in tg_data.db.
func MigrateLocal(db *sql.DB) error {
	stmts := []string{
		// ── dialogs ──────────────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS tg_dialogs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id  INTEGER NOT NULL,
            dialog_id   TEXT    NOT NULL,
            title       TEXT    NOT NULL DEFAULT '',
            username    TEXT    NOT NULL DEFAULT '',
            updated_at  TEXT    NOT NULL DEFAULT '',
            last_msg_at INTEGER NOT NULL DEFAULT 0,
            UNIQUE (account_id, dialog_id)
        )`,
		`CREATE INDEX IF NOT EXISTS idx_tgd_account
            ON tg_dialogs(account_id, last_msg_at DESC)`,

		// ── messages ─────────────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS tg_messages (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id  INTEGER NOT NULL,
            dialog_id   TEXT    NOT NULL,
            msg_id      INTEGER NOT NULL DEFAULT 0,
            from_name   TEXT    NOT NULL DEFAULT '',
            text        TEXT    NOT NULL DEFAULT '',
            date        INTEGER NOT NULL DEFAULT 0,
            out         INTEGER NOT NULL DEFAULT 0,
            UNIQUE (account_id, dialog_id, msg_id)
        )`,
		`CREATE INDEX IF NOT EXISTS idx_tgm_dialog
            ON tg_messages(account_id, dialog_id, date ASC)`,
		`CREATE INDEX IF NOT EXISTS idx_tgm_date
            ON tg_messages(account_id, date DESC)`,

		// ── send history ─────────────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS tg_send_history (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            time    TEXT    NOT NULL DEFAULT '',
            message TEXT    NOT NULL DEFAULT '',
            result  TEXT    NOT NULL DEFAULT '',
            reply   TEXT    NOT NULL DEFAULT ''
        )`,
		`CREATE INDEX IF NOT EXISTS idx_tgsh_task
            ON tg_send_history(task_id, id DESC)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("migrate local db: %w\nstmt: %s", err, s)
		}
	}
	return nil
}
