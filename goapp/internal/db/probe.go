package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// ProbeDBName is the filename for the probe telemetry database.
const ProbeDBName = "probe_data.db"

// OpenProbe opens (or creates) the per-deployment probe_data.db which stores
// probe statuses and telemetry history. This database is intentionally
// kept separate from the main app DB and the telegram local DB.
func OpenProbe(dataDir string) (*sql.DB, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	path := filepath.Join(dataDir, ProbeDBName)
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)")
	if err != nil {
		return nil, fmt.Errorf("open probe db: %w", err)
	}
	db.SetMaxOpenConns(1) // sqlite WAL: single writer is enough
	if err := MigrateProbe(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// MigrateProbe creates/updates all tables in probe_data.db.
func MigrateProbe(db *sql.DB) error {
	stmts := []string{
		// ── probe node runtime status ─────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS probe_node_status (
            node_id   INTEGER PRIMARY KEY,
            online    INTEGER NOT NULL DEFAULT 0,
            last_ping INTEGER NOT NULL DEFAULT 0
        )`,

		// ── probe telemetry history ───────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS probe_node_stats_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            cpu REAL NOT NULL,
            mem_pct REAL NOT NULL,
            disk_pct REAL NOT NULL,
            net_in INTEGER NOT NULL,
            net_out INTEGER NOT NULL
        )`,
		`CREATE INDEX IF NOT EXISTS idx_pnsh_node
            ON probe_node_stats_history(node_id, created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_pnsh_created
            ON probe_node_stats_history(created_at)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("migrate probe db: %w\nstmt: %s", err, s)
		}
	}

	return nil
}
