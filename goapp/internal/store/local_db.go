package store

import (
	"database/sql"
	"fmt"
)

// localDB is the handle to tg_data.db, opened at startup via SetLocalDB.
// It holds per-deployment data that is NOT backed up to Cloudflare D1:
//   - tg_dialogs    – cached dialog list per account
//   - tg_messages   – stored chat message history
//   - tg_send_history – auto-send task execution log
var localDB *sql.DB

// SetLocalDB must be called once from main after db.OpenLocal succeeds.
// All tg_dialogs / tg_messages / tg_send_history store functions depend on it.
func SetLocalDB(db *sql.DB) {
	localDB = db
}

func GetLocalSetting(key string) string {
	if localDB == nil {
		return ""
	}
	var val string
	err := localDB.QueryRow("SELECT value FROM local_settings WHERE key = ?", key).Scan(&val)
	if err != nil {
		return ""
	}
	return val
}

func SetLocalSetting(key, value string) error {
	if localDB == nil {
		return fmt.Errorf("localDB not initialized")
	}
	_, err := localDB.Exec(
		"INSERT OR REPLACE INTO local_settings (key, value) VALUES (?, ?)",
		key,
		value,
	)
	return err
}
