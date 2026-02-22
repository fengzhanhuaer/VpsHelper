package store

import (
	"database/sql"
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
