package store

import (
	"strconv"
	"strings"
)

// MigrateLegacyPeerKeys converts old peerKey-format dialog_ids stored in
// tg_dialogs and tg_messages (e.g. "user:123", "channel:456", "chat:789")
// to the canonical numeric format used by RefreshDialogs.
//
// This is a one-time, idempotent migration that should be called at startup
// after SetLocalDB(). It is safe to call multiple times.
func MigrateLegacyPeerKeys() error {
	// 1. Find all dialog_ids in tg_dialogs that look like peerKey format.
	rows, err := localDB.Query(
		`SELECT DISTINCT account_id, dialog_id, title, username, updated_at, last_msg_at
		   FROM tg_dialogs
		  WHERE dialog_id LIKE 'user:%'
		     OR dialog_id LIKE 'channel:%'
		     OR dialog_id LIKE 'chat:%'`,
	)
	if err != nil {
		return nil // table might not exist yet; safe to skip
	}
	defer rows.Close()

	type legacyRow struct {
		accountID int64
		oldID     string
		title     string
		username  string
		updatedAt string
		lastMsgAt int64
	}

	var legacy []legacyRow
	for rows.Next() {
		var r legacyRow
		if err := rows.Scan(&r.accountID, &r.oldID, &r.title, &r.username, &r.updatedAt, &r.lastMsgAt); err == nil {
			legacy = append(legacy, r)
		}
	}
	rows.Close()

	for _, r := range legacy {
		newID := peerKeyToDialogID(r.oldID)
		if newID == "" || newID == r.oldID {
			continue // cannot convert — skip
		}

		// Repair the title if it still holds the raw peerKey as a placeholder.
		title := r.title
		if title == r.oldID || title == "" {
			title = newID // fall back to numeric ID; will be overwritten on next Refresh
		}

		tx, err := localDB.Begin()
		if err != nil {
			continue
		}

		// 2a. Migrate tg_messages rows from old dialog_id → new dialog_id.
		//     Use INSERT OR IGNORE to avoid duplicating messages that were
		//     already stored with the correct numeric ID.
		_, _ = tx.Exec(
			`INSERT OR IGNORE INTO tg_messages (account_id, dialog_id, msg_id, from_name, text, date, out)
			 SELECT account_id, ?, msg_id, from_name, text, date, out
			   FROM tg_messages
			  WHERE account_id = ? AND dialog_id = ?`,
			newID, r.accountID, r.oldID,
		)
		// 2b. Delete the old message rows.
		_, _ = tx.Exec(
			`DELETE FROM tg_messages WHERE account_id = ? AND dialog_id = ?`,
			r.accountID, r.oldID,
		)

		// 3. Upsert tg_dialogs with the numeric ID (keep the better last_msg_at).
		_, _ = tx.Exec(
			`INSERT INTO tg_dialogs (account_id, dialog_id, title, username, updated_at, last_msg_at)
			 VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT(account_id, dialog_id) DO UPDATE SET
			   last_msg_at = CASE WHEN excluded.last_msg_at > last_msg_at THEN excluded.last_msg_at ELSE last_msg_at END,
			   updated_at  = CASE WHEN excluded.last_msg_at > last_msg_at THEN excluded.updated_at  ELSE updated_at  END`,
			r.accountID, newID, title, r.username, r.updatedAt, r.lastMsgAt,
		)

		// 4. Remove the old peerKey dialog row.
		_, _ = tx.Exec(
			`DELETE FROM tg_dialogs WHERE account_id = ? AND dialog_id = ?`,
			r.accountID, r.oldID,
		)

		_ = tx.Commit()
	}

	return nil
}

// peerKeyToDialogID converts a peerKey string to its canonical numeric dialogID.
//
//	"user:123"    → "123"
//	"chat:123"    → "-123"
//	"channel:123" → "-(1000000000000 + 123)"
func peerKeyToDialogID(key string) string {
	if after, ok := strings.CutPrefix(key, "user:"); ok {
		if _, err := strconv.ParseInt(after, 10, 64); err == nil {
			return after
		}
	}
	if after, ok := strings.CutPrefix(key, "chat:"); ok {
		if n, err := strconv.ParseInt(after, 10, 64); err == nil {
			return strconv.FormatInt(-n, 10)
		}
	}
	if after, ok := strings.CutPrefix(key, "channel:"); ok {
		if n, err := strconv.ParseInt(after, 10, 64); err == nil {
			return strconv.FormatInt(-(1000000000000 + n), 10)
		}
	}
	return ""
}
