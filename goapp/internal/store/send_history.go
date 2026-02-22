package store

import (
	"database/sql"
	"fmt"
)

const maxSendHistoryEntries = 1000

// SendHistoryEntry is one execution record for an auto-send task.
type SendHistoryEntry struct {
	Time    string `json:"time"`
	Message string `json:"message"`
	Result  string `json:"result"`
	Reply   string `json:"reply"`
}

// ListSendHistory returns up to maxSendHistoryEntries entries for taskID, newest first.
// The dbConn parameter is kept for interface consistency but is not used.
func ListSendHistory(_ *sql.DB, taskID int64) ([]SendHistoryEntry, error) {
	rows, err := localDB.Query(
		`SELECT time, message, result, reply
		   FROM tg_send_history
		  WHERE task_id = ?
		  ORDER BY id DESC
		  LIMIT ?`,
		taskID, maxSendHistoryEntries,
	)
	if err != nil {
		return nil, fmt.Errorf("list send history: %w", err)
	}
	defer rows.Close()

	var entries []SendHistoryEntry
	for rows.Next() {
		var e SendHistoryEntry
		if err := rows.Scan(&e.Time, &e.Message, &e.Result, &e.Reply); err != nil {
			return nil, fmt.Errorf("scan send history: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// AppendSendHistory inserts a new execution record and trims the oldest rows
// so at most maxSendHistoryEntries are kept per task.
func AppendSendHistory(taskID int64, timeStr, message, result, reply string) error {
	if _, err := localDB.Exec(
		`INSERT INTO tg_send_history (task_id, time, message, result, reply) VALUES (?, ?, ?, ?, ?)`,
		taskID, timeStr, message, result, reply,
	); err != nil {
		return fmt.Errorf("append send history: %w", err)
	}

	// Trim: keep only the latest maxSendHistoryEntries rows for this task.
	_, _ = localDB.Exec(
		`DELETE FROM tg_send_history
		 WHERE task_id = ?
		   AND id NOT IN (
		     SELECT id FROM tg_send_history
		     WHERE task_id = ?
		     ORDER BY id DESC
		     LIMIT ?
		 )`,
		taskID, taskID, maxSendHistoryEntries,
	)

	return nil
}

// DeleteSendHistoryFile removes all history rows for a task (called on task delete).
// The name is kept for backward compatibility with callers.
func DeleteSendHistoryFile(taskID int64) {
	_, _ = localDB.Exec("DELETE FROM tg_send_history WHERE task_id = ?", taskID)
}
