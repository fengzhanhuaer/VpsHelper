package store

import (
	"fmt"
	"sort"
	"strings"
)

const maxChatMessages = 2000

// ChatMessage is one persisted message in a dialog's history.
type ChatMessage struct {
	MsgID int    `json:"msg_id"`
	From  string `json:"from"` // "me" (out) or sender user_id string
	Text  string `json:"text"`
	Date  int64  `json:"date"` // unix
	Out   bool   `json:"out"`
}

// AppendChatMessage inserts a message into tg_messages in tg_data.db,
// and trims older rows so at most maxChatMessages per dialog are kept.
func AppendChatMessage(accountID int64, dialogID string, msg ChatMessage) error {
	if msg.Text == "" {
		return nil
	}

	outInt := 0
	if msg.Out {
		outInt = 1
	}

	if _, err := localDB.Exec(
		`INSERT OR IGNORE INTO tg_messages (account_id, dialog_id, msg_id, from_name, text, date, out)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		accountID, dialogID, msg.MsgID, msg.From, msg.Text, msg.Date, outInt,
	); err != nil {
		return fmt.Errorf("append chat message: %w", err)
	}

	// Trim: keep only the latest maxChatMessages rows for this dialog.
	_, _ = localDB.Exec(
		`DELETE FROM tg_messages
		 WHERE account_id = ? AND dialog_id = ?
		   AND id NOT IN (
		     SELECT id FROM tg_messages
		     WHERE account_id = ? AND dialog_id = ?
		     ORDER BY date DESC, id DESC
		     LIMIT ?
		 )`,
		accountID, dialogID, accountID, dialogID, maxChatMessages,
	)

	return nil
}

// ListChatMessages returns stored messages for a dialog (oldest first, max 2000).
func ListChatMessages(accountID int64, dialogID string) ([]ChatMessage, error) {
	rows, err := localDB.Query(
		`SELECT msg_id, from_name, text, date, out
		   FROM tg_messages
		  WHERE account_id = ? AND dialog_id = ?
		  ORDER BY date ASC, id ASC`,
		accountID, dialogID,
	)
	if err != nil {
		return nil, fmt.Errorf("list chat messages: %w", err)
	}
	defer rows.Close()

	var msgs []ChatMessage
	for rows.Next() {
		var m ChatMessage
		var outInt int
		if err := rows.Scan(&m.MsgID, &m.From, &m.Text, &m.Date, &outInt); err != nil {
			return nil, fmt.Errorf("scan chat message: %w", err)
		}
		m.Out = outInt == 1
		msgs = append(msgs, m)
	}
	return msgs, nil
}

// ListDialogsWithHistory returns the dialog IDs that have any stored message
// for the given accountID. Used at startup for catch-up fetch.
func ListDialogsWithHistory(accountID int64) []string {
	rows, err := localDB.Query(
		`SELECT DISTINCT dialog_id FROM tg_messages WHERE account_id = ?`,
		accountID,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// GetLastStoredMsgID returns the highest msg_id in the stored history for a dialog.
// Returns 0 if no messages are stored.
func GetLastStoredMsgID(accountID int64, dialogID string) int {
	var maxID int
	err := localDB.QueryRow(
		`SELECT COALESCE(MAX(msg_id), 0) FROM tg_messages WHERE account_id = ? AND dialog_id = ?`,
		accountID, dialogID,
	).Scan(&maxID)
	if err != nil {
		return 0
	}
	return maxID
}

// DeleteChatMsgsForAccount removes all chat messages for an account.
func DeleteChatMsgsForAccount(accountID int64) {
	_, _ = localDB.Exec("DELETE FROM tg_messages WHERE account_id = ?", accountID)
}

// SearchResult is one message hit returned by SearchChatMessages.
type SearchResult struct {
	DialogID    string      `json:"dialog_id"`
	DialogTitle string      `json:"dialog_title"`
	Msg         ChatMessage `json:"msg"`
}

// SearchChatMessages searches all stored messages for accountID that contain query
// (case-insensitive substring match). titleMap optionally maps dialogID → human title.
// Returns at most maxResults hits.
func SearchChatMessages(accountID int64, query string, titleMap map[string]string, maxResults int) ([]SearchResult, error) {
	if maxResults <= 0 {
		maxResults = 200
	}
	lq := strings.ToLower(query)

	rows, err := localDB.Query(
		`SELECT dialog_id, msg_id, from_name, text, date, out
		   FROM tg_messages
		  WHERE account_id = ? AND text LIKE ?
		  ORDER BY date DESC
		  LIMIT ?`,
		accountID, "%"+lq+"%", maxResults,
	)
	if err != nil {
		return nil, fmt.Errorf("search chat messages: %w", err)
	}
	defer rows.Close()

	// LIKE in SQLite is case-insensitive for ASCII; for full unicode we do an extra Go filter.
	var results []SearchResult
	for rows.Next() {
		var dialogID string
		var m ChatMessage
		var outInt int
		if err := rows.Scan(&dialogID, &m.MsgID, &m.From, &m.Text, &m.Date, &outInt); err != nil {
			continue
		}
		// Extra Go-level filter for non-ASCII unicode case-insensitivity.
		if !strings.Contains(strings.ToLower(m.Text), lq) {
			continue
		}
		m.Out = outInt == 1
		title := dialogID
		if titleMap != nil {
			if t, ok := titleMap[dialogID]; ok && t != "" {
				title = t
			}
		}
		results = append(results, SearchResult{
			DialogID:    dialogID,
			DialogTitle: title,
			Msg:         m,
		})
	}

	// Sort by date DESC for consistent ordering.
	sort.Slice(results, func(i, j int) bool {
		return results[i].Msg.Date > results[j].Msg.Date
	})

	return results, nil
}
