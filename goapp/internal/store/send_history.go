package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const maxSendHistoryEntries = 1000

// SendHistoryEntry is one execution record for an auto-send task.
type SendHistoryEntry struct {
	Time    string `json:"time"`
	Message string `json:"message"`
	Result  string `json:"result"`
	Reply   string `json:"reply"`
}

var sendHistoryMu sync.Mutex

func sendHistoryDir() string {
	base := os.Getenv("VPSHELPER_DATA_DIR")
	if base == "" {
		wd, _ := os.Getwd()
		base = filepath.Join(wd, "..", "userdata")
	}
	return filepath.Join(base, "send_history")
}

func sendHistoryPath(taskID int64) string {
	return filepath.Join(sendHistoryDir(), fmt.Sprintf("%d.json", taskID))
}

// ListSendHistory returns up to maxSendHistoryEntries entries, newest first.
// The dbConn parameter is kept for interface consistency but is not used.
func ListSendHistory(_ *sql.DB, taskID int64) ([]SendHistoryEntry, error) {
	data, err := os.ReadFile(sendHistoryPath(taskID))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read send history: %w", err)
	}
	var entries []SendHistoryEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse send history: %w", err)
	}
	return entries, nil
}

// AppendSendHistory prepends a new entry and trims to maxSendHistoryEntries.
func AppendSendHistory(taskID int64, timeStr, message, result, reply string) error {
	sendHistoryMu.Lock()
	defer sendHistoryMu.Unlock()

	dir := sendHistoryDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create send_history dir: %w", err)
	}

	path := sendHistoryPath(taskID)
	var entries []SendHistoryEntry

	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &entries)
	}

	// Prepend newest entry
	entry := SendHistoryEntry{Time: timeStr, Message: message, Result: result, Reply: reply}
	entries = append([]SendHistoryEntry{entry}, entries...)
	if len(entries) > maxSendHistoryEntries {
		entries = entries[:maxSendHistoryEntries]
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal send history: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write send history: %w", err)
	}
	return os.Rename(tmp, path)
}

// DeleteSendHistoryFile removes the history JSON file for a task (called on task delete).
func DeleteSendHistoryFile(taskID int64) {
	_ = os.Remove(sendHistoryPath(taskID))
}
