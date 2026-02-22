package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode"
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

var chatMsgMu sync.Mutex

func chatMsgsDir() string {
	base := os.Getenv("VPSHELPER_DATA_DIR")
	if base == "" {
		wd, _ := os.Getwd()
		base = filepath.Join(wd, "..", "userdata")
	}
	return filepath.Join(base, "messages")
}

// safeDialogID converts a dialog_id string to a filesystem-safe filename stem.
// e.g. "-1001234567890" → "-1001234567890", "@username" → "_username"
func safeDialogID(dialogID string) string {
	var sb strings.Builder
	for _, r := range dialogID {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
			sb.WriteRune(r)
		} else if r == '@' {
			sb.WriteRune('_')
		} else {
			sb.WriteRune('_')
		}
	}
	return sb.String()
}

func chatMsgsPath(accountID int64, dialogID string) string {
	dir := filepath.Join(chatMsgsDir(), fmt.Sprintf("%d", accountID))
	return filepath.Join(dir, safeDialogID(dialogID)+".json")
}

// AppendChatMessage prepends a message and trims to maxChatMessages.
// Newest messages are at the END (for display order).
func AppendChatMessage(accountID int64, dialogID string, msg ChatMessage) error {
	if msg.Text == "" {
		return nil
	}
	chatMsgMu.Lock()
	defer chatMsgMu.Unlock()

	path := chatMsgsPath(accountID, dialogID)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create chat_msgs dir: %w", err)
	}

	var msgs []ChatMessage
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &msgs)
	}

	msgs = append(msgs, msg)
	// Keep latest maxChatMessages (tail).
	if len(msgs) > maxChatMessages {
		msgs = msgs[len(msgs)-maxChatMessages:]
	}

	data, err := json.MarshalIndent(msgs, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ListChatMessages returns stored messages for a dialog (oldest first, max 2000).
func ListChatMessages(accountID int64, dialogID string) ([]ChatMessage, error) {
	data, err := os.ReadFile(chatMsgsPath(accountID, dialogID))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read chat msgs: %w", err)
	}
	var msgs []ChatMessage
	if err := json.Unmarshal(data, &msgs); err != nil {
		return nil, fmt.Errorf("parse chat msgs: %w", err)
	}
	// Sort by Date ascending (oldest first) for chat display.
	sort.Slice(msgs, func(i, j int) bool { return msgs[i].Date < msgs[j].Date })
	return msgs, nil
}

// DeleteChatMsgsForAccount removes all chat message files for an account.
func DeleteChatMsgsForAccount(accountID int64) {
	dir := filepath.Join(chatMsgsDir(), fmt.Sprintf("%d", accountID))
	_ = os.RemoveAll(dir)
}
