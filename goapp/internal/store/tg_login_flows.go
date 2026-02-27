package store

import (
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// LoginFlow holds in-progress Telegram auth data.
// It is kept entirely in memory; the data is intentionally ephemeral
// (Telegram phone_code_hash expires in ~5 minutes, so persistence
// across restarts is neither necessary nor useful).
type LoginFlow struct {
	ID            int64
	Owner         string
	Phone         string
	AccountName   string
	SessionText   string
	PhoneCodeHash string
	CreatedAt     string
}

// loginFlowStore is the process-global in-memory store for active login flows.
var loginFlowStore = struct {
	mu      sync.RWMutex
	counter atomic.Int64
	flows   map[int64]*LoginFlow
}{
	flows: make(map[int64]*LoginFlow),
}

// CreateLoginFlow creates a new in-flight login flow and returns its ID.
// The dbConn parameter is kept for signature compatibility but is not used.
func CreateLoginFlow(_ *sql.DB, owner, phone, accountName string) (int64, error) {
	id := loginFlowStore.counter.Add(1)
	flow := &LoginFlow{
		ID:          id,
		Owner:       owner,
		Phone:       phone,
		AccountName: accountName,
		CreatedAt:   time.Now().Format(time.RFC3339),
	}
	loginFlowStore.mu.Lock()
	loginFlowStore.flows[id] = flow
	loginFlowStore.mu.Unlock()
	return id, nil
}

// GetLoginFlow retrieves a login flow by ID and owner.
// The dbConn parameter is kept for signature compatibility but is not used.
func GetLoginFlow(_ *sql.DB, id int64, owner string) (*LoginFlow, error) {
	loginFlowStore.mu.RLock()
	flow, ok := loginFlowStore.flows[id]
	loginFlowStore.mu.RUnlock()
	if !ok || flow.Owner != owner {
		return nil, fmt.Errorf("get login flow: not found")
	}
	// Return a copy to avoid data races.
	cp := *flow
	return &cp, nil
}

// UpdateLoginFlowCodeHash updates the phone_code_hash field of a flow.
// The dbConn parameter is kept for signature compatibility but is not used.
func UpdateLoginFlowCodeHash(_ *sql.DB, id int64, codeHash string) error {
	loginFlowStore.mu.Lock()
	defer loginFlowStore.mu.Unlock()
	flow, ok := loginFlowStore.flows[id]
	if !ok {
		return fmt.Errorf("update login flow code hash: not found")
	}
	flow.PhoneCodeHash = codeHash
	return nil
}

// UpdateLoginFlowSession updates the session_text field of a flow.
// The dbConn parameter is kept for signature compatibility but is not used.
func UpdateLoginFlowSession(_ *sql.DB, id int64, sessionText string) error {
	loginFlowStore.mu.Lock()
	defer loginFlowStore.mu.Unlock()
	flow, ok := loginFlowStore.flows[id]
	if !ok {
		return fmt.Errorf("update login flow session: not found")
	}
	flow.SessionText = sessionText
	return nil
}

// DeleteLoginFlow removes the flow from memory (no error if already gone).
// The dbConn parameter is kept for signature compatibility but is not used.
func DeleteLoginFlow(_ *sql.DB, id int64, owner string) error {
	loginFlowStore.mu.Lock()
	defer loginFlowStore.mu.Unlock()
	if flow, ok := loginFlowStore.flows[id]; ok && flow.Owner == owner {
		delete(loginFlowStore.flows, id)
	}
	return nil
}

// GetLoginFlowSessionText returns the current session_text for the given flow.
// Used by tg.LoginFlowSessionStorage to implement SessionStorage.
func GetLoginFlowSessionText(id int64) (string, bool) {
	loginFlowStore.mu.RLock()
	defer loginFlowStore.mu.RUnlock()
	flow, ok := loginFlowStore.flows[id]
	if !ok {
		return "", false
	}
	return flow.SessionText, true
}

// SetLoginFlowSessionText overwrites the session_text for the given flow.
// Used by tg.LoginFlowSessionStorage to implement SessionStorage.
func SetLoginFlowSessionText(id int64, text string) bool {
	loginFlowStore.mu.Lock()
	defer loginFlowStore.mu.Unlock()
	flow, ok := loginFlowStore.flows[id]
	if !ok {
		return false
	}
	flow.SessionText = text
	return true
}
