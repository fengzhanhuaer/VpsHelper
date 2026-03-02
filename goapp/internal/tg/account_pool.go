package tg

import (
	"sync"

	"github.com/gotd/td/tg"
)

// accountPoolKey identifies a unique TG account.
type accountPoolKey struct {
	owner     string
	accountID int64
}

var (
	poolMu   sync.RWMutex
	livePool = map[accountPoolKey]*tg.Client{}
)

// poolRegister stores a live API client for (owner, accountID).
// Called by runAutoReplyListener once the long-lived connection is established.
func poolRegister(owner string, accountID int64, api *tg.Client) {
	poolMu.Lock()
	livePool[accountPoolKey{owner, accountID}] = api
	poolMu.Unlock()
}

// poolUnregister removes the entry when the long-lived connection exits.
func poolUnregister(owner string, accountID int64) {
	poolMu.Lock()
	delete(livePool, accountPoolKey{owner, accountID})
	poolMu.Unlock()
}

// GetLiveAPI returns the live MTProto *tg.Client for (owner, accountID),
// or nil if no long-lived auto-reply connection is currently active.
// Callers should fall back to a short-lived connection when nil is returned.
func GetLiveAPI(owner string, accountID int64) *tg.Client {
	poolMu.RLock()
	api := livePool[accountPoolKey{owner, accountID}]
	poolMu.RUnlock()
	return api
}
