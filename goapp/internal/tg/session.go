package tg

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/gotd/td/session"

	"vpshelper-go/internal/store"
)

// LoginFlowSessionStorage implements telegram.SessionStorage backed by the
// in-memory LoginFlow store instead of the SQLite database.
// The dbConn field is retained for signature compatibility with
// NewLoginFlowSessionStorage callers but is not used.
type LoginFlowSessionStorage struct {
	dbConn *sql.DB
	flowID int64
}

func NewLoginFlowSessionStorage(dbConn *sql.DB, flowID int64) *LoginFlowSessionStorage {
	return &LoginFlowSessionStorage{dbConn: dbConn, flowID: flowID}
}

func (s *LoginFlowSessionStorage) LoadSession(_ context.Context) ([]byte, error) {
	text, ok := store.GetLoginFlowSessionText(s.flowID)
	if !ok || text == "" {
		return nil, session.ErrNotFound
	}
	data, err := decodeSessionText(text)
	if err != nil {
		return nil, fmt.Errorf("decode session: %w", err)
	}
	// Auto-migrate legacy session encoding if needed.
	if shouldRewriteSessionText(text, data) {
		_ = s.StoreSession(context.Background(), data)
	}
	return data, nil
}

func (s *LoginFlowSessionStorage) StoreSession(_ context.Context, data []byte) error {
	encoded := encodeSessionText(data)
	if !store.SetLoginFlowSessionText(s.flowID, encoded) {
		return fmt.Errorf("store session: flow %d not found", s.flowID)
	}
	return nil
}
