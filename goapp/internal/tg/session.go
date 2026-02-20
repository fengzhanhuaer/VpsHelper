package tg

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/gotd/td/session"
)

type LoginFlowSessionStorage struct {
	dbConn *sql.DB
	flowID int64
}

func NewLoginFlowSessionStorage(dbConn *sql.DB, flowID int64) *LoginFlowSessionStorage {
	return &LoginFlowSessionStorage{dbConn: dbConn, flowID: flowID}
}

func (s *LoginFlowSessionStorage) LoadSession(ctx context.Context) ([]byte, error) {
	var sessionText string
	err := s.dbConn.QueryRowContext(
		ctx,
		"SELECT session_text FROM tg_login_flows WHERE id = ?",
		s.flowID,
	).Scan(&sessionText)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, session.ErrNotFound
		}
		return nil, fmt.Errorf("load session: %w", err)
	}
	if sessionText == "" {
		return nil, session.ErrNotFound
	}
	data, err := decodeSessionText(sessionText)
	if err != nil {
		return nil, fmt.Errorf("decode session: %w", err)
	}
	// Auto-migrate legacy session text to the current canonical format.
	if shouldRewriteSessionText(sessionText, data) {
		_ = s.StoreSession(ctx, data)
	}
	return data, nil
}

func (s *LoginFlowSessionStorage) StoreSession(ctx context.Context, data []byte) error {
	encoded := encodeSessionText(data)
	if _, err := s.dbConn.ExecContext(
		ctx,
		"UPDATE tg_login_flows SET session_text = ? WHERE id = ?",
		encoded,
		s.flowID,
	); err != nil {
		return fmt.Errorf("store session: %w", err)
	}
	return nil
}
