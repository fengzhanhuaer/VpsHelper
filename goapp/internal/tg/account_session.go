package tg

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/gotd/td/session"
)

// AccountSessionStorage stores gotd session bytes in tg_accounts.session_text (base64 text).
//
// It is compatible with current schema and allows long-lived sessions for sending tasks.
type AccountSessionStorage struct {
	dbConn    *sql.DB
	owner     string
	accountID int64
}

func NewAccountSessionStorage(dbConn *sql.DB, owner string, accountID int64) *AccountSessionStorage {
	return &AccountSessionStorage{dbConn: dbConn, owner: owner, accountID: accountID}
}

func (s *AccountSessionStorage) LoadSession(ctx context.Context) ([]byte, error) {
	var sessionText string
	err := s.dbConn.QueryRowContext(
		ctx,
		"SELECT session_text FROM tg_accounts WHERE id = ? AND owner = ?",
		s.accountID,
		s.owner,
	).Scan(&sessionText)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, session.ErrNotFound
		}
		return nil, fmt.Errorf("load account session: %w", err)
	}
	if sessionText == "" {
		return nil, session.ErrNotFound
	}
	b, err := decodeSessionText(sessionText)
	if err != nil {
		return nil, fmt.Errorf("decode account session: %w", err)
	}
	return b, nil
}

func (s *AccountSessionStorage) StoreSession(ctx context.Context, data []byte) error {
	encoded := encodeSessionText(data)
	if _, err := s.dbConn.ExecContext(
		ctx,
		"UPDATE tg_accounts SET session_text = ? WHERE id = ? AND owner = ?",
		encoded,
		s.accountID,
		s.owner,
	); err != nil {
		return fmt.Errorf("store account session: %w", err)
	}
	return nil
}
