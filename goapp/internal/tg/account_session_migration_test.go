package tg

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func buildTelethonStringSession() string {
	payload := make([]byte, 263)
	payload[0] = 2 // dc id
	copy(payload[1:5], []byte{149, 154, 167, 51})
	binary.BigEndian.PutUint16(payload[5:7], 443)
	for i := 7; i < len(payload); i++ {
		payload[i] = byte(i)
	}
	return "1" + base64.URLEncoding.EncodeToString(payload)
}

func TestAccountSessionStorage_AutoMigratesLegacyTelethonString(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`
		CREATE TABLE tg_accounts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			owner TEXT NOT NULL,
			account_name TEXT NOT NULL,
			session_text TEXT NOT NULL,
			created_at TEXT NOT NULL
		)
	`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}

	legacy := buildTelethonStringSession()
	_, err = db.Exec(
		"INSERT INTO tg_accounts (owner, account_name, session_text, created_at) VALUES (?, ?, ?, ?)",
		"u1",
		"a1",
		legacy,
		time.Now().Format(time.RFC3339),
	)
	if err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	s := NewAccountSessionStorage(db, "u1", 1)
	decoded, err := s.LoadSession(context.Background())
	if err != nil {
		t.Fatalf("load session: %v", err)
	}
	if len(decoded) == 0 {
		t.Fatal("decoded session should not be empty")
	}

	var saved string
	if err := db.QueryRow("SELECT session_text FROM tg_accounts WHERE id = 1").Scan(&saved); err != nil {
		t.Fatalf("query saved session: %v", err)
	}

	expected := encodeSessionText(decoded)
	if saved != expected {
		t.Fatalf("session text was not migrated to canonical format")
	}
}
