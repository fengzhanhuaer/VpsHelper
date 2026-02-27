package store

import (
	"database/sql"
	"fmt"
)

func HasUsers(dbConn *sql.DB) (bool, error) {
	var count int
	if err := dbConn.QueryRow("SELECT COUNT(1) FROM users").Scan(&count); err != nil {
		return false, fmt.Errorf("has users: %w", err)
	}
	return count > 0, nil
}

func CreateUser(dbConn *sql.DB, username, passwordHash string) error {
	_, err := dbConn.Exec(
		"INSERT INTO users (username, password_hash) VALUES (?, ?)",
		username,
		passwordHash,
	)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

func GetPasswordHash(dbConn *sql.DB, username string) (string, error) {
	var hash string
	err := dbConn.QueryRow(
		"SELECT password_hash FROM users WHERE username = ?",
		username,
	).Scan(&hash)
	if err != nil {
		return "", fmt.Errorf("get password hash: %w", err)
	}
	return hash, nil
}

func UpdatePasswordHash(dbConn *sql.DB, username, passwordHash string) error {
	_, err := dbConn.Exec(
		"UPDATE users SET password_hash = ? WHERE username = ?",
		passwordHash,
		username,
	)
	if err != nil {
		return fmt.Errorf("update password hash: %w", err)
	}
	return nil
}
