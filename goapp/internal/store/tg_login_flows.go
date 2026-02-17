package store

import (
    "database/sql"
    "fmt"
    "time"
)

type LoginFlow struct {
    ID            int64
    Owner         string
    Phone         string
    AccountName   string
    SessionText   string
    PhoneCodeHash string
    CreatedAt     string
}

func CreateLoginFlow(dbConn *sql.DB, owner, phone, accountName string) (int64, error) {
    createdAt := time.Now().Format(time.RFC3339)
    res, err := dbConn.Exec(
        "INSERT INTO tg_login_flows (owner, phone, account_name, session_text, phone_code_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        owner,
        phone,
        accountName,
        "",
        "",
        createdAt,
    )
    if err != nil {
        return 0, fmt.Errorf("create login flow: %w", err)
    }
    id, err := res.LastInsertId()
    if err != nil {
        return 0, fmt.Errorf("get login flow id: %w", err)
    }
    return id, nil
}

func GetLoginFlow(dbConn *sql.DB, id int64, owner string) (*LoginFlow, error) {
    row := dbConn.QueryRow(
        "SELECT id, owner, phone, account_name, session_text, phone_code_hash, created_at FROM tg_login_flows WHERE id = ? AND owner = ?",
        id,
        owner,
    )

    flow := &LoginFlow{}
    if err := row.Scan(
        &flow.ID,
        &flow.Owner,
        &flow.Phone,
        &flow.AccountName,
        &flow.SessionText,
        &flow.PhoneCodeHash,
        &flow.CreatedAt,
    ); err != nil {
        return nil, fmt.Errorf("get login flow: %w", err)
    }
    return flow, nil
}

func UpdateLoginFlowCodeHash(dbConn *sql.DB, id int64, codeHash string) error {
    if _, err := dbConn.Exec(
        "UPDATE tg_login_flows SET phone_code_hash = ? WHERE id = ?",
        codeHash,
        id,
    ); err != nil {
        return fmt.Errorf("update login flow code hash: %w", err)
    }
    return nil
}

func UpdateLoginFlowSession(dbConn *sql.DB, id int64, sessionText string) error {
    if _, err := dbConn.Exec(
        "UPDATE tg_login_flows SET session_text = ? WHERE id = ?",
        sessionText,
        id,
    ); err != nil {
        return fmt.Errorf("update login flow session: %w", err)
    }
    return nil
}

func DeleteLoginFlow(dbConn *sql.DB, id int64, owner string) error {
    if _, err := dbConn.Exec(
        "DELETE FROM tg_login_flows WHERE id = ? AND owner = ?",
        id,
        owner,
    ); err != nil {
        return fmt.Errorf("delete login flow: %w", err)
    }
    return nil
}
