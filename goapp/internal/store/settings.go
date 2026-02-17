package store

import (
    "database/sql"
    "fmt"
)

func GetSettings(dbConn *sql.DB, keys []string) (map[string]string, error) {
    result := make(map[string]string)
    if len(keys) == 0 {
        return result, nil
    }

    placeholders := "?"
    args := make([]any, 0, len(keys))
    args = append(args, keys[0])
    for i := 1; i < len(keys); i++ {
        placeholders += ", ?"
        args = append(args, keys[i])
    }

    query := "SELECT key, value FROM app_settings WHERE key IN (" + placeholders + ")"
    rows, err := dbConn.Query(query, args...)
    if err != nil {
        return nil, fmt.Errorf("get settings: %w", err)
    }
    defer rows.Close()

    for rows.Next() {
        var key string
        var value string
        if err := rows.Scan(&key, &value); err != nil {
            return nil, fmt.Errorf("scan settings: %w", err)
        }
        result[key] = value
    }

    if err := rows.Err(); err != nil {
        return nil, fmt.Errorf("iterate settings: %w", err)
    }

    return result, nil
}

func SetSetting(dbConn *sql.DB, key, value string) error {
    _, err := dbConn.Exec(
        "INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)",
        key,
        value,
    )
    if err != nil {
        return fmt.Errorf("set setting: %w", err)
    }
    return nil
}
