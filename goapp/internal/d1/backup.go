package d1

import (
    "context"
    "database/sql"
    "fmt"
    "sort"
    "strings"
)

var TGTables = []string{
    "tg_accounts",
    "tg_dialogs",
    "tg_sign_tasks",
    "tg_auto_send_tasks",
    "tg_login_flows",
    "app_settings",
}

func EnsureSchema(ctx context.Context, cf Client, accountID, dbID string, local *sql.DB) (bool, string) {
    for _, table := range TGTables {
        var createSQL string
        err := local.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name = ?", table).Scan(&createSQL)
        if err != nil || createSQL == "" {
            continue
        }

        ok, _, msg := cf.D1Query(ctx, accountID, dbID, createSQL, nil)
        if !ok {
            lower := msg
            if lower != "" {
                // best-effort match
                if containsInsensitive(lower, "already exists") {
                    continue
                }
            }
            return false, fmt.Sprintf("创建云端表失败(%s)：%s", table, msg)
        }
    }

    return true, "ok"
}

func BackupLocalToD1(ctx context.Context, cf Client, accountID, dbID string, local *sql.DB) (bool, string) {
    ok, msg := EnsureSchema(ctx, cf, accountID, dbID, local)
    if !ok {
        return false, msg
    }

    for _, table := range TGTables {
        // Load all local rows.
        rows, err := local.QueryContext(ctx, "SELECT * FROM "+table)
        if err != nil {
            continue
        }

        cols, _ := rows.Columns()
        values := make([]any, len(cols))
        valuePtrs := make([]any, len(cols))
        for i := range valuePtrs {
            valuePtrs[i] = &values[i]
        }

        localRows := make([][]any, 0)
        for rows.Next() {
            if err := rows.Scan(valuePtrs...); err != nil {
                continue
            }
            one := make([]any, len(cols))
            copy(one, values)
            for i, v := range one {
                if b, ok := v.([]byte); ok {
                    one[i] = string(b)
                }
            }
            localRows = append(localRows, one)
        }
        rows.Close()

        okDel, _, emsg := cf.D1Query(ctx, accountID, dbID, "DELETE FROM "+table, nil)
        if !okDel {
            return false, fmt.Sprintf("清空云端表失败(%s)：%s", table, emsg)
        }

        if len(localRows) == 0 {
            continue
        }

        placeholders := make([]string, len(cols))
        for i := range placeholders {
            placeholders[i] = "?"
        }

        sqlText := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table, join(cols, ","), join(placeholders, ","))
        for _, row := range localRows {
            okIns, _, emsg := cf.D1Query(ctx, accountID, dbID, sqlText, row)
            if !okIns {
                return false, fmt.Sprintf("写入云端失败(%s)：%s", table, emsg)
            }
        }
    }

    return true, "本地数据库已备份到云端 D1。"
}

func PullD1ToLocal(ctx context.Context, cf Client, accountID, dbID string, local *sql.DB) (bool, string) {
    ok, msg := EnsureSchema(ctx, cf, accountID, dbID, local)
    if !ok {
        return false, msg
    }

    for _, table := range TGTables {
        okSel, rows, emsg := cf.D1Query(ctx, accountID, dbID, "SELECT * FROM "+table, nil)
        if !okSel {
            return false, fmt.Sprintf("读取云端失败(%s)：%s", table, emsg)
        }

        if _, err := local.ExecContext(ctx, "DELETE FROM "+table); err != nil {
            return false, fmt.Sprintf("清空本地失败(%s)：%s", table, err)
        }

        if len(rows) == 0 {
            continue
        }

        colOrder := tableColumns(local, table)
        if len(colOrder) == 0 {
            // fallback to keys of first row (sorted)
            for k := range rows[0] {
                colOrder = append(colOrder, k)
            }
            sort.Strings(colOrder)
        }

        placeholders := make([]string, len(colOrder))
        for i := range placeholders {
            placeholders[i] = "?"
        }
        sqlText := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table, join(colOrder, ","), join(placeholders, ","))

        for _, row := range rows {
            params := make([]any, 0, len(colOrder))
            for _, col := range colOrder {
                params = append(params, row[col])
            }
            if _, err := local.ExecContext(ctx, sqlText, params...); err != nil {
                return false, fmt.Sprintf("写入本地失败(%s)：%s", table, err)
            }
        }
    }

    return true, "云端 D1 数据已拉取到本地。"
}

func tableColumns(local *sql.DB, table string) []string {
    rows, err := local.Query("PRAGMA table_info(" + table + ")")
    if err != nil {
        return nil
    }
    defer rows.Close()

    type col struct {
        cid  int
        name string
    }
    cols := make([]col, 0)
    for rows.Next() {
        var cid int
        var name string
        var ctype string
        var notnull int
        var dflt any
        var pk int
        _ = rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk)
        if name != "" {
            cols = append(cols, col{cid: cid, name: name})
        }
    }

    sort.Slice(cols, func(i, j int) bool { return cols[i].cid < cols[j].cid })
    out := make([]string, 0, len(cols))
    for _, c := range cols {
        out = append(out, c.name)
    }
    return out
}

func join(items []string, sep string) string {
    if len(items) == 0 {
        return ""
    }
    out := items[0]
    for i := 1; i < len(items); i++ {
        out += sep + items[i]
    }
    return out
}

func containsInsensitive(s, sub string) bool {
    if sub == "" {
        return true
    }
    return (len(s) >= len(sub)) && (indexInsensitive(s, sub) >= 0)
}

func indexInsensitive(s, sub string) int {
    // naive ASCII-ish match is fine for error messages.
    ls := strings.ToLower(s)
    lsub := strings.ToLower(sub)
    return strings.Index(ls, lsub)
}
