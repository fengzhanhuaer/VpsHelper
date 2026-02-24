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
    "tg_auto_send_tasks",
    "tg_auto_reply_rules",
    "shell_shortcuts",
    "probe_nodes",
    "probe_tasks",
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
                    if table == "tg_accounts" {
                        cf.D1Query(ctx, accountID, dbID, "ALTER TABLE tg_accounts ADD COLUMN tg_user_id INTEGER DEFAULT 0;", nil)
                    }
                    continue
                }
            }
            return false, fmt.Sprintf("创建云端表失败(%s)：%s", table, msg)
        }
    }

    return true, "ok"
}

func BackupLocalToD1(ctx context.Context, cf Client, accountID, dbID string, local *sql.DB) (bool, string) {
    return BackupLocalToD1WithProgress(ctx, cf, accountID, dbID, local, nil)
}

// ProgressFunc receives (percent 0-100, message). Called after each table.
type ProgressFunc func(pct int, msg string)

// d1MaxParams is the safe bound-parameter limit per D1 query.
// Cloudflare D1 allows up to 100 parameters; we stay under that.
const d1MaxParams = 90

func BackupLocalToD1WithProgress(ctx context.Context, cf Client, accountID, dbID string, local *sql.DB, progress ProgressFunc) (bool, string) {
    ok, msg := EnsureSchema(ctx, cf, accountID, dbID, local)
    if !ok {
        return false, msg
    }

    total := len(TGTables)
    for idx, table := range TGTables {
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

        pct := func() int { return 40 + (idx+1)*55/total }

        if len(localRows) == 0 {
            if progress != nil {
                progress(pct(), fmt.Sprintf("表 %s：空表，已跳过 (%d/%d)", table, idx+1, total))
            }
            continue
        }

        // Build multi-row INSERT batches.
        // Max rows per batch = floor(d1MaxParams / len(cols)), at least 1.
        rowsPerBatch := d1MaxParams / len(cols)
        if rowsPerBatch < 1 {
            rowsPerBatch = 1
        }

        colNames := join(cols, ",")
        rowPlaceholder := "(" + join(makePlaceholders(len(cols)), ",") + ")"

        inserted := 0
        for start := 0; start < len(localRows); start += rowsPerBatch {
            end := start + rowsPerBatch
            if end > len(localRows) {
                end = len(localRows)
            }
            batch := localRows[start:end]

            // Build "VALUES (?,?,...), (?,?,...), ..."
            valueSets := make([]string, len(batch))
            params := make([]any, 0, len(batch)*len(cols))
            for r, row := range batch {
                valueSets[r] = rowPlaceholder
                params = append(params, row...)
            }
            sqlText := fmt.Sprintf("INSERT INTO %s (%s) VALUES %s",
                table, colNames, join(valueSets, ","))

            okIns, _, emsg := cf.D1Query(ctx, accountID, dbID, sqlText, params)
            if !okIns {
                return false, fmt.Sprintf("写入云端失败(%s)：%s", table, emsg)
            }
            inserted += len(batch)

            // Fire progress after every chunk to keep SSE alive.
            if progress != nil {
                progress(pct(), fmt.Sprintf("表 %s：已写入 %d/%d 行 (%d/%d)",
                    table, inserted, len(localRows), idx+1, total))
            }
        }
    }

    return true, "本地数据库已备份到云端 D1。"
}

func PullD1ToLocal(ctx context.Context, cf Client, accountID, dbID string, local *sql.DB) (bool, string) {
    return PullD1ToLocalWithProgress(ctx, cf, accountID, dbID, local, nil)
}

func PullD1ToLocalWithProgress(ctx context.Context, cf Client, accountID, dbID string, local *sql.DB, progress ProgressFunc) (bool, string) {
    ok, msg := EnsureSchema(ctx, cf, accountID, dbID, local)
    if !ok {
        return false, msg
    }

    total := len(TGTables)
    for idx, table := range TGTables {
        okSel, rows, emsg := cf.D1Query(ctx, accountID, dbID, "SELECT * FROM "+table, nil)
        if !okSel {
            return false, fmt.Sprintf("读取云端失败(%s)：%s", table, emsg)
        }

        if _, err := local.ExecContext(ctx, "DELETE FROM "+table); err != nil {
            return false, fmt.Sprintf("清空本地失败(%s)：%s", table, err)
        }

        if len(rows) == 0 {
            if progress != nil {
                pct := 15 + (idx+1)*80/total
                progress(pct, fmt.Sprintf("表 %s：云端为空，已跳过 (%d/%d)", table, idx+1, total))
            }
            continue
        }

        colOrder := tableColumns(local, table)
        if len(colOrder) == 0 {
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

        if progress != nil {
            pct := 15 + (idx+1)*80/total
            progress(pct, fmt.Sprintf("表 %s：已拉取 %d 行 (%d/%d)", table, len(rows), idx+1, total))
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

func makePlaceholders(n int) []string {
    ps := make([]string, n)
    for i := range ps {
        ps[i] = "?"
    }
    return ps
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

// SyncDropExtraD1Tables drops every table in D1 that is NOT present in
// localTableNames. This keeps the cloud schema in sync with the local DB.
// Returns the list of dropped table names and any hard error encountered.
func SyncDropExtraD1Tables(ctx context.Context, cf Client, accountID, dbID string, localTableNames []string) (dropped []string, err error) {
    // Build local set
    localSet := make(map[string]bool, len(localTableNames))
    for _, t := range localTableNames {
        localSet[t] = true
    }

    // Query D1 for all user tables
    ok, rows, msg := cf.D1Query(ctx, accountID, dbID,
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'", nil)
    if !ok {
        return nil, fmt.Errorf("list D1 tables: %s", msg)
    }

    for _, row := range rows {
        name, _ := row["name"].(string)
        if name == "" || localSet[name] {
            continue // keep
        }
        // This table does not exist locally → drop it from D1
        okDrop, _, dropMsg := cf.D1Query(ctx, accountID, dbID,
            "DROP TABLE IF EXISTS "+name, nil)
        if !okDrop {
            // non-fatal: log and continue
            dropped = append(dropped, name+"(failed: "+dropMsg+")")
        } else {
            dropped = append(dropped, name)
        }
    }
    return dropped, nil
}
