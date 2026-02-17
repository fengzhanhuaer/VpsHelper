package tg

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"vpshelper-go/internal/store"
)

var autoSignRunning atomic.Bool

// StartAutoSign runs a daily sign routine if enabled.
//
// Controlled by app_settings:
// - tg_sign_auto_enabled: "1" to enable
// - tg_sign_auto_time: "HH:MM" (default 03:30)
// - tg_sign_auto_last_date: "YYYY-MM-DD" guard to run once per day
// - tg_sign_auto_last_result: last run summary
func StartAutoSign(ctx context.Context, dbConn *sql.DB) {
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runAutoSignOnce(dbConn)
			}
		}
	}()
}

func runAutoSignOnce(dbConn *sql.DB) {
	if !autoSignRunning.CompareAndSwap(false, true) {
		return
	}
	defer autoSignRunning.Store(false)

	keys := []string{"tg_sign_auto_enabled", "tg_sign_auto_time", "tg_sign_auto_last_date"}
	settings, err := store.GetSettings(dbConn, keys)
	if err != nil {
		return
	}
	if strings.TrimSpace(settings["tg_sign_auto_enabled"]) != "1" {
		return
	}

	backupTime := strings.TrimSpace(settings["tg_sign_auto_time"])
	if backupTime == "" {
		backupTime = "03:30"
	}
	stamp := time.Now().Format(time.RFC3339)

	hh, mm, ok := parseHHMM(backupTime)
	if !ok {
		_ = store.SetSetting(dbConn, "tg_sign_auto_last_date", time.Now().Format("2006-01-02"))
		_ = store.SetSetting(dbConn, "tg_sign_auto_last_result", fmt.Sprintf("%s 自动签到失败：tg_sign_auto_time 格式无效（期望 HH:MM）", stamp))
		return
	}

	now := time.Now()
	today := now.Format("2006-01-02")
	if settings["tg_sign_auto_last_date"] == today {
		return
	}

	target := time.Date(now.Year(), now.Month(), now.Day(), hh, mm, 0, 0, now.Location())
	if now.Before(target) {
		return
	}

	tasks, err := store.ListAllSignTasks(dbConn)
	if err != nil {
		_ = store.SetSetting(dbConn, "tg_sign_auto_last_date", today)
		_ = store.SetSetting(dbConn, "tg_sign_auto_last_result", fmt.Sprintf("%s 自动签到失败：读取任务失败", stamp))
		return
	}
	if len(tasks) == 0 {
		_ = store.SetSetting(dbConn, "tg_sign_auto_last_date", today)
		_ = store.SetSetting(dbConn, "tg_sign_auto_last_result", fmt.Sprintf("%s 自动签到：无任务", stamp))
		return
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s 自动签到：共 %d 条\n", stamp, len(tasks)))

	for _, t := range tasks {
		msg := strings.TrimSpace(t.Message)
		if msg == "" {
			msg = "签到"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		ok, res := SendOnce(ctx, dbConn, t.Owner, t.AccountID, t.DialogID, msg)
		cancel()
		state := "OK"
		if !ok {
			state = "FAIL"
		}
		sb.WriteString(fmt.Sprintf("- %s acc=%d target=%s: %s %s\n", t.Owner, t.AccountID, t.DialogID, state, res))
	}

	result := sb.String()
	result = truncate(result, 2000)
	_ = store.SetSetting(dbConn, "tg_sign_auto_last_date", today)
	_ = store.SetSetting(dbConn, "tg_sign_auto_last_result", result)
}
