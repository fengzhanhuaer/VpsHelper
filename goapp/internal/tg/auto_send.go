package tg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gotd/td/telegram"

	"vpshelper-go/internal/store"
)

var autoSendRunning atomic.Bool

func StartAutoSend(ctx context.Context, dbConn *sql.DB) {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runAutoSendTick(dbConn)
			}
		}
	}()
}

type autoSendConfig struct {
	apiID    int
	apiHash  string
	allProxy string
}

func RunAutoSendTaskNow(ctx context.Context, dbConn *sql.DB, owner string, taskID int64) (bool, string) {
	task, err := store.GetAutoSendTaskByID(dbConn, owner, taskID)
	if err != nil {
		return false, "task not found"
	}

	cfg, err := loadAutoSendConfig(dbConn)
	if err != nil {
		return false, err.Error()
	}

	runAt := time.Now()
	lastRun := runAt.Format(time.RFC3339)
	if ctx == nil {
		ctx = context.Background()
	}
	callCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	errMsg, resolvedDialogID := runAutoSendTask(callCtx, dbConn, task, cfg)
	cancel()
	if resolvedDialogID != "" && resolvedDialogID != strings.TrimSpace(task.DialogID) {
		_ = store.UpdateAutoSendTaskDialogID(dbConn, task.Owner, task.ID, resolvedDialogID)
		task.DialogID = resolvedDialogID
	}

	_ = store.UpdateAutoSendAfterRun(dbConn, task.Owner, task.ID, nextRunAt(runAt, task), lastRun, truncate(errMsg, 500))
	if errMsg != "ok" {
		return false, errMsg
	}
	return true, "ok"
}

func runAutoSendTick(dbConn *sql.DB) {
	if !autoSendRunning.CompareAndSwap(false, true) {
		return
	}
	defer autoSendRunning.Store(false)

	now := time.Now()
	nowText := now.Format(time.RFC3339)
	tasks, err := store.ListDueAutoSendTasks(dbConn, nowText)
	if err != nil {
		return
	}
	if len(tasks) == 0 {
		return
	}

	cfg, err := loadAutoSendConfig(dbConn)
	if err != nil {
		return
	}

	rand.Seed(time.Now().UnixNano())

	for _, t := range tasks {
		runAt := time.Now()
		lastRun := runAt.Format(time.RFC3339)
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		errMsg, resolvedDialogID := runAutoSendTask(ctx, dbConn, t, cfg)
		cancel()
		if resolvedDialogID != "" && resolvedDialogID != strings.TrimSpace(t.DialogID) {
			_ = store.UpdateAutoSendTaskDialogID(dbConn, t.Owner, t.ID, resolvedDialogID)
			t.DialogID = resolvedDialogID
		}

		next := nextRunAt(runAt, t)
		_ = store.UpdateAutoSendAfterRun(dbConn, t.Owner, t.ID, next, lastRun, truncate(errMsg, 500))
	}
}

func loadAutoSendConfig(dbConn *sql.DB) (autoSendConfig, error) {
	settings, err := store.GetSettings(dbConn, []string{"telegram_api_id", "telegram_api_hash", "tg_all_proxy"})
	if err != nil {
		return autoSendConfig{}, err
	}
	apiIDText := strings.TrimSpace(settings["telegram_api_id"])
	apiHash := strings.TrimSpace(settings["telegram_api_hash"])
	allProxy := strings.TrimSpace(settings["tg_all_proxy"])
	if apiIDText == "" || apiHash == "" {
		return autoSendConfig{}, errors.New("telegram api settings missing")
	}

	apiID, err := parseInt(apiIDText)
	if err != nil {
		return autoSendConfig{}, err
	}

	return autoSendConfig{apiID: apiID, apiHash: apiHash, allProxy: allProxy}, nil
}

func runAutoSendTask(ctx context.Context, dbConn *sql.DB, t store.AutoSendTask, cfg autoSendConfig) (string, string) {
	storage := NewAccountSessionStorage(dbConn, t.Owner, t.AccountID)
	opts, err := buildOptions(storage, cfg.allProxy)
	if err != nil {
		return "client options error", ""
	}

	client := telegram.NewClient(cfg.apiID, cfg.apiHash, opts)
	resolvedDialogID := ""
	err = client.Run(ctx, func(ctx context.Context) error {
		usedDialogID, err := SendMessageToTarget(ctx, client, t.DialogID, t.Message)
		if err != nil {
			return err
		}
		resolvedDialogID = strings.TrimSpace(usedDialogID)
		return nil
	})
	if err != nil {
		return err.Error(), resolvedDialogID
	}
	if normalized, ok := NormalizeDialogID(resolvedDialogID); ok {
		resolvedDialogID = normalized
	}
	return "ok", resolvedDialogID
}

func buildOptions(storage telegram.SessionStorage, allProxy string) (telegram.Options, error) {
	// Reuse login option builder.
	return newTelegramOptions(storage, true, allProxy)
}

func parseInt(v string) (int, error) {
	var n int
	_, err := fmt.Sscanf(v, "%d", &n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func nextRunAt(now time.Time, t store.AutoSendTask) string {
	jitter := 0
	if t.JitterSeconds > 0 {
		jitter = rand.Intn(t.JitterSeconds + 1)
	}

	schedule := strings.TrimSpace(t.ScheduleType)
	if schedule == "" {
		schedule = "interval"
	}

	switch schedule {
	case "daily":
		hh, mm, ok := parseHHMM(t.TimeOfDay)
		if !ok {
			return now.Add(time.Duration(t.IntervalSeconds) * time.Second).Add(time.Duration(jitter) * time.Second).Format(time.RFC3339)
		}
		next := time.Date(now.Year(), now.Month(), now.Day(), hh, mm, 0, 0, now.Location())
		if !next.After(now) {
			next = next.Add(24 * time.Hour)
		}
		next = next.Add(time.Duration(jitter) * time.Second)
		return next.Format(time.RFC3339)
	default:
		interval := t.IntervalSeconds
		if interval <= 0 {
			interval = 3600
		}
		return now.Add(time.Duration(interval)*time.Second + time.Duration(jitter)*time.Second).Format(time.RFC3339)
	}
}

func parseHHMM(v string) (hh int, mm int, ok bool) {
	v = strings.TrimSpace(v)
	tm, err := time.Parse("15:04", v)
	if err != nil {
		return 0, 0, false
	}
	return tm.Hour(), tm.Minute(), true
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max]
}
