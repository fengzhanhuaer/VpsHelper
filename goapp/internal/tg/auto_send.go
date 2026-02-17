package tg

import (
	"context"
	"database/sql"
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

	settings, err := store.GetSettings(dbConn, []string{"telegram_api_id", "telegram_api_hash", "tg_all_proxy"})
	if err != nil {
		return
	}
	apiIDText := strings.TrimSpace(settings["telegram_api_id"])
	apiHash := strings.TrimSpace(settings["telegram_api_hash"])
	allProxy := strings.TrimSpace(settings["tg_all_proxy"])
	if apiIDText == "" || apiHash == "" {
		return
	}

	apiID, err := parseInt(apiIDText)
	if err != nil {
		return
	}

	rand.Seed(time.Now().UnixNano())

	for _, t := range tasks {
		lastRun := time.Now().Format(time.RFC3339)
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		errMsg := "ok"

		storage := NewAccountSessionStorage(dbConn, t.Owner, t.AccountID)
		opts, err := buildOptions(storage, allProxy)
		if err != nil {
			errMsg = "client options error"
			cancel()
			_ = store.UpdateAutoSendAfterRun(dbConn, t.Owner, t.ID, nextRunAt(now, t), lastRun, errMsg)
			continue
		}

		client := telegram.NewClient(apiID, apiHash, opts)
		err = client.Run(ctx, func(ctx context.Context) error {
			return SendMessageToUsername(ctx, client, t.DialogID, t.Message)
		})
		if err != nil {
			errMsg = err.Error()
		}
		cancel()

		next := nextRunAt(now, t)
		_ = store.UpdateAutoSendAfterRun(dbConn, t.Owner, t.ID, next, lastRun, truncate(errMsg, 500))
	}
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
