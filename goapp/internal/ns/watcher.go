package ns

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"vpshelper-go/internal/store"
	"vpshelper-go/internal/tgbot"
)

// StartLotteryWatcher runs a background goroutine that checks pending lottery
// watches every minute and sends TG bot notifications when a watched user wins.
func StartLotteryWatcher(ctx context.Context, dbConn *sql.DB) {
	go func() {
		// Wait 10s after startup to let everything initialize.
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}

		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			runLotteryCheck(dbConn)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func runLotteryCheck(dbConn *sql.DB) {
	nowMs := time.Now().UnixMilli()

	// 1. Process pending watches whose draw_time has passed.
	pending, err := store.ListPendingLotteryWatches(nowMs)
	if err != nil {
		log.Printf("[lottery] list pending: %v", err)
		return
	}
	for _, w := range pending {
		checkAndSave(w)
	}

	// 2. Send TG notifications for won-but-unnotified watches (needs main dbConn for bot settings).
	unnotified, err := store.ListWonUnnotified()
	if err != nil {
		return
	}
	for _, w := range unnotified {
		sendWinNotification(dbConn, w)
	}
}

func checkAndSave(w store.LotteryWatch) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := CheckResult(ctx, w.URL, w.WatchUsername)
	if err != nil {
		log.Printf("[lottery] check id=%d (attempt %d): %v", w.ID, w.CheckCount+1, err)
		// Bump retry counter with backoff; will stop after 10 attempts.
		_ = store.BumpLotteryCheckCount(w.ID, w.CheckCount)
		return
	}

	winnersJSON := "[]"
	if len(result.Winners) > 0 {
		var parts []string
		for _, n := range result.Winners {
			parts = append(parts, `"`+n+`"`)
		}
		winnersJSON = "[" + strings.Join(parts, ",") + "]"
	}

	status := "drawn"
	if result.IsWon {
		status = "won"
	}
	_ = store.UpdateLotteryWatchResult(w.ID, status, winnersJSON, result.Note)
	log.Printf("[lottery] id=%d post=%s status=%s", w.ID, w.PostID, status)
}

func sendWinNotification(dbConn *sql.DB, w store.LotteryWatch) {
	settings, err := store.GetSettings(dbConn, []string{
		"tg_bot_token", "tg_bot_admin_id",
	})
	if err != nil {
		return
	}
	token := strings.TrimSpace(settings["tg_bot_token"])
	adminIDStr := strings.TrimSpace(settings["tg_bot_admin_id"])
	if token == "" || adminIDStr == "" {
		// No bot configured; mark as notified to avoid retrying endlessly.
		_ = store.MarkLotteryNotified(w.ID)
		return
	}
	adminID, err := strconv.ParseInt(adminIDStr, 10, 64)
	if err != nil {
		_ = store.MarkLotteryNotified(w.ID)
		return
	}

	msg := fmt.Sprintf(
		"🎉 抽奖中奖提醒！\n\n用户名: %s\n帖子: %s\n%s\n\n链接: %s",
		w.WatchUsername, w.PostID, w.Note, w.URL,
	)

	if err := tgbot.SendMessage(dbConn, adminID, msg); err != nil {
		log.Printf("[lottery] send notification id=%d: %v", w.ID, err)
		return
	}
	_ = store.MarkLotteryNotified(w.ID)
	log.Printf("[lottery] notification sent id=%d", w.ID)
}
