package d1

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"vpshelper-go/internal/store"
)

func StartAutoBackup(ctx context.Context, dbConn *sql.DB) {
	ticker := time.NewTicker(60 * time.Second)

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runOnce(dbConn)
			}
		}
	}()
}

func runOnce(dbConn *sql.DB) {
	keys := []string{
		"db_auto_backup_enabled",
		"db_auto_backup_time",
		"db_auto_backup_last_date",
		"cf_api_token",
		"cf_account_id",
		"cf_d1_database_id",
	}

	settings, err := store.GetSettings(dbConn, keys)
	if err != nil {
		return
	}

	if settings["db_auto_backup_enabled"] != "1" {
		return
	}

	backupTime := settings["db_auto_backup_time"]
	if backupTime == "" {
		backupTime = "03:30"
	}

	hh, mm, ok := parseHHMM(backupTime)
	if !ok {
		stamp := time.Now().Format(time.RFC3339)
		_ = store.SetSetting(dbConn, "db_auto_backup_last_date", time.Now().Format("2006-01-02"))
		_ = store.SetSetting(dbConn, "db_auto_backup_last_result", fmt.Sprintf("%s 自动备份失败：db_auto_backup_time 格式无效（期望 HH:MM）", stamp))
		return
	}

	now := time.Now()
	today := now.Format("2006-01-02")
	if settings["db_auto_backup_last_date"] == today {
		return
	}

	target := time.Date(now.Year(), now.Month(), now.Day(), hh, mm, 0, 0, now.Location())
	if now.Before(target) {
		return
	}

	token := settings["cf_api_token"]
	accountID := settings["cf_account_id"]
	dbID := settings["cf_d1_database_id"]

	stamp := time.Now().Format(time.RFC3339)

	if token == "" || accountID == "" || dbID == "" {
		_ = store.SetSetting(dbConn, "db_auto_backup_last_result", fmt.Sprintf("%s 自动备份失败：Cloudflare 配置不完整", stamp))
		_ = store.SetSetting(dbConn, "db_auto_backup_last_date", today)
		return
	}

	cf := Client{Token: token}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	okBak, msgBak := BackupLocalToD1(ctx, cf, accountID, dbID, dbConn)
	_ = store.SetSetting(dbConn, "db_auto_backup_last_date", today)
	_ = store.SetSetting(dbConn, "db_auto_backup_last_result", fmt.Sprintf("%s %s", stamp, msgBak))

	_ = okBak
}

func parseHHMM(v string) (hh int, mm int, ok bool) {
	if len(v) < 4 {
		return 0, 0, false
	}
	t, err := time.Parse("15:04", v)
	if err != nil {
		return 0, 0, false
	}
	return t.Hour(), t.Minute(), true
}
