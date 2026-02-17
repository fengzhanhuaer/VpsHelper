package store

import (
	"database/sql"
	"fmt"
	"time"
)

type AutoSendTask struct {
	ID              int64
	Owner           string
	AccountID       int64
	DialogID        string
	Message         string
	IntervalSeconds int
	JitterSeconds   int
	ScheduleType    string
	TimeOfDay       string
	Enabled         bool
	NextRunAt       string
	LastRunAt       string
	LastResult      string
	CreatedAt       string
	UpdatedAt       string
}

func ListAutoSendTasks(dbConn *sql.DB, owner string) ([]AutoSendTask, error) {
	rows, err := dbConn.Query(
		`SELECT id, owner, account_id, dialog_id, message, interval_seconds, jitter_seconds, schedule_type, time_of_day,
               enabled, next_run_at, COALESCE(last_run_at, ''), COALESCE(last_result, ''), created_at, updated_at
          FROM tg_auto_send_tasks
         WHERE owner = ?
         ORDER BY id DESC`,
		owner,
	)
	if err != nil {
		return nil, fmt.Errorf("list auto send tasks: %w", err)
	}
	defer rows.Close()

	var out []AutoSendTask
	for rows.Next() {
		var t AutoSendTask
		var enabledInt int
		if err := rows.Scan(
			&t.ID,
			&t.Owner,
			&t.AccountID,
			&t.DialogID,
			&t.Message,
			&t.IntervalSeconds,
			&t.JitterSeconds,
			&t.ScheduleType,
			&t.TimeOfDay,
			&enabledInt,
			&t.NextRunAt,
			&t.LastRunAt,
			&t.LastResult,
			&t.CreatedAt,
			&t.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan auto send task: %w", err)
		}
		t.Enabled = enabledInt == 1
		out = append(out, t)
	}
	return out, nil
}

func CreateAutoSendTask(dbConn *sql.DB, owner string, accountID int64, dialogID, message string, intervalSeconds, jitterSeconds int, scheduleType, timeOfDay string, enabled bool, nextRunAt string) error {
	stamp := time.Now().Format(time.RFC3339)
	en := 0
	if enabled {
		en = 1
	}
	if scheduleType == "" {
		scheduleType = "interval"
	}
	if nextRunAt == "" {
		nextRunAt = stamp
	}
	_, err := dbConn.Exec(
		`INSERT INTO tg_auto_send_tasks (owner, account_id, dialog_id, message, interval_seconds, jitter_seconds, schedule_type, time_of_day,
                                      enabled, next_run_at, last_run_at, last_result, last_reply, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?)`,
		owner,
		accountID,
		dialogID,
		message,
		intervalSeconds,
		jitterSeconds,
		scheduleType,
		timeOfDay,
		en,
		nextRunAt,
		stamp,
		stamp,
	)
	if err != nil {
		return fmt.Errorf("create auto send task: %w", err)
	}
	return nil
}

func DeleteAutoSendTask(dbConn *sql.DB, owner string, taskID int64) error {
	if _, err := dbConn.Exec("DELETE FROM tg_auto_send_tasks WHERE id = ? AND owner = ?", taskID, owner); err != nil {
		return fmt.Errorf("delete auto send task: %w", err)
	}
	return nil
}

func SetAutoSendTaskNextRunAt(dbConn *sql.DB, owner string, taskID int64, nextRunAt string) error {
	if _, err := dbConn.Exec(
		"UPDATE tg_auto_send_tasks SET next_run_at = ?, updated_at = ? WHERE id = ? AND owner = ?",
		nextRunAt,
		time.Now().Format(time.RFC3339),
		taskID,
		owner,
	); err != nil {
		return fmt.Errorf("set auto send next_run_at: %w", err)
	}
	return nil
}

func SetAutoSendTaskEnabled(dbConn *sql.DB, owner string, taskID int64, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	if _, err := dbConn.Exec("UPDATE tg_auto_send_tasks SET enabled = ?, updated_at = ? WHERE id = ? AND owner = ?", v, time.Now().Format(time.RFC3339), taskID, owner); err != nil {
		return fmt.Errorf("set auto send enabled: %w", err)
	}
	return nil
}

func UpdateAutoSendAfterRun(dbConn *sql.DB, owner string, taskID int64, nextRunAt, lastRunAt, lastResult string) error {
	if _, err := dbConn.Exec(
		"UPDATE tg_auto_send_tasks SET next_run_at = ?, last_run_at = ?, last_result = ?, updated_at = ? WHERE id = ? AND owner = ?",
		nextRunAt,
		lastRunAt,
		lastResult,
		time.Now().Format(time.RFC3339),
		taskID,
		owner,
	); err != nil {
		return fmt.Errorf("update auto send after run: %w", err)
	}
	return nil
}

func ListDueAutoSendTasks(dbConn *sql.DB, nowRFC3339 string) ([]AutoSendTask, error) {
	rows, err := dbConn.Query(
		`SELECT id, owner, account_id, dialog_id, message, interval_seconds, jitter_seconds, schedule_type, time_of_day,
               enabled, next_run_at, COALESCE(last_run_at, ''), COALESCE(last_result, ''), created_at, updated_at
          FROM tg_auto_send_tasks
         WHERE enabled = 1 AND next_run_at <= ?
         ORDER BY next_run_at ASC
         LIMIT 50`,
		nowRFC3339,
	)
	if err != nil {
		return nil, fmt.Errorf("list due auto send tasks: %w", err)
	}
	defer rows.Close()

	var out []AutoSendTask
	for rows.Next() {
		var t AutoSendTask
		var enabledInt int
		if err := rows.Scan(
			&t.ID,
			&t.Owner,
			&t.AccountID,
			&t.DialogID,
			&t.Message,
			&t.IntervalSeconds,
			&t.JitterSeconds,
			&t.ScheduleType,
			&t.TimeOfDay,
			&enabledInt,
			&t.NextRunAt,
			&t.LastRunAt,
			&t.LastResult,
			&t.CreatedAt,
			&t.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan due auto send task: %w", err)
		}
		t.Enabled = enabledInt == 1
		out = append(out, t)
	}
	return out, nil
}
