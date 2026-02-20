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
	DialogTitle     string
	Message         string
	IntervalSeconds int
	JitterSeconds   int
	ScheduleType    string
	TimeOfDay       string
	Enabled         bool
	NextRunAt       string
	LastRunAt       string
	LastResult      string
	LastReply       string
	CreatedAt       string
	UpdatedAt       string
}

func ListAutoSendTasks(dbConn *sql.DB, owner string) ([]AutoSendTask, error) {
	rows, err := dbConn.Query(
		`SELECT t.id, t.owner, t.account_id, t.dialog_id, COALESCE(d.title, ''), t.message, t.interval_seconds, t.jitter_seconds, t.schedule_type, t.time_of_day,
               t.enabled, t.next_run_at, COALESCE(t.last_run_at, ''), COALESCE(t.last_result, ''), COALESCE(t.last_reply, ''), t.created_at, t.updated_at
          FROM tg_auto_send_tasks t
          LEFT JOIN tg_dialogs d
            ON d.account_id = t.account_id AND d.dialog_id = t.dialog_id
         WHERE t.owner = ?
         ORDER BY t.id DESC`,
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
			&t.DialogTitle,
			&t.Message,
			&t.IntervalSeconds,
			&t.JitterSeconds,
			&t.ScheduleType,
			&t.TimeOfDay,
			&enabledInt,
			&t.NextRunAt,
			&t.LastRunAt,
			&t.LastResult,
			&t.LastReply,
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

func GetAutoSendTaskByID(dbConn *sql.DB, owner string, taskID int64) (AutoSendTask, error) {
	var t AutoSendTask
	var enabledInt int
	err := dbConn.QueryRow(
		`SELECT id, owner, account_id, dialog_id, message, interval_seconds, jitter_seconds, schedule_type, time_of_day,
               enabled, next_run_at, COALESCE(last_run_at, ''), COALESCE(last_result, ''), COALESCE(last_reply, ''), created_at, updated_at
          FROM tg_auto_send_tasks
         WHERE owner = ? AND id = ?`,
		owner,
		taskID,
	).Scan(
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
		&t.LastReply,
		&t.CreatedAt,
		&t.UpdatedAt,
	)
	if err != nil {
		return AutoSendTask{}, fmt.Errorf("get auto send task: %w", err)
	}
	t.Enabled = enabledInt == 1
	return t, nil
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

func UpdateAutoSendTaskDialogID(dbConn *sql.DB, owner string, taskID int64, dialogID string) error {
	if _, err := dbConn.Exec(
		"UPDATE tg_auto_send_tasks SET dialog_id = ?, updated_at = ? WHERE id = ? AND owner = ?",
		dialogID,
		time.Now().Format(time.RFC3339),
		taskID,
		owner,
	); err != nil {
		return fmt.Errorf("update auto send dialog_id: %w", err)
	}
	return nil
}

func UpdateAutoSendAfterRun(dbConn *sql.DB, owner string, taskID int64, nextRunAt, lastRunAt, lastResult, lastReply string) error {
	if _, err := dbConn.Exec(
		"UPDATE tg_auto_send_tasks SET next_run_at = ?, last_run_at = ?, last_result = ?, last_reply = ?, updated_at = ? WHERE id = ? AND owner = ?",
		nextRunAt,
		lastRunAt,
		lastResult,
		lastReply,
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
               enabled, next_run_at, COALESCE(last_run_at, ''), COALESCE(last_result, ''), COALESCE(last_reply, ''), created_at, updated_at
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
			&t.LastReply,
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
