package store

import (
	"database/sql"
	"fmt"
	"time"
)

// AutoSendTask is self-contained: it carries the session and API credentials
// needed to execute independently, without querying tg_accounts or app_settings.
type AutoSendTask struct {
	ID              int64
	Owner           string
	AccountID       int64  // kept for reference / display; not used at runtime
	AccountName     string // display label
	DialogID        string
	DialogTitle     string // joined at list time, not stored
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
	// Embedded credentials — the task is self-contained at runtime.
	SessionText string
	APIID       string
	APIHash     string
	AllProxy    string
}

func scanAutoSendTask(row interface{ Scan(...any) error }) (AutoSendTask, error) {
	var t AutoSendTask
	var enabledInt int
	if err := row.Scan(
		&t.ID, &t.Owner, &t.AccountID, &t.AccountName,
		&t.DialogID, &t.DialogTitle, &t.Message,
		&t.IntervalSeconds, &t.JitterSeconds, &t.ScheduleType, &t.TimeOfDay,
		&enabledInt, &t.NextRunAt,
		&t.LastRunAt, &t.LastResult, &t.LastReply,
		&t.CreatedAt, &t.UpdatedAt,
		&t.SessionText, &t.APIID, &t.APIHash, &t.AllProxy,
	); err != nil {
		return AutoSendTask{}, err
	}
	t.Enabled = enabledInt == 1
	return t, nil
}

func ListAutoSendTasks(dbConn *sql.DB, owner string) ([]AutoSendTask, error) {
	rows, err := dbConn.Query(
		`SELECT t.id, t.owner, t.account_id, COALESCE(t.account_name,''),
                t.dialog_id, '', t.message,
                t.interval_seconds, t.jitter_seconds, t.schedule_type, COALESCE(t.time_of_day,''),
                t.enabled, t.next_run_at,
                COALESCE(t.last_run_at,''), COALESCE(t.last_result,''), COALESCE(t.last_reply,''),
                t.created_at, t.updated_at,
                COALESCE(t.session_text,''), COALESCE(t.api_id,''), COALESCE(t.api_hash,''), COALESCE(t.all_proxy,'')
           FROM tg_auto_send_tasks t
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
		t, err := scanAutoSendTask(rows)
		if err != nil {
			return nil, fmt.Errorf("scan auto send task: %w", err)
		}
		out = append(out, t)
	}
	return out, nil
}

func GetAutoSendTaskByID(dbConn *sql.DB, owner string, taskID int64) (AutoSendTask, error) {
	row := dbConn.QueryRow(
		`SELECT t.id, t.owner, t.account_id, COALESCE(t.account_name,''),
                t.dialog_id, '', t.message,
                t.interval_seconds, t.jitter_seconds, t.schedule_type, COALESCE(t.time_of_day,''),
                t.enabled, t.next_run_at,
                COALESCE(t.last_run_at,''), COALESCE(t.last_result,''), COALESCE(t.last_reply,''),
                t.created_at, t.updated_at,
                COALESCE(t.session_text,''), COALESCE(t.api_id,''), COALESCE(t.api_hash,''), COALESCE(t.all_proxy,'')
           FROM tg_auto_send_tasks t
          WHERE t.owner = ? AND t.id = ?`,
		owner, taskID,
	)
	t, err := scanAutoSendTask(row)
	if err != nil {
		return AutoSendTask{}, fmt.Errorf("get auto send task: %w", err)
	}
	return t, nil
}

// ListDueAutoSendTasks returns tasks whose next_run_at is <= nowRFC3339 and are enabled.
// The LEFT JOIN with tg_dialogs is omitted here to avoid extra overhead in the hot path;
// DialogTitle will be empty (it's unused at execution time).
func ListDueAutoSendTasks(dbConn *sql.DB, nowRFC3339 string) ([]AutoSendTask, error) {
	rows, err := dbConn.Query(
		`SELECT t.id, t.owner, t.account_id, COALESCE(t.account_name,''),
                t.dialog_id, '', t.message,
                t.interval_seconds, t.jitter_seconds, t.schedule_type, COALESCE(t.time_of_day,''),
                t.enabled, t.next_run_at,
                COALESCE(t.last_run_at,''), COALESCE(t.last_result,''), COALESCE(t.last_reply,''),
                t.created_at, t.updated_at,
                COALESCE(t.session_text,''), COALESCE(t.api_id,''), COALESCE(t.api_hash,''), COALESCE(t.all_proxy,'')
           FROM tg_auto_send_tasks t
          WHERE t.enabled = 1 AND t.next_run_at <= ?
          ORDER BY t.next_run_at ASC
          LIMIT 50`,
		nowRFC3339,
	)
	if err != nil {
		return nil, fmt.Errorf("list due auto send tasks: %w", err)
	}
	defer rows.Close()

	var out []AutoSendTask
	for rows.Next() {
		t, err := scanAutoSendTask(rows)
		if err != nil {
			return nil, fmt.Errorf("scan due auto send task: %w", err)
		}
		out = append(out, t)
	}
	return out, nil
}

func CreateAutoSendTask(dbConn *sql.DB, owner string, accountID int64, accountName, dialogID, message string,
	intervalSeconds, jitterSeconds int, scheduleType, timeOfDay string, enabled bool, nextRunAt,
	sessionText, apiID, apiHash, allProxy string) error {

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
		`INSERT INTO tg_auto_send_tasks
            (owner, account_id, account_name, dialog_id, message, interval_seconds, jitter_seconds,
             schedule_type, time_of_day, enabled, next_run_at, last_run_at, last_result, last_reply,
             created_at, updated_at, session_text, api_id, api_hash, all_proxy)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?, ?, ?, ?, ?)`,
		owner, accountID, accountName, dialogID, message, intervalSeconds, jitterSeconds,
		scheduleType, timeOfDay, en, nextRunAt,
		stamp, stamp, sessionText, apiID, apiHash, allProxy,
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
	DeleteSendHistoryFile(taskID)
	return nil
}

func SetAutoSendTaskNextRunAt(dbConn *sql.DB, owner string, taskID int64, nextRunAt string) error {
	if _, err := dbConn.Exec(
		"UPDATE tg_auto_send_tasks SET next_run_at = ?, updated_at = ? WHERE id = ? AND owner = ?",
		nextRunAt, time.Now().Format(time.RFC3339), taskID, owner,
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
	if _, err := dbConn.Exec(
		"UPDATE tg_auto_send_tasks SET enabled = ?, updated_at = ? WHERE id = ? AND owner = ?",
		v, time.Now().Format(time.RFC3339), taskID, owner,
	); err != nil {
		return fmt.Errorf("set auto send enabled: %w", err)
	}
	return nil
}

func UpdateAutoSendTaskDialogID(dbConn *sql.DB, owner string, taskID int64, dialogID string) error {
	if _, err := dbConn.Exec(
		"UPDATE tg_auto_send_tasks SET dialog_id = ?, updated_at = ? WHERE id = ? AND owner = ?",
		dialogID, time.Now().Format(time.RFC3339), taskID, owner,
	); err != nil {
		return fmt.Errorf("update auto send dialog_id: %w", err)
	}
	return nil
}

func UpdateAutoSendAfterRun(dbConn *sql.DB, owner string, taskID int64, nextRunAt, lastRunAt, lastResult, lastReply string) error {
	if _, err := dbConn.Exec(
		"UPDATE tg_auto_send_tasks SET next_run_at = ?, last_run_at = ?, last_result = ?, last_reply = ?, updated_at = ? WHERE id = ? AND owner = ?",
		nextRunAt, lastRunAt, lastResult, lastReply, time.Now().Format(time.RFC3339), taskID, owner,
	); err != nil {
		return fmt.Errorf("update auto send after run: %w", err)
	}
	_ = AppendSendHistory(taskID, lastRunAt, "", lastResult, lastReply)
	return nil
}

// UpdateAutoSendTask edits message and schedule settings.
func UpdateAutoSendTask(dbConn *sql.DB, owner string, taskID int64, message, scheduleType, timeOfDay string, intervalSeconds, jitterSeconds int) error {
	if _, err := dbConn.Exec(
		`UPDATE tg_auto_send_tasks
		    SET message = ?, schedule_type = ?, time_of_day = ?, interval_seconds = ?, jitter_seconds = ?, updated_at = ?
		  WHERE id = ? AND owner = ?`,
		message, scheduleType, timeOfDay, intervalSeconds, jitterSeconds,
		time.Now().Format(time.RFC3339), taskID, owner,
	); err != nil {
		return fmt.Errorf("update auto send task: %w", err)
	}
	return nil
}
