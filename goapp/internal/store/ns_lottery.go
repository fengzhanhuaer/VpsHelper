package store

import (
	"fmt"
	"time"
)

// LotteryStatus values.
const (
	LotteryStatusPending = "pending" // draw time not yet reached
	LotteryStatusDrawn   = "drawn"   // drawn, did not win
	LotteryStatusWon     = "won"     // drawn and won
)

// LotteryWatch is one monitored NodeSeek lucky draw.
type LotteryWatch struct {
	ID            int64  `json:"id"`
	Owner         string `json:"owner"`
	URL           string `json:"url"`
	PostID        string `json:"post_id"`
	DrawTime      int64  `json:"draw_time"`     // unix ms
	Count         int    `json:"count"`          // number of prizes
	StartFloor    int    `json:"start_floor"`    // floor >= start_floor qualify
	Duplicate     bool   `json:"duplicate"`      // allow same user to win multiple times
	WatchUsername string `json:"watch_username"` // nodeseek username to monitor
	Status        string `json:"status"`         // pending / drawn / won
	Winners       string `json:"winners"`        // JSON array of winner names
	Notified      bool   `json:"notified"`
	Note          string `json:"note"` // human-readable result message
	CheckCount    int    `json:"check_count"`
	NextCheckAt   int64  `json:"next_check_at"` // unix ms; 0 = check anytime after draw_time
	CreatedAt     string `json:"created_at"`
}

func CreateLotteryWatch(owner, rawURL, postID string, drawTime int64, count, startFloor int, duplicate bool, watchUsername string) (int64, error) {
	dupInt := 0
	if duplicate {
		dupInt = 1
	}
	res, err := localDB.Exec(
		`INSERT INTO ns_lottery_watches
		 (owner, url, post_id, draw_time, count, start_floor, duplicate, watch_username, status, winners, notified, note, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', '', 0, '', ?)`,
		owner, rawURL, postID, drawTime, count, startFloor, dupInt, watchUsername,
		time.Now().Format(time.RFC3339),
	)
	if err != nil {
		return 0, fmt.Errorf("create lottery watch: %w", err)
	}
	id, _ := res.LastInsertId()
	return id, nil
}

func ListLotteryWatches(owner string) ([]LotteryWatch, error) {
	rows, err := localDB.Query(
		`SELECT id, owner, url, post_id, draw_time, count, start_floor, duplicate,
		        watch_username, status, winners, notified, note, check_count, next_check_at, created_at
		   FROM ns_lottery_watches
		  WHERE owner = ?
		  ORDER BY draw_time DESC`,
		owner,
	)
	if err != nil {
		return nil, fmt.Errorf("list lottery watches: %w", err)
	}
	defer rows.Close()

	var out []LotteryWatch
	for rows.Next() {
		var w LotteryWatch
		var dupInt, notifInt int
		if err := rows.Scan(
			&w.ID, &w.Owner, &w.URL, &w.PostID, &w.DrawTime,
			&w.Count, &w.StartFloor, &dupInt,
			&w.WatchUsername, &w.Status, &w.Winners, &notifInt, &w.Note,
			&w.CheckCount, &w.NextCheckAt, &w.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan lottery watch: %w", err)
		}
		w.Duplicate = dupInt == 1
		w.Notified = notifInt == 1
		out = append(out, w)
	}
	return out, nil
}

// ListPendingLotteryWatches returns pending watches whose draw_time has passed.
func ListPendingLotteryWatches(nowMs int64) ([]LotteryWatch, error) {
	rows, err := localDB.Query(
		`SELECT id, owner, url, post_id, draw_time, count, start_floor, duplicate,
		        watch_username, status, winners, notified, note, check_count, next_check_at, created_at
		   FROM ns_lottery_watches
		  WHERE status = 'pending' AND draw_time <= ? AND check_count < 10
		    AND (next_check_at = 0 OR next_check_at <= ?)`,
		nowMs, nowMs,
	)
	if err != nil {
		return nil, fmt.Errorf("list pending lottery watches: %w", err)
	}
	defer rows.Close()

	var out []LotteryWatch
	for rows.Next() {
		var w LotteryWatch
		var dupInt, notifInt int
		if err := rows.Scan(
			&w.ID, &w.Owner, &w.URL, &w.PostID, &w.DrawTime,
			&w.Count, &w.StartFloor, &dupInt,
			&w.WatchUsername, &w.Status, &w.Winners, &notifInt, &w.Note,
			&w.CheckCount, &w.NextCheckAt, &w.CreatedAt,
		); err != nil {
			continue
		}
		w.Duplicate = dupInt == 1
		w.Notified = notifInt == 1
		out = append(out, w)
	}
	return out, nil
}

// ListWonUnnotified returns won watches that have not yet been sent a TG notification.
func ListWonUnnotified() ([]LotteryWatch, error) {
	rows, err := localDB.Query(
		`SELECT id, owner, url, post_id, draw_time, count, start_floor, duplicate,
		        watch_username, status, winners, notified, note, check_count, next_check_at, created_at
		   FROM ns_lottery_watches
		  WHERE status = 'won' AND notified = 0`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []LotteryWatch
	for rows.Next() {
		var w LotteryWatch
		var dupInt, notifInt int
		if err := rows.Scan(
			&w.ID, &w.Owner, &w.URL, &w.PostID, &w.DrawTime,
			&w.Count, &w.StartFloor, &dupInt,
			&w.WatchUsername, &w.Status, &w.Winners, &notifInt, &w.Note,
			&w.CheckCount, &w.NextCheckAt, &w.CreatedAt,
		); err != nil {
			continue
		}
		w.Duplicate = dupInt == 1
		w.Notified = notifInt == 1
		out = append(out, w)
	}
	return out, nil
}

// BumpLotteryCheckCount increments check_count and sets next_check_at for retry backoff.
// Backoff schedule: 1st=5min, 2nd=10min, 3rd+=30min. Max 10 retries.
func BumpLotteryCheckCount(id int64, checkCount int) error {
	delayMin := 5
	if checkCount >= 2 {
		delayMin = 30
	} else if checkCount >= 1 {
		delayMin = 10
	}
	nextMs := time.Now().Add(time.Duration(delayMin) * time.Minute).UnixMilli()
	_, err := localDB.Exec(
		`UPDATE ns_lottery_watches SET check_count = check_count + 1, next_check_at = ? WHERE id = ?`,
		nextMs, id,
	)
	return err
}

func UpdateLotteryWatchResult(id int64, status, winners, note string) error {
	_, err := localDB.Exec(
		`UPDATE ns_lottery_watches SET status=?, winners=?, note=? WHERE id=?`,
		status, winners, note, id,
	)
	return err
}

func MarkLotteryNotified(id int64) error {
	_, err := localDB.Exec(`UPDATE ns_lottery_watches SET notified=1 WHERE id=?`, id)
	return err
}

func DeleteLotteryWatch(owner string, id int64) error {
	_, err := localDB.Exec(
		`DELETE FROM ns_lottery_watches WHERE id=? AND owner=?`, id, owner,
	)
	return err
}
