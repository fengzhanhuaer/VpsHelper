package store

import (
	"database/sql"
	"strconv"
	"time"
)

// probeDB is the handle to probe_data.db, opened at startup via SetProbeDB.
// It holds per-deployment probe data that is NOT backed up to Cloudflare D1:
//   - probe_node_status         – runtime connection state per node
//   - probe_node_stats_history  – retained historical load telemetry
var probeDB *sql.DB

// SetProbeDB must be called once from main after db.OpenProbe succeeds.
func SetProbeDB(db *sql.DB) {
	probeDB = db
}

// InsertProbeStatsHistory writes a snapshot of real-time telemetry to the local DB.
func InsertProbeStatsHistory(nodeID int64, cpu, memPct, diskPct float64, netIn, netOut uint64) {
	if probeDB == nil {
		return
	}
	now := time.Now().Unix()
	_, _ = probeDB.Exec(`INSERT INTO probe_node_stats_history 
		(node_id, created_at, cpu, mem_pct, disk_pct, net_in, net_out) 
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		nodeID, now, cpu, memPct, diskPct, netIn, netOut)
}

// CleanupProbeStatsHistory purges telemetry history older than the configured days.
// The retention days configuration is read from the main database.
func CleanupProbeStatsHistory(dbConn *sql.DB) {
	if probeDB == nil {
		return
	}
	settings, err := GetSettings(dbConn, []string{"probe_history_days"})
	daysStr := settings["probe_history_days"]
	days := 90
	if err == nil && daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 {
			days = d
		}
	}

	cutoff := time.Now().AddDate(0, 0, -days).Unix()
	_, _ = probeDB.Exec(`DELETE FROM probe_node_stats_history WHERE created_at < ?`, cutoff)
}

// InsertProbePingHistory writes a snapshot of real-time ping results to the local DB.
func InsertProbePingHistory(nodeID, taskID int64, latency, loss float64) {
	if probeDB == nil {
		return
	}
	now := time.Now().Unix()
	_, _ = probeDB.Exec(`INSERT INTO probe_ping_history (node_id, task_id, created_at, latency, loss) VALUES (?, ?, ?, ?, ?)`, nodeID, taskID, now, latency, loss)
}

// CleanupProbePingHistory purges ping history older than configured days.
func CleanupProbePingHistory(dbConn *sql.DB) {
	if probeDB == nil {
		return
	}
	settings, err := GetSettings(dbConn, []string{"probe_history_days"})
	daysStr := settings["probe_history_days"]
	days := 90
	if err == nil && daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 {
			days = d
		}
	}

	cutoff := time.Now().AddDate(0, 0, -days).Unix()
	_, _ = probeDB.Exec(`DELETE FROM probe_ping_history WHERE created_at < ?`, cutoff)
}

// PingHistoryPoint represents a single point in time.
type PingHistoryPoint struct {
	CreatedAt int64   `json:"created_at"`
	Latency   float64 `json:"latency"`
	Loss      float64 `json:"loss"`
}

// GetProbePingHistoryForNode retrieves the ping telemetry for a particular node spanning the last `hours`.
func GetProbePingHistoryForNode(nodeID int64, hours int) (map[int64][]PingHistoryPoint, error) {
	if probeDB == nil {
		return map[int64][]PingHistoryPoint{}, nil
	}
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	rows, err := probeDB.Query(
		`SELECT task_id, created_at, latency, loss FROM probe_ping_history WHERE node_id = ? AND created_at >= ? ORDER BY task_id, created_at ASC`,
		nodeID, cutoff,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := make(map[int64][]PingHistoryPoint)
	for rows.Next() {
		var taskID, createdAt int64
		var latency, loss float64
		if err := rows.Scan(&taskID, &createdAt, &latency, &loss); err == nil {
			results[taskID] = append(results[taskID], PingHistoryPoint{
				CreatedAt: createdAt,
				Latency:   latency,
				Loss:      loss,
			})
		}
	}
	return results, nil
}
