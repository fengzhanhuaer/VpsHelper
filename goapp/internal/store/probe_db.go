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
