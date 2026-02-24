package store

import (
	"database/sql"
	"fmt"
	"time"
)

// ProbeTask represents a ping target task assigned to probe nodes.
type ProbeTask struct {
	ID             int64
	Name           string // 备注名
	Target         string // ping 的 IP / 域名
	NodeIDs        string // 逗号分隔的节点 ID，例如 ",1,4,5,"
	ReportInterval int    // 拨测周期 (秒)
	CreatedAt      string
}

// ListProbeTasks returns all ping tasks mapping.
func ListProbeTasks(dbConn *sql.DB) ([]ProbeTask, error) {
	rows, err := dbConn.Query(
		`SELECT id, name, target, node_ids, report_interval, created_at FROM probe_tasks ORDER BY id DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list probe tasks: %w", err)
	}
	defer rows.Close()

	var tasks []ProbeTask
	for rows.Next() {
		var t ProbeTask
		if err := rows.Scan(&t.ID, &t.Name, &t.Target, &t.NodeIDs, &t.ReportInterval, &t.CreatedAt); err != nil {
			return nil, err
		}
		tasks = append(tasks, t)
	}
	return tasks, rows.Err()
}

// CreateProbeTask inserts a new probe task map.
func CreateProbeTask(dbConn *sql.DB, name, target, nodeIDs string, reportInterval int) error {
	now := time.Now().Format("2006-01-02 15:04:05")
	_, err := dbConn.Exec(
		`INSERT INTO probe_tasks (name, target, node_ids, report_interval, created_at) VALUES (?, ?, ?, ?, ?)`,
		name, target, nodeIDs, reportInterval, now,
	)
	return err
}

// UpdateProbeTask edits an existing ping task.
func UpdateProbeTask(dbConn *sql.DB, id int64, name, target, nodeIDs string, reportInterval int) error {
	_, err := dbConn.Exec(
		`UPDATE probe_tasks SET name = ?, target = ?, node_ids = ?, report_interval = ? WHERE id = ?`,
		name, target, nodeIDs, reportInterval, id,
	)
	return err
}

// DeleteProbeTask removes a specific probe task.
func DeleteProbeTask(dbConn *sql.DB, id int64) error {
	_, err := dbConn.Exec(`DELETE FROM probe_tasks WHERE id = ?`, id)
	return err
}

// GetProbeTasksForNode returns all ping tasks assigned to a particular node ID.
func GetProbeTasksForNode(dbConn *sql.DB, nodeID int64) ([]ProbeTask, error) {
	nodeScope := fmt.Sprintf("%%,%d,%%", nodeID)
	rows, err := dbConn.Query(
		`SELECT id, name, target, node_ids, report_interval, created_at FROM probe_tasks WHERE node_ids LIKE ? ORDER BY id DESC`,
		nodeScope,
	)
	if err != nil {
		return nil, fmt.Errorf("list node probe tasks: %w", err)
	}
	defer rows.Close()

	var tasks []ProbeTask
	for rows.Next() {
		var t ProbeTask
		if err := rows.Scan(&t.ID, &t.Name, &t.Target, &t.NodeIDs, &t.ReportInterval, &t.CreatedAt); err != nil {
			return nil, err
		}
		tasks = append(tasks, t)
	}
	return tasks, rows.Err()
}
