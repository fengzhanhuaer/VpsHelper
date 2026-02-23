package store

import (
	"database/sql"
	"fmt"
	"time"
)

// ProbeNode represents a registered probe agent node (identity, stored in main DB).
type ProbeNode struct {
	ID             int64
	Name           string
	Note           string
	Secret         string
	CreatedAt      string
	ReportInterval int // seconds, default 3

	// Runtime fields loaded from local DB (probe_node_status), not backed up.
	Online   bool
	LastPing int64 // unix seconds
}

// ListProbeNodes returns all probe nodes from the main DB, merged with runtime
// status from the local DB.
func ListProbeNodes(dbConn *sql.DB) ([]ProbeNode, error) {
	rows, err := dbConn.Query(
		`SELECT id, name, note, secret, created_at, COALESCE(report_interval, 3) FROM probe_nodes ORDER BY id ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list probe nodes: %w", err)
	}
	defer rows.Close()

	var nodes []ProbeNode
	for rows.Next() {
		var n ProbeNode
		if err := rows.Scan(&n.ID, &n.Name, &n.Note, &n.Secret, &n.CreatedAt, &n.ReportInterval); err != nil {
			return nil, err
		}
		if n.ReportInterval <= 0 {
			n.ReportInterval = 60
		}
		nodes = append(nodes, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Merge runtime status from local DB.
	if localDB != nil {
		for i := range nodes {
			var online int
			_ = localDB.QueryRow(
				`SELECT online, last_ping FROM probe_node_status WHERE node_id = ?`,
				nodes[i].ID,
			).Scan(&online, &nodes[i].LastPing)
			nodes[i].Online = online == 1
		}
	}
	return nodes, nil
}

// GetProbeNodeBySecret looks up a node by its secret (for probe authentication).
func GetProbeNodeBySecret(dbConn *sql.DB, secret string) (ProbeNode, error) {
	var n ProbeNode
	err := dbConn.QueryRow(
		`SELECT id, name, note, secret, created_at, COALESCE(report_interval, 3) FROM probe_nodes WHERE secret = ?`, secret,
	).Scan(&n.ID, &n.Name, &n.Note, &n.Secret, &n.CreatedAt, &n.ReportInterval)
	if err != nil {
		return ProbeNode{}, fmt.Errorf("get probe node by secret: %w", err)
	}
	if n.ReportInterval <= 0 {
		n.ReportInterval = 3
	}
	// Merge runtime status.
	if localDB != nil {
		var online int
		_ = localDB.QueryRow(
			`SELECT online, last_ping FROM probe_node_status WHERE node_id = ?`, n.ID,
		).Scan(&online, &n.LastPing)
		n.Online = online == 1
	}
	return n, nil
}

// CreateProbeNode inserts a new probe node (main DB) and returns its ID.
func CreateProbeNode(dbConn *sql.DB, name, note, secret string) (int64, error) {
	now := time.Now().Format("2006-01-02 15:04:05")
	res, err := dbConn.Exec(
		`INSERT INTO probe_nodes (name, note, secret, created_at, report_interval) VALUES (?, ?, ?, ?, 60)`,
		name, note, secret, now,
	)
	if err != nil {
		return 0, fmt.Errorf("create probe node: %w", err)
	}
	return res.LastInsertId()
}

// DeleteProbeNode removes a node from the main DB and its status from local DB.
func DeleteProbeNode(dbConn *sql.DB, id int64) error {
	if _, err := dbConn.Exec(`DELETE FROM probe_nodes WHERE id = ?`, id); err != nil {
		return err
	}
	if localDB != nil {
		_, _ = localDB.Exec(`DELETE FROM probe_node_status WHERE node_id = ?`, id)
	}
	return nil
}

// UpdateProbeNodeInfo updates name and note in the main DB.
func UpdateProbeNodeInfo(dbConn *sql.DB, id int64, name, note string) error {
	_, err := dbConn.Exec(
		`UPDATE probe_nodes SET name = ?, note = ? WHERE id = ?`, name, note, id,
	)
	return err
}

// UpdateProbeNodeSecret updates the secret of a node in the main DB.
func UpdateProbeNodeSecret(dbConn *sql.DB, id int64, secret string) error {
	_, err := dbConn.Exec(
		`UPDATE probe_nodes SET secret = ? WHERE id = ?`, secret, id,
	)
	return err
}

// UpdateProbeNodeInterval sets the report_interval (seconds) for a node.
func UpdateProbeNodeInterval(dbConn *sql.DB, id int64, interval int) error {
	if interval < 1 {
		interval = 1
	}
	if interval > 300 {
		interval = 300
	}
	_, err := dbConn.Exec(
		`UPDATE probe_nodes SET report_interval = ? WHERE id = ?`, interval, id,
	)
	return err
}

// SetProbeNodeOnline updates the runtime online/ping state in local DB only.
func SetProbeNodeOnline(nodeID int64, online bool) {
	if localDB == nil {
		return
	}
	onlineInt := 0
	if online {
		onlineInt = 1
	}
	_, _ = localDB.Exec(
		`INSERT INTO probe_node_status (node_id, online, last_ping)
		 VALUES (?, ?, ?)
		 ON CONFLICT(node_id) DO UPDATE SET online = excluded.online, last_ping = excluded.last_ping`,
		nodeID, onlineInt, time.Now().Unix(),
	)
}
