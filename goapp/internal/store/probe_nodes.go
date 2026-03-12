package store

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	geoCache   sync.Map
	nonceCache sync.Map
)

// GenerateChallengeNonce generates a short-lived random nonce for probe anti-replay auth.
func GenerateChallengeNonce() (string, error) {
	b := make([]byte, 16) // 128-bit
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(b)
	nonceCache.Store(nonce, time.Now().Add(60*time.Second)) // valid for 60s
	return nonce, nil
}

// ConsumeChallengeNonce checks if the nonce exists and is valid.
// It does NOT delete the nonce immediately to allow reuse within the TTL window.
func ConsumeChallengeNonce(nonce string) bool {
	val, ok := nonceCache.Load(nonce)
	if !ok {
		return false
	}

	expiry := val.(time.Time)
	if time.Now().After(expiry) {
		return false
	}
	return true
}

func init() {
	// Cleanup expired nonces periodically
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			now := time.Now()
			nonceCache.Range(func(key, value any) bool {
				expiry := value.(time.Time)
				if now.After(expiry) {
					nonceCache.Delete(key)
				}
				return true
			})
		}
	}()
}

func getGeoForIP(ip string) string {
	if val, ok := geoCache.Load(ip); ok {
		return val.(string)
	}

	geoCache.Store(ip, "获取中...")

	go func() {
		geoReq, err := http.NewRequest("GET", "http://ip-api.com/line/"+ip+"?fields=country,city,isp&lang=zh-CN", nil)
		if err != nil {
			geoCache.Store(ip, "未知归属地")
			return
		}

		client := &http.Client{Timeout: 5 * time.Second}
		geoResp, err := client.Do(geoReq)
		if err != nil {
			geoCache.Store(ip, "未知归属地")
			return
		}
		defer geoResp.Body.Close()

		geoBody, _ := io.ReadAll(geoResp.Body)
		parts := strings.Split(strings.TrimSpace(string(geoBody)), "\n")
		var geoStr string

		label := "IPv4"
		if strings.Contains(ip, ":") {
			label = "IPv6"
		}

		if len(parts) == 3 {
			if parts[1] != "" {
				geoStr = fmt.Sprintf("%s: %s %s (%s)", label, parts[0], parts[1], parts[2])
			} else {
				geoStr = fmt.Sprintf("%s: %s (%s)", label, parts[0], parts[2])
			}
		} else {
			geoStr = label + "未知归属地"
		}

		geoCache.Store(ip, geoStr)
	}()

	return "获取中..."
}

type NodeIPInfo struct {
	Value string
	Geo   string
	Raw   string
}

// ProbeNode represents a registered probe agent node (identity, stored in main DB).
type ProbeNode struct {
	ID             int64
	Name           string
	Note           string
	Secret         string
	CreatedAt      string
	ReportInterval int // seconds, default 60
	Vendor         string
	VendorUrl      string
	Price          string
	ExpiredAt      string
	ExpireDaysStr  string
	Domain         string
	TLSCertPem     string
	TLSKeyPem      string
	TLSCertExpired string

	// Runtime fields loaded from local DB (probe_node_status), not backed up.
	Online          bool
	LastPing        int64 // unix seconds
	LastPingStr     string
	Version         string
	IP              string
	IPs             []string
	IPInfos         []NodeIPInfo
	UpgradeProgress string
}

// ListProbeNodes returns all probe nodes from the main DB, merged with runtime
// status from the local DB.
func ListProbeNodes(dbConn *sql.DB) ([]ProbeNode, error) {
	rows, err := dbConn.Query(
		`SELECT id, name, note, secret, created_at, COALESCE(report_interval, 60), COALESCE(vendor, ''), COALESCE(vendor_url, ''), COALESCE(price, ''), COALESCE(expired_at, ''), COALESCE(domain, ''), COALESCE(tls_cert_pem, ''), COALESCE(tls_key_pem, ''), COALESCE(tls_cert_expired_at, '') FROM probe_nodes ORDER BY id ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list probe nodes: %w", err)
	}
	defer rows.Close()

	var nodes []ProbeNode
	for rows.Next() {
		var n ProbeNode
		if err := rows.Scan(&n.ID, &n.Name, &n.Note, &n.Secret, &n.CreatedAt, &n.ReportInterval, &n.Vendor, &n.VendorUrl, &n.Price, &n.ExpiredAt, &n.Domain, &n.TLSCertPem, &n.TLSKeyPem, &n.TLSCertExpired); err != nil {
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

	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)

	for i := range nodes {
		if nodes[i].ExpiredAt != "" {
			if t, err := time.Parse("2006-01-02", nodes[i].ExpiredAt); err == nil {
				target := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.Local)
				days := int(target.Sub(today).Hours() / 24)
				if days > 0 {
					nodes[i].ExpireDaysStr = fmt.Sprintf("剩 %d 天", days)
				} else if days == 0 {
					nodes[i].ExpireDaysStr = "今天到期"
				} else {
					nodes[i].ExpireDaysStr = fmt.Sprintf("超期 %d 天", -days)
				}
			}
		}

		// Merge runtime status from probe DB.
		if probeDB != nil {
			var online int
			var versionStr, ipStr, upStr string
			_ = probeDB.QueryRow(
				`SELECT online, last_ping, version, ip, upgrade_progress FROM probe_node_status WHERE node_id = ?`,
				nodes[i].ID,
			).Scan(&online, &nodes[i].LastPing, &versionStr, &ipStr, &upStr)
			nodes[i].Online = online == 1
			nodes[i].Version = versionStr
			nodes[i].IP = ipStr
			if ipStr != "" {
				nodes[i].IPs = strings.FieldsFunc(ipStr, func(r rune) bool {
					return r == '\n' || r == ','
				})
				for _, rawIP := range nodes[i].IPs {
					geo := getGeoForIP(rawIP)
					nodes[i].IPInfos = append(nodes[i].IPInfos, NodeIPInfo{Raw: rawIP, Value: rawIP, Geo: geo})
				}
			}
			nodes[i].UpgradeProgress = upStr
			if nodes[i].LastPing > 0 {
				nodes[i].LastPingStr = time.Unix(nodes[i].LastPing, 0).Format("2006-01-02 15:04:05")
			} else {
				nodes[i].LastPingStr = "--"
			}
		}
	}
	return nodes, nil
}

// GetProbeNodeBySecret looks up a node by its secret (for probe authentication).
func GetProbeNodeBySecret(dbConn *sql.DB, secret string) (ProbeNode, error) {
	var n ProbeNode
	err := dbConn.QueryRow(
		`SELECT id, name, note, secret, created_at, COALESCE(report_interval, 60), COALESCE(vendor, ''), COALESCE(vendor_url, ''), COALESCE(price, ''), COALESCE(expired_at, ''), COALESCE(domain, ''), COALESCE(tls_cert_pem, ''), COALESCE(tls_key_pem, ''), COALESCE(tls_cert_expired_at, '') FROM probe_nodes WHERE secret = ?`, secret,
	).Scan(&n.ID, &n.Name, &n.Note, &n.Secret, &n.CreatedAt, &n.ReportInterval, &n.Vendor, &n.VendorUrl, &n.Price, &n.ExpiredAt, &n.Domain, &n.TLSCertPem, &n.TLSKeyPem, &n.TLSCertExpired)
	if err != nil {
		return ProbeNode{}, fmt.Errorf("get probe node by secret: %w", err)
	}
	if n.ReportInterval <= 0 {
		n.ReportInterval = 60
	}
	if n.ExpiredAt != "" {
		if t, err := time.Parse("2006-01-02", n.ExpiredAt); err == nil {
			now := time.Now()
			today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
			target := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.Local)
			days := int(target.Sub(today).Hours() / 24)
			if days > 0 {
				n.ExpireDaysStr = fmt.Sprintf("剩 %d 天", days)
			} else if days == 0 {
				n.ExpireDaysStr = "今天到期"
			} else {
				n.ExpireDaysStr = fmt.Sprintf("超期 %d 天", -days)
			}
		}
	}

	// Merge runtime status.
	if probeDB != nil {
		var online int
		var versionStr, ipStr, upStr string
		_ = probeDB.QueryRow(
			`SELECT online, last_ping, version, ip, upgrade_progress FROM probe_node_status WHERE node_id = ?`, n.ID,
		).Scan(&online, &n.LastPing, &versionStr, &ipStr, &upStr)
		n.Online = online == 1
		n.Version = versionStr
		n.IP = ipStr
		if ipStr != "" {
			n.IPs = strings.FieldsFunc(ipStr, func(r rune) bool {
				return r == '\n' || r == ','
			})
			for _, rawIP := range n.IPs {
				geo := getGeoForIP(rawIP)
				n.IPInfos = append(n.IPInfos, NodeIPInfo{Raw: rawIP, Value: rawIP, Geo: geo})
			}
		}
		n.UpgradeProgress = upStr
		if n.LastPing > 0 {
			n.LastPingStr = time.Unix(n.LastPing, 0).Format("2006-01-02 15:04:05")
		} else {
			n.LastPingStr = "--"
		}
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

// DeleteProbeNode moves a node from probe_nodes to probe_nodes_deleted.
func DeleteProbeNode(dbConn *sql.DB, id int64) error {
	now := time.Now().Format("2006-01-02 15:04:05")
	tx, err := dbConn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		INSERT INTO probe_nodes_deleted (name, note, secret, created_at, report_interval, vendor, vendor_url, price, expired_at, domain, tls_cert_pem, tls_key_pem, tls_cert_expired_at, deleted_at)
		SELECT name, note, secret, created_at, report_interval, vendor, vendor_url, price, expired_at, domain, tls_cert_pem, tls_key_pem, tls_cert_expired_at, ?
		FROM probe_nodes WHERE id = ?
	`, now, id)
	if err != nil {
		return fmt.Errorf("archive node: %w", err)
	}

	if _, err := tx.Exec(`DELETE FROM probe_nodes WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete node: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	if probeDB != nil {
		_, _ = probeDB.Exec(`DELETE FROM probe_node_status WHERE node_id = ?`, id)
	}
	return nil
}

// DeletedProbeNode represents a soft-deleted probe node.
type DeletedProbeNode struct {
	ID             int64
	Name           string
	Note           string
	Secret         string
	CreatedAt      string
	ReportInterval int
	Vendor         string
	VendorUrl      string
	Price          string
	ExpiredAt      string
	Domain         string
	TLSCertPem     string
	TLSKeyPem      string
	TLSCertExpired string
	DeletedAt      string
}

// ListDeletedProbeNodes returns all soft-deleted nodes.
func ListDeletedProbeNodes(dbConn *sql.DB) ([]DeletedProbeNode, error) {
	rows, err := dbConn.Query(
		`SELECT id, name, note, secret, created_at, report_interval, vendor, vendor_url, price, expired_at, domain, tls_cert_pem, tls_key_pem, tls_cert_expired_at, deleted_at FROM probe_nodes_deleted ORDER BY deleted_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list deleted nodes: %w", err)
	}
	defer rows.Close()

	var nodes []DeletedProbeNode
	for rows.Next() {
		var n DeletedProbeNode
		if err := rows.Scan(&n.ID, &n.Name, &n.Note, &n.Secret, &n.CreatedAt, &n.ReportInterval, &n.Vendor, &n.VendorUrl, &n.Price, &n.ExpiredAt, &n.Domain, &n.TLSCertPem, &n.TLSKeyPem, &n.TLSCertExpired, &n.DeletedAt); err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return nodes, rows.Err()
}

// GetProbeNodeByID retrieves a probe node by its ID.
func GetProbeNodeByID(dbConn *sql.DB, id int64) (ProbeNode, error) {
	var n ProbeNode
	err := dbConn.QueryRow(
		`SELECT id, name, note, secret, created_at, COALESCE(report_interval, 60), COALESCE(vendor, ''), COALESCE(vendor_url, ''), COALESCE(price, ''), COALESCE(expired_at, ''), COALESCE(domain, ''), COALESCE(tls_cert_pem, ''), COALESCE(tls_key_pem, ''), COALESCE(tls_cert_expired_at, '') FROM probe_nodes WHERE id = ?`, id,
	).Scan(&n.ID, &n.Name, &n.Note, &n.Secret, &n.CreatedAt, &n.ReportInterval, &n.Vendor, &n.VendorUrl, &n.Price, &n.ExpiredAt, &n.Domain, &n.TLSCertPem, &n.TLSKeyPem, &n.TLSCertExpired)
	if err != nil {
		return ProbeNode{}, fmt.Errorf("get probe node by id: %w", err)
	}

	if n.ExpiredAt != "" {
		if t, err := time.Parse("2006-01-02", n.ExpiredAt); err == nil {
			now := time.Now()
			today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
			target := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.Local)
			days := int(target.Sub(today).Hours() / 24)
			if days > 0 {
				n.ExpireDaysStr = fmt.Sprintf("剩 %d 天", days)
			} else if days == 0 {
				n.ExpireDaysStr = "今天到期"
			} else {
				n.ExpireDaysStr = fmt.Sprintf("超期 %d 天", -days)
			}
		}
	}

	// Merge runtime status.
	if probeDB != nil {
		var online int
		var versionStr, ipStr, upStr string
		_ = probeDB.QueryRow(
			`SELECT online, last_ping, version, ip, upgrade_progress FROM probe_node_status WHERE node_id = ?`, n.ID,
		).Scan(&online, &n.LastPing, &versionStr, &ipStr, &upStr)
		n.Online = online == 1
		n.Version = versionStr
		n.IP = ipStr
		if ipStr != "" {
			n.IPs = strings.FieldsFunc(ipStr, func(r rune) bool {
				return r == '\n' || r == ','
			})
			for _, rawIP := range n.IPs {
				geo := getGeoForIP(rawIP)
				n.IPInfos = append(n.IPInfos, NodeIPInfo{Raw: rawIP, Value: rawIP, Geo: geo})
			}
		}
		n.UpgradeProgress = upStr
		if n.LastPing > 0 {
			n.LastPingStr = time.Unix(n.LastPing, 0).Format("2006-01-02 15:04:05")
		} else {
			n.LastPingStr = "--"
		}
	}
	return n, nil
}

// RestoreDeletedProbeNode moves the node back from probe_nodes_deleted to probe_nodes.
func RestoreDeletedProbeNode(dbConn *sql.DB, id int64) error {
	tx, err := dbConn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		INSERT INTO probe_nodes (name, note, secret, created_at, report_interval, vendor, vendor_url, price, expired_at, domain, tls_cert_pem, tls_key_pem, tls_cert_expired_at)
		SELECT name, note, secret, created_at, report_interval, vendor, vendor_url, price, expired_at, domain, tls_cert_pem, tls_key_pem, tls_cert_expired_at
		FROM probe_nodes_deleted WHERE id = ?
	`, id)
	if err != nil {
		return fmt.Errorf("restore node: %w", err)
	}

	if _, err := tx.Exec(`DELETE FROM probe_nodes_deleted WHERE id = ?`, id); err != nil {
		return fmt.Errorf("cleanup deleted node: %w", err)
	}

	return tx.Commit()
}

// HardDeleteProbeNode removes a node permanently.
func HardDeleteProbeNode(dbConn *sql.DB, id int64) error {
	_, err := dbConn.Exec(`DELETE FROM probe_nodes_deleted WHERE id = ?`, id)
	return err
}

// UpdateProbeNodeDetails updates editable properties in the main DB.
func UpdateProbeNodeDetails(dbConn *sql.DB, id int64, name, note, vendor, vendorUrl, price, expiredAt string, interval int) error {
	if interval < 1 {
		interval = 1
	}
	if interval > 3600 {
		interval = 3600
	}
	_, err := dbConn.Exec(
		`UPDATE probe_nodes SET name = ?, note = ?, vendor = ?, vendor_url = ?, price = ?, expired_at = ?, report_interval = ? WHERE id = ?`,
		name, note, vendor, vendorUrl, price, expiredAt, interval, id,
	)
	return err
}

// UpdateProbeNodeTLS updates the automatically assigned Domain and generated TLS certificate materials.
func UpdateProbeNodeTLS(dbConn *sql.DB, id int64, domain, certPem, keyPem, expiredAt string) error {
	_, err := dbConn.Exec(
		`UPDATE probe_nodes SET domain = ?, tls_cert_pem = ?, tls_key_pem = ?, tls_cert_expired_at = ? WHERE id = ?`,
		domain, certPem, keyPem, expiredAt, id,
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

// SetProbeNodeOnline updates the runtime online/ping state (and version) in probe DB only.
func SetProbeNodeOnline(nodeID int64, online bool, version, ip string) {
	if probeDB == nil {
		return
	}
	onlineInt := 0
	if online {
		onlineInt = 1
	}
	_, _ = probeDB.Exec(
		`INSERT INTO probe_node_status (node_id, online, last_ping, version, ip, upgrade_progress)
		 VALUES (?, ?, ?, ?, ?, '')
		 ON CONFLICT(node_id) DO UPDATE SET 
		 	online = excluded.online, 
		 	last_ping = excluded.last_ping,
		 	version = CASE WHEN excluded.version != '' THEN excluded.version ELSE version END,
			ip = CASE WHEN excluded.ip != '' THEN excluded.ip ELSE ip END,
			upgrade_progress = CASE WHEN excluded.online = 1 THEN '' ELSE upgrade_progress END`,
		nodeID, onlineInt, time.Now().Unix(), version, ip,
	)
}

// UpdateProbeNodeUpgradeProgress updates the upgrade progress text for a node.
func UpdateProbeNodeUpgradeProgress(nodeID int64, progress string) {
	if probeDB == nil {
		return
	}
	_, _ = probeDB.Exec(`UPDATE probe_node_status SET upgrade_progress = ? WHERE node_id = ?`, progress, nodeID)
}

// AuthenticateProbeNodeBySignature validates the Anti-Replay HMAC signature.
// It uses a random nonce instead of a timestamp to prevent NTP drift issues.
func AuthenticateProbeNodeBySignature(dbConn *sql.DB, probeIDHex, nonce, signatureHex string) (ProbeNode, error) {
	// 1. Consume nonce
	if !ConsumeChallengeNonce(nonce) {
		return ProbeNode{}, fmt.Errorf("invalid or expired nonce")
	}

	// 2. Fetch all nodes to match Public ID
	// Because Public ID is SHA256(secret) and we don't store it natively in DB,
	// we iterate through the nodes (usually < 100 for a personal dashboard).
	nodes, err := ListProbeNodes(dbConn)
	if err != nil {
		return ProbeNode{}, fmt.Errorf("failed to list nodes: %w", err)
	}

	var matchedNode *ProbeNode
	for i, n := range nodes {
		hID := sha256.Sum256([]byte(n.Secret))
		if hex.EncodeToString(hID[:]) == probeIDHex {
			matchedNode = &nodes[i]
			break
		}
	}

	if matchedNode == nil {
		return ProbeNode{}, fmt.Errorf("probe identity not found")
	}

	// 3. Verify HMAC Signature
	mac := hmac.New(sha256.New, []byte(matchedNode.Secret))
	mac.Write([]byte(nonce))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if hmac.Equal([]byte(signatureHex), []byte(expectedSig)) {
		return *matchedNode, nil
	}

	return ProbeNode{}, fmt.Errorf("invalid hmac signature")
}
