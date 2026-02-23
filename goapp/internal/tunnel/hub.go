package tunnel

import (
	"sync"

	"github.com/gorilla/websocket"
)

// NodeStats represents the telemetry data sent from a probe.
type NodeStats struct {
	NodeID   int64   `json:"node_id"`
	CPU      float64 `json:"cpu"`
	MemPct   float64 `json:"mem_pct"`
	MemUsed  string  `json:"mem_used"`
	DiskPct  float64 `json:"disk_pct"`
	DiskUsed string  `json:"disk_used"`
	NetIn    uint64  `json:"net_in"`
	NetOut   uint64  `json:"net_out"`
	Uptime   string  `json:"uptime"`
	Online   bool    `json:"online,omitempty"` // used for status updates
}

var (
	// DashboardClients map[*websocket.Conn]bool holds active dashboard viewers.
	DashboardClients = sync.Map{}
	
	// StatsBroadcast channel receives stats from all probes and multiplexes them to viewers.
	StatsBroadcast = make(chan NodeStats, 100)
)

func init() {
	go func() {
		for stats := range StatsBroadcast {
			DashboardClients.Range(func(key, value interface{}) bool {
				conn := key.(*websocket.Conn)
				err := conn.WriteJSON(stats)
				if err != nil {
					conn.Close()
					DashboardClients.Delete(key)
				}
				return true
			})
		}
	}()
}

// AddDashboardClient registers a new web viewer socket.
func AddDashboardClient(conn *websocket.Conn) {
	DashboardClients.Store(conn, true)
}

// RemoveDashboardClient removes a web viewer socket.
func RemoveDashboardClient(conn *websocket.Conn) {
	DashboardClients.Delete(conn)
	conn.Close()
}

// BroadcastStatus forces a UI update (e.g., node disconnected).
func BroadcastStatus(nodeID int64, online bool) {
	StatsBroadcast <- NodeStats{
		NodeID: nodeID,
		Online: online,
	}
}
