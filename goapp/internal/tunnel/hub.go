package tunnel

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

// NodeStats represents the telemetry data sent from a probe.
type NodeStats struct {
	NodeID   int64   `json:"node_id"`
	CPU      float64 `json:"cpu"`
	MemPct   float64 `json:"mem_pct"`
	MemUsed  string  `json:"mem_used"`
	SwapPct  float64 `json:"swap_pct"`
	SwapUsed string  `json:"swap_used"`
	DiskPct  float64 `json:"disk_pct"`
	DiskUsed string  `json:"disk_used"`
	NetIn    uint64  `json:"net_in"`
	NetOut   uint64  `json:"net_out"`
	Uptime   string  `json:"uptime"`
	Online   bool    `json:"online,omitempty"` // used for status updates
}

// ControlMsg is the generic server→probe control message.
// Type identifies the action; Payload carries arbitrary JSON.
// Adding new control types only requires defining a new Type string.
type ControlMsg struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// TelemetryMsg is the generic probe→server telemetry message.
// Type identifies what kind of data is being reported (e.g. "stats", "process_list").
// Payload carries the actual data as arbitrary JSON.
type TelemetryMsg struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

var (
	// DashboardClients map[*websocket.Conn]bool holds active dashboard viewers.
	DashboardClients = sync.Map{}

	// StatsBroadcast channel receives stats from all probes and multiplexes them to viewers.
	StatsBroadcast = make(chan NodeStats, 100)

	// PingBroadcast channel receives ping results from probes and broadcasts them to viewers.
	PingBroadcast = make(chan PingStatsBroadcastMsg, 100)

	// EventBroadcast channel pushes arbitrary status updates (like Upgrade Progress or Version) to dashboard.
	EventBroadcast = make(chan map[string]interface{}, 100)
)

// PingStatsBroadcastMsg wraps the ping telemetry payload for the frontend.
type PingStatsBroadcastMsg struct {
	Type    string                       `json:"type"`
	NodeID  int64                        `json:"node_id"`
	Results map[int64]map[string]float64 `json:"results"`
}

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

	go func() {
		for msg := range PingBroadcast {
			DashboardClients.Range(func(key, value interface{}) bool {
				conn := key.(*websocket.Conn)
				err := conn.WriteJSON(msg)
				if err != nil {
					conn.Close()
					DashboardClients.Delete(key)
				}
				return true
			})
		}
	}()

	go func() {
		for msg := range EventBroadcast {
			DashboardClients.Range(func(key, value interface{}) bool {
				conn := key.(*websocket.Conn)
				err := conn.WriteJSON(msg)
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

// PushConfigToNode opens a new Yamux stream to an online node and sends a
// control message. This can be called for any type of server-initiated config push.
// payload must be a JSON-marshallable value.
func PushConfigToNode(nodeID int64, msgType string, payload interface{}) error {
	sessVal, ok := ActiveSessions.Load(nodeID)
	if !ok {
		return fmt.Errorf("node %d is not currently connected", nodeID)
	}
	sess := sessVal.(*yamux.Session)
	stream, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}
	defer stream.Close()

	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	msg := ControlMsg{
		Type:    msgType,
		Payload: rawPayload,
	}
	enc := json.NewEncoder(stream)
	if err := enc.Encode(msg); err != nil {
		return fmt.Errorf("send control msg: %w", err)
	}
	return nil
}

// PushConfigToAllNodes pushes a control message to all currently connected probes.
func PushConfigToAllNodes(msgType string, payload interface{}) {
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return
	}
	msg := ControlMsg{
		Type:    msgType,
		Payload: rawPayload,
	}

	ActiveSessions.Range(func(key, value interface{}) bool {
		sess := value.(*yamux.Session)
		stream, err := sess.OpenStream()
		if err == nil {
			go func() {
				defer stream.Close()
				enc := json.NewEncoder(stream)
				_ = enc.Encode(msg)
			}()
		}
		return true
	})
}

// OpenShellStream requests a shell stream from the connected node.
// It sends the 'shell' control message and returns the open stream for bidirectional communication.
func OpenShellStream(nodeID int64) (*yamux.Stream, error) {
	sessVal, ok := ActiveSessions.Load(nodeID)
	if !ok {
		return nil, fmt.Errorf("node %d is not currently connected", nodeID)
	}
	sess := sessVal.(*yamux.Session)
	stream, err := sess.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open shell stream: %w", err)
	}

	msg := ControlMsg{
		Type:    "shell",
		Payload: []byte("{}"),
	}
	enc := json.NewEncoder(stream)
	if err := enc.Encode(msg); err != nil {
		stream.Close()
		return nil, fmt.Errorf("send shell control msg: %w", err)
	}

	return stream, nil
}

// OpenLogStream requests the probe to execute and return its operational logs.
func OpenLogStream(nodeID int64) (string, error) {
	sessVal, ok := ActiveSessions.Load(nodeID)
	if !ok {
		return "", fmt.Errorf("node %d is not currently connected", nodeID)
	}
	sess := sessVal.(*yamux.Session)
	stream, err := sess.OpenStream()
	if err != nil {
		return "", fmt.Errorf("open log stream: %w", err)
	}
	defer stream.Close()

	msg := ControlMsg{
		Type:    "log",
		Payload: []byte("{}"),
	}
	enc := json.NewEncoder(stream)
	if err := enc.Encode(msg); err != nil {
		return "", fmt.Errorf("send log control msg: %w", err)
	}

	out, err := io.ReadAll(stream)
	if err != nil && err != io.EOF {
		return "", err
	}
	return string(out), nil
}

// OpenExecStream requests the probe to execute a short-lived shell command within a specified working directory.
func OpenExecStream(nodeID int64, cwd string, cmd string) (string, error) {
	sessVal, ok := ActiveSessions.Load(nodeID)
	if !ok {
		return "", fmt.Errorf("node %d is not currently connected", nodeID)
	}
	sess := sessVal.(*yamux.Session)
	stream, err := sess.OpenStream()
	if err != nil {
		return "", fmt.Errorf("open exec stream: %w", err)
	}
	defer stream.Close()

	payload, _ := json.Marshal(map[string]string{
		"cwd":     cwd,
		"command": cmd,
	})
	
	msg := ControlMsg{
		Type:    "exec_cmd",
		Payload: payload,
	}
	enc := json.NewEncoder(stream)
	if err := enc.Encode(msg); err != nil {
		return "", fmt.Errorf("send exec control msg: %w", err)
	}

	out, err := io.ReadAll(stream)
	if err != nil && err != io.EOF {
		return "", err
	}
	return string(out), nil
}
