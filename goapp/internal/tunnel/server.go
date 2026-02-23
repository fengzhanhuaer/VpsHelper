package tunnel

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"

	"vpshelper-go/internal/security"
	"vpshelper-go/internal/store"
)

var (
	// ActiveSessions holds a mapping from NodeID to yamux.Session.
	ActiveSessions = sync.Map{}

	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all for tunneling
		},
	}
)

// StartServer starts the WebSocket tunnel listener on the specified private port.
func StartServer(ctx context.Context, dbConn *sql.DB) error {
	settings, err := store.GetSettings(dbConn, []string{"probe_private_port"})
	if err != nil {
		return fmt.Errorf("read settings: %w", err)
	}

	port := settings["probe_private_port"]
	if port == "" {
		port = "15019"
	}

	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/tunnel/:secret", func(c *gin.Context) {
		handleTunnelConnect(c, dbConn)
	})

	addr := ":" + port
	server := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	go func() {
		log.Printf("[Tunnel] Listening for probe connections on %s", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[Tunnel] server error: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		log.Printf("[Tunnel] Shutting down...")
		_ = server.Shutdown(context.Background())
	}()

	go func() {
		// Run a cleanup once on startup, then every 24 hours.
		store.CleanupProbeStatsHistory(dbConn)
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				store.CleanupProbeStatsHistory(dbConn)
			}
		}
	}()

	return nil
}

func handleTunnelConnect(c *gin.Context, dbConn *sql.DB) {
	ip := c.ClientIP()
	if security.IsBanned(ip) {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	secret := c.Param("secret")
	if secret == "" {
		secret = c.GetHeader("X-Probe-Secret")
	}
	if secret == "" {
		security.RecordFailure(dbConn, ip)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	node, err := store.GetProbeNodeBySecret(dbConn, secret)
	if err != nil {
		security.RecordFailure(dbConn, ip)
		log.Printf("[Tunnel] Unauthorized probe connection attempt: invalid secret")
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("[Tunnel] WebSocket upgrade failed for node %s (ID %d): %v", node.Name, node.ID, err)
		return
	}

	log.Printf("[Tunnel] Node %s (ID %d) connected.", node.Name, node.ID)

	// Wrap WebSocket connection into an io.ReadWriteCloser
	wsConn := &WsConn{Conn: conn}

	// Setup Yamux Server
	conf := yamux.DefaultConfig()
	conf.EnableKeepAlive = true
	// Accept KeepAlive Interval ~30s is default
	yamuxSession, err := yamux.Server(wsConn, conf)
	if err != nil {
		log.Printf("[Tunnel] Node %s yamux setup failed: %v", node.Name, err)
		conn.Close()
		return
	}

	// If there's an existing session, close it (disconnect older instance)
	if oldSess, ok := ActiveSessions.Load(node.ID); ok {
		log.Printf("[Tunnel] Replacing existing session for node %s (ID %d)", node.Name, node.ID)
		oldSess.(*yamux.Session).Close()
	}

	// Register session
	ActiveSessions.Store(node.ID, yamuxSession)
	probeVersion := c.GetHeader("X-Probe-Version")
	store.SetProbeNodeOnline(node.ID, true, probeVersion)
	BroadcastStatus(node.ID, true) // Notify dashboard viewers

	// Maintain connection state / block until dropped
	go monitorSession(node.ID, node.Name, yamuxSession)
}

func monitorSession(nodeID int64, nodeName string, session *yamux.Session) {
	defer func() {
		session.Close()
		// Only remove if it's still THIS session (in case of quick reconnect overrides)
		if active, ok := ActiveSessions.Load(nodeID); ok && active == session {
			ActiveSessions.Delete(nodeID)
			store.SetProbeNodeOnline(nodeID, false, "")
			BroadcastStatus(nodeID, false) // Notify dashboard viewers
			log.Printf("[Tunnel] Node %s (ID %d) detached.", nodeName, nodeID)
		}
	}()

	// Accept Streams / Wait for disconnect
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			if err != yamux.ErrSessionShutdown {
				log.Printf("[Tunnel] session AcceptStream error: %v", err)
			}
			return
		}
		
		// Typically, a probe initiates streams to send data or report status.
		// However, controlling commands are usually initiated BY the server to the client.
		// In Yamux, BOTH sides can open streams!
		// For now, if probe opens a stream, Handle it:
		go handleIncomingProbeStream(nodeID, stream)
	}
}

func handleIncomingProbeStream(nodeID int64, stream *yamux.Stream) {
	defer stream.Close()
	
	reader := bufio.NewReader(stream)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	handshake := strings.TrimSpace(line)

	switch handshake {
	case "STATS":
		handleStatsStream(nodeID, reader)
	default:
		log.Printf("[Tunnel] Unknown stream handshake from node %d: %s", nodeID, handshake)
	}
}

func handleStatsStream(nodeID int64, reader *bufio.Reader) {
	decoder := json.NewDecoder(reader)
	for {
		var msg TelemetryMsg
		if err := decoder.Decode(&msg); err != nil {
			// Stream broken or EOF
			return
		}
		switch msg.Type {
		case "stats":
			var ns NodeStats
			if err := json.Unmarshal(msg.Payload, &ns); err != nil {
				log.Printf("[Tunnel] malformed stats payload from node %d: %v", nodeID, err)
				continue
			}
			ns.NodeID = nodeID
			ns.Online = true
			StatsBroadcast <- ns
			store.InsertProbeStatsHistory(nodeID, ns.CPU, ns.MemPct, ns.DiskPct, ns.NetIn, ns.NetOut)
		case "ping_results":
			var results map[int64]map[string]float64
			if err := json.Unmarshal(msg.Payload, &results); err != nil {
				log.Printf("[Tunnel] malformed ping payload from node %d: %v", nodeID, err)
				continue
			}
			for taskID, data := range results {
				store.InsertProbePingHistory(nodeID, taskID, data["latency"], data["loss"])
			}
			PingBroadcast <- PingStatsBroadcastMsg{
				Type:    "ping_results",
				NodeID:  nodeID,
				Results: results,
			}
		default:
			log.Printf("[Tunnel] unknown telemetry type '%s' from node %d", msg.Type, nodeID)
		}
	}
}
