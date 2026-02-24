package web

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"vpshelper-go/internal/store"
	"vpshelper-go/internal/tunnel"
)

var dashboardUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// probeDashboardWS upgrades the dashboard HTTP connection to a WebSocket
// and registers it with the global tunnel Hub to receive realtime stats.
func (h *Handler) probeDashboardWS(c *gin.Context) {
	// Simple session check (if they can't access panel, they can't access ws)
	if h.currentUser(c) == "" {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	conn, err := dashboardUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("[Web] Failed to upgrade dashboard WS: %v", err)
		return
	}

	tunnel.AddDashboardClient(conn)

	// User wants rapid updates (5s) for 5 minutes when a dashboard is opened
	go func() {
		log.Printf("[Web] Dashboard opened. Rapid 5s refresh mode enabled for 5 minutes.")
		tunnel.PushConfigToAllNodes("config", map[string]interface{}{
			"report_interval": 5,
		})

		time.Sleep(5 * time.Minute)

		log.Printf("[Web] Rapid refresh mode elapsed. Restoring original node intervals.")
		nodes, err := store.ListProbeNodes(h.dbConn)
		if err == nil {
			for _, n := range nodes {
				go tunnel.PushConfigToNode(n.ID, "config", map[string]interface{}{
					"report_interval": n.ReportInterval,
				})
			}
		}
	}()

	// We just need to keep the connection open and read to detect disconnects.
	// The tunnel's Broadcast loop will handle writing stats to it.
	go func() {
		defer tunnel.RemoveDashboardClient(conn)
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				return // Client disconnected
			}
		}
	}()
}
