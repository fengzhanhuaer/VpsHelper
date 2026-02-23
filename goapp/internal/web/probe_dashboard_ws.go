package web

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

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
