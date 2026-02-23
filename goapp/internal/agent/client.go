package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"

	"vpshelper-go/internal/tunnel"
)

type DiscoverResponse struct {
	Success bool   `json:"success"`
	NodeID  int64  `json:"node_id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Error   string `json:"error"`
}

// Start manages the lifecycle of the probe connection to the control center
func Start(ctx context.Context, serverHost, secret string) {
	go func() {
		delay := 2 * time.Second
		for {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("[Agent] 正在连接控制中心: %s", serverHost)
				err := connectAndServe(ctx, serverHost, secret)
				if err != nil {
					log.Printf("[Agent] 隧道中断或失败: %v, 将在 %s 后重试...", err, delay)
					time.Sleep(delay)
					// Simple backoff
					if delay < 30*time.Second {
						delay *= 2
					}
				} else {
					delay = 2 * time.Second // reset backoff on clean close
				}
			}
		}
	}()
}

func connectAndServe(ctx context.Context, serverHost, secret string) error {
	// 1. Discover Real Address
	if !strings.HasPrefix(serverHost, "http") {
		serverHost = "https://" + serverHost
	}
	discoverURL := strings.TrimSuffix(serverHost, "/") + "/api/probe/discover"
	
	req, err := http.NewRequestWithContext(ctx, "GET", discoverURL, nil)
	if err != nil {
		return fmt.Errorf("create discover request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+secret)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("do discover request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("discover failed with status %d: %s", resp.StatusCode, string(body))
	}

	var dResp DiscoverResponse
	if err := json.NewDecoder(resp.Body).Decode(&dResp); err != nil {
		return fmt.Errorf("decode discover response: %w", err)
	}

	if !dResp.Success {
		return fmt.Errorf("discover returned error: %s", dResp.Error)
	}

	wsAddress := dResp.Address
	log.Printf("[Agent] 寻址成功: 节点ID=%d, 专属入口=%s", dResp.NodeID, wsAddress)

	// 2. Establish WebSocket direct to private port
	dialer := websocket.DefaultDialer
	wsHeader := http.Header{}
	wsHeader.Set("X-Probe-Secret", secret)

	conn, _, err := dialer.DialContext(ctx, wsAddress, wsHeader)
	if err != nil {
		return fmt.Errorf("websocket dial to %s: %w", wsAddress, err)
	}

	log.Printf("[Agent] WebSocket 建立成功, 正在提升为 Yamux 多路复用隧道...")

	wsConn := &tunnel.WsConn{Conn: conn}

	// 3. Setup Yamux Client
	conf := yamux.DefaultConfig()
	conf.EnableKeepAlive = true
	
	session, err := yamux.Client(wsConn, conf)
	if err != nil {
		conn.Close()
		return fmt.Errorf("yamux client init: %w", err)
	}

	log.Printf("[Agent] Yamux 隧道连接已开启并就绪！")

	errCh := make(chan error, 1)

	// Stream 1: Telemetry (Push stats to server)
	go startTelemetryStream(ctx, session, errCh)

	// Heartbeat / ping thread to ensure multiplexer is alive
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				session.Close()
				return
			case <-ticker.C:
				if session.IsClosed() {
					errCh <- fmt.Errorf("session implicitly closed")
					return
				}
				_, err := session.Ping()
				if err != nil {
					errCh <- fmt.Errorf("yamux ping failed: %w", err)
					return
				}
			}
		}
	}()

	// Accept inbound streams from server (e.g., shell commands, proxy data)
	go func() {
		for {
			stream, err := session.AcceptStream()
			if err != nil {
				if err != yamux.ErrSessionShutdown {
					errCh <- fmt.Errorf("accept stream fail: %w", err)
				} else {
					errCh <- nil
				}
				return
			}
			go handleIncomingControlStream(stream)
		}
	}()

	// Block until context cancels or error triggers reconnect
	select {
	case <-ctx.Done():
		session.Close()
		return nil
	case err := <-errCh:
		session.Close()
		return err
	}
}

// handleIncomingControlStream processes streams specifically opened by the center to the probe
func handleIncomingControlStream(stream *yamux.Stream) {
	defer stream.Close()
	// Future implementation:
	// Use stream to run shell commands, setup proxy paths, etc.
}

// startTelemetryStream continuously reads system stats and pumps it through the Yamux stream
func startTelemetryStream(ctx context.Context, session *yamux.Session, errCh chan error) {
	// Let the system settle
	time.Sleep(2 * time.Second)

	stream, err := session.OpenStream()
	if err != nil {
		errCh <- fmt.Errorf("open telemetry stream failed: %w", err)
		return
	}
	defer stream.Close()

	// Handshake identifier for the server multiplexer
	if _, err := stream.Write([]byte("STATS\n")); err != nil {
		errCh <- fmt.Errorf("telemetry handshake write: %w", err)
		return
	}

	encoder := json.NewEncoder(stream)
	ticker := time.NewTicker(3 * time.Second) // Upload stats every 3s
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats := CollectStats()
			if err := encoder.Encode(stats); err != nil {
				// Stream broken
				log.Printf("[Agent] Telemetry stream broken: %v", err)
				errCh <- fmt.Errorf("telemetry encode: %w", err)
				return
			}
		}
	}
}
