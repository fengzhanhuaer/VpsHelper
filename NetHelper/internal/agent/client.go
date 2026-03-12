package agent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"

	"NetHelper/internal/config"
	"NetHelper/internal/version"
)

type DiscoverResponse struct {
	Success        bool   `json:"success"`
	NodeID         int64  `json:"node_id"`
	Name           string `json:"name"`
	Address        string `json:"address"`
	ReportInterval int    `json:"report_interval"`
	Error          string `json:"error"`
}

// Start manages the lifecycle of the NetHelper connection to the control center
func Start(ctx context.Context, cfg *config.Config) {
	if cfg == nil || cfg.ServerUrl == "" || cfg.SecretKey == "" {
		log.Printf("[NetHelper Agent] 未配置主控服务地址或密钥，不启动长连接服务。")
		return
	}

	go func() {
		delay := 2 * time.Second
		for {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("[NetHelper Agent] 正在连接主控中心: %s", cfg.ServerUrl)
				err := connectAndServe(ctx, cfg.ServerUrl, cfg.SecretKey)
				if err != nil {
					log.Printf("[NetHelper Agent] 隧道中断或失败: %v, 将在 %s 后重试...", err, delay)
					time.Sleep(delay)
					if delay < 30*time.Second {
						delay *= 2
					}
				} else {
					delay = 2 * time.Second
				}
			}
		}
	}()
}

// WsConn wraps a gorilla websocket to provide io.ReadWriteCloser methods
type WsConn struct {
	Conn *websocket.Conn
}
func (c *WsConn) Read(b []byte) (n int, err error) {
	_, r, err := c.Conn.NextReader()
	if err != nil {
		return 0, err
	}
	return r.Read(b)
}
func (c *WsConn) Write(b []byte) (n int, err error) {
	err = c.Conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
func (c *WsConn) Close() error {
	return c.Conn.Close()
}

func fetchOutboundIPs(ctx context.Context) string {
	subCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	v4Chan := make(chan string, 1)
	fetchIP := func(url string, ch chan string) {
		req, err := http.NewRequestWithContext(subCtx, "GET", url, nil)
		if err != nil {
			ch <- ""
			return
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			ch <- ""
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		ip := strings.TrimSpace(string(body))
		if len(ip) > 5 && len(ip) < 50 && !strings.Contains(ip, "<") {
			ch <- ip
		} else {
			ch <- ""
		}
	}
	go fetchIP("https://v4.ident.me", v4Chan)
	return <-v4Chan
}

func connectAndServe(ctx context.Context, serverHost, secret string) error {
	nonce, err := fetchChallengeNonce(ctx, serverHost)
	if err != nil {
		log.Printf("[NetHelper Agent] Failed to fetch challenge nonce: %v", err)
	}
	if !strings.HasPrefix(serverHost, "http") {
		serverHost = "https://" + serverHost
	}
	discoverURL := strings.TrimSuffix(serverHost, "/") + "/api/probe/discover"

	req, err := http.NewRequestWithContext(ctx, "GET", discoverURL, nil)
	if err != nil {
		return fmt.Errorf("create discover request: %w", err)
	}
	AddProbeAuthHeaders(req, secret, nonce)

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
	log.Printf("[NetHelper Agent] 寻址成功: 节点ID=%d, 专属入口=%s", dResp.NodeID, wsAddress)

	dialer := websocket.DefaultDialer
	wsHeader := http.Header{}

	wsNonce, err := fetchChallengeNonce(ctx, serverHost)
	if err != nil {
		log.Printf("[NetHelper Agent] Failed to fetch nonce for tunnel: %v", err)
	}
	
	if wsNonce != "" {
		hID := sha256.Sum256([]byte(secret))
		wsProbeID := hex.EncodeToString(hID[:])
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(wsNonce))
		wsSig := hex.EncodeToString(mac.Sum(nil))

		wsHeader.Set("X-Probe-ID", wsProbeID)
		wsHeader.Set("X-Probe-Nonce", wsNonce)
		wsHeader.Set("X-Probe-Signature", wsSig)
	}

	wsHeader.Set("X-Probe-Version", "NetHelper_v"+version.Version)
	
	reportedIP := fetchOutboundIPs(ctx)
	if reportedIP != "" {
		wsHeader.Set("X-Probe-IP", reportedIP)
	}

	// Make WebSocket Connection
	conn, _, err := dialer.DialContext(ctx, wsAddress, wsHeader)
	if err != nil {
		return fmt.Errorf("websocket dial to %s: %w", wsAddress, err)
	}

	log.Printf("[NetHelper Agent] WebSocket 建立成功, 正在提升为 Yamux 多路复用隧道...")

	wsConn := &WsConn{Conn: conn}

	conf := yamux.DefaultConfig()
	conf.EnableKeepAlive = true

	session, err := yamux.Client(wsConn, conf)
	if err != nil {
		conn.Close()
		return fmt.Errorf("yamux client init: %w", err)
	}

	log.Printf("[NetHelper Agent] Yamux 隧道连接已开启并就绪！供未来扩展。")

	errCh := make(chan error, 1)

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

	// Accept inbound streams from server (To be implemented when extending NetHelper via Master)
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
			// Close it straight away since we aren't handling server-side commands yet.
			stream.Close()
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
