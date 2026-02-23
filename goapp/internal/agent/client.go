package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"

	"vpshelper-go/internal/tunnel"
)

type DiscoverResponse struct {
	Success        bool   `json:"success"`
	NodeID         int64  `json:"node_id"`
	Name           string `json:"name"`
	Address        string `json:"address"`
	ReportInterval int    `json:"report_interval"` // seconds
	Error          string `json:"error"`
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

	reportInterval := dResp.ReportInterval
	if reportInterval <= 0 {
		reportInterval = 3
	}

	wsAddress := dResp.Address
	log.Printf("[Agent] 寻址成功: 节点ID=%d, 专属入口=%s, 汇报周期=%ds", dResp.NodeID, wsAddress, reportInterval)

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
	// intervalCh allows the server to push interval changes to the telemetry goroutine
	intervalCh := make(chan int, 4)

	// Stream 1: Telemetry (Push stats to server)
	go startTelemetryStream(ctx, session, reportInterval, intervalCh, errCh)

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
			go handleIncomingControlStream(stream, intervalCh)
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

// handleIncomingControlStream processes streams opened by the control center.
// It decodes a generic JSON ControlMsg and dispatches to the correct handler.
// New control types can be added by extending the switch below.
func handleIncomingControlStream(stream *yamux.Stream, intervalCh chan int) {
	defer stream.Close()

	var msg tunnel.ControlMsg
	if err := json.NewDecoder(stream).Decode(&msg); err != nil {
		log.Printf("[Agent] control stream decode error: %v", err)
		return
	}

	switch msg.Type {
	case "config":
		var cfg struct {
			ReportInterval int `json:"report_interval"`
		}
		if err := json.Unmarshal(msg.Payload, &cfg); err == nil && cfg.ReportInterval > 0 {
			log.Printf("[Agent] 服务端推送新汇报周期: %ds", cfg.ReportInterval)
			select {
			case intervalCh <- cfg.ReportInterval:
			default:
			}
		}

	case "upgrade":
		var payload struct {
			Secret string `json:"secret"`
			Host   string `json:"host"`
		}
		if err := json.Unmarshal(msg.Payload, &payload); err == nil && payload.Secret != "" {
			log.Printf("[Agent] 收到服务端在线更新指令，开始执行自动升级并重启...")
			go func() {
				script := fmt.Sprintf(`#!/bin/bash
sleep 2
curl -sSL https://raw.githubusercontent.com/fengzhanhuaer/VpsHelper/main/install-probe.sh > /tmp/install-probe.sh
chmod +x /tmp/install-probe.sh
/tmp/install-probe.sh --secret "%s" --host "%s"
rm -f /tmp/install-probe.sh /tmp/vpsprobe_upgrade_*.sh
`, payload.Secret, payload.Host)
				scriptPath := fmt.Sprintf("/tmp/vpsprobe_upgrade_%d.sh", time.Now().Unix())
				if err := os.WriteFile(scriptPath, []byte(script), 0755); err == nil {
					cmd := exec.Command("systemd-run", "--unit=vpsprobe-upgrade-"+strconv.FormatInt(time.Now().Unix(), 10), scriptPath)
					if err := cmd.Start(); err != nil {
						log.Printf("[Agent] 启动升级进程失败: %v", err)
					} else {
						log.Printf("[Agent] 已将升级任务投递给独立 systemd worker。")
					}
				}
			}()
		}

	default:
		log.Printf("[Agent] 未知控制消息类型: %s", msg.Type)
	}
}

// startTelemetryStream continuously reads system stats and pumps them through the Yamux stream.
// The reporting interval can be changed at runtime via intervalCh.
func startTelemetryStream(ctx context.Context, session *yamux.Session, initialInterval int, intervalCh <-chan int, errCh chan error) {
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
	currentInterval := time.Duration(initialInterval) * time.Second
	ticker := time.NewTicker(currentInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case newInterval := <-intervalCh:
			if newInterval > 0 {
				currentInterval = time.Duration(newInterval) * time.Second
				ticker.Reset(currentInterval)
				log.Printf("[Agent] 汇报周期已动态调整为 %ds", newInterval)
			}
		case <-ticker.C:
			rawStats := CollectStats()
			payload, err := json.Marshal(rawStats)
			if err != nil {
				log.Printf("[Agent] stats marshal error: %v", err)
				continue
			}
			msg := tunnel.TelemetryMsg{
				Type:    "stats",
				Payload: payload,
			}
			if err := encoder.Encode(msg); err != nil {
				log.Printf("[Agent] Telemetry stream broken: %v", err)
				errCh <- fmt.Errorf("telemetry encode: %w", err)
				return
			}
		}
	}
}
