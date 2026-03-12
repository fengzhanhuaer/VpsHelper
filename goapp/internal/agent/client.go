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
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"

	"vpshelper-go/internal/logger"
	"vpshelper-go/internal/shell"
	"vpshelper-go/internal/tunnel"
	"vpshelper-go/internal/version"
)

type PingTaskInfo struct {
	ID             int64  `json:"id"`
	Target         string `json:"target"`
	ReportInterval int    `json:"report_interval"`
}

type DiscoverResponse struct {
	Success        bool           `json:"success"`
	NodeID         int64          `json:"node_id"`
	Name           string         `json:"name"`
	Address        string         `json:"address"`
	ReportInterval int            `json:"report_interval"` // seconds
	PingTasks      []PingTaskInfo `json:"ping_tasks"`
	Error          string         `json:"error"`
}

type CertResponse struct {
	Success    bool   `json:"success"`
	Domain     string `json:"domain"`
	TLSCertPem string `json:"tls_cert_pem"`
	TLSKeyPem  string `json:"tls_key_pem"`
	Error      string `json:"error"`
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

func fetchOutboundIPs(ctx context.Context) string {
	// 给出3秒超时以避免卡死探针的长链接建立
	subCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	v4Chan := make(chan string, 1)
	v6Chan := make(chan string, 1)

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
	go fetchIP("https://v6.ident.me", v6Chan)

	v4 := <-v4Chan
	v6 := <-v6Chan

	if v4 != "" && v6 != "" && v4 != v6 {
		return v4 + "," + v6
	}
	if v4 != "" {
		return v4
	}
	if v6 != "" {
		return v6
	}
	return ""
}

// fetchChallengeNonce retrieves a short-lived nonce from the master server.
func fetchChallengeNonce(ctx context.Context, serverHost string) (string, error) {
	url := serverHost
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}
	url = strings.TrimRight(url, "/") + "/api/probe/challenge"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad status code: %d", resp.StatusCode)
	}
	var res struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", err
	}
	return res.Nonce, nil
}

// AddProbeAuthHeaders injects the Anti-Replay HMAC verification headers into the given request.
func AddProbeAuthHeaders(req *http.Request, secret, nonce string) {
	if nonce == "" {
		return
	}
	hID := sha256.Sum256([]byte(secret))
	probeID := hex.EncodeToString(hID[:])

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(nonce))
	sig := hex.EncodeToString(mac.Sum(nil))

	req.Header.Set("X-Probe-ID", probeID)
	req.Header.Set("X-Probe-Nonce", nonce)
	req.Header.Set("X-Probe-Signature", sig)
}

// fetchCertificate securely retrieves the TLS certificate assigned to this node by the Master Node.
// It implements basic caching: if a valid certificate is already present locally, it skips the network request.
func fetchCertificate(ctx context.Context, serverHost, secret string) error {
	// Simple caching: check if cert already exists and is reasonably valid.
	certPath := tunnel.GetLocalNodeCertPath()
	keyPath := tunnel.GetLocalNodeKeyPath()
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			// If files exist, we skip downloading to avoid hammering the control center.
			// Detailed expiry checking can be added if the probe needs to independently renew,
			// but currently the master handles renewal and pushes/pulls can be event-driven.
			// For now, if we have a cert, we trust it's the latest pulled or will be updated on next restart.
			log.Printf("[Agent] 本地已存在通过中心下发的归属证书缓存，跳过拉取 [%s]", certPath)
			return nil
		}
	}

	url := serverHost
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}
	url = strings.TrimRight(url, "/") + "/api/probe/cert"

	nonce, err := fetchChallengeNonce(ctx, serverHost)
	if err != nil {
		return fmt.Errorf("fetch cert nonce: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("create cert request: %w", err)
	}
	AddProbeAuthHeaders(req, secret, nonce)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("do cert request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// No certificate provisioned yet, which is normal for a fresh node or if auto_tls is off.
		log.Printf("[Agent] 该节点尚未在中心分配或生成专属证书。")
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("cert fetch failed with status %d: %s", resp.StatusCode, string(body))
	}

	var cResp CertResponse
	if err := json.NewDecoder(resp.Body).Decode(&cResp); err != nil {
		return fmt.Errorf("decode cert response: %w", err)
	}

	if !cResp.Success || cResp.Domain == "" || cResp.TLSCertPem == "" {
		return fmt.Errorf("cert fetch returned error or incomplete data: %s", cResp.Error)
	}

	// Save to local storage for the tunnel listener to use
	if err := os.WriteFile(certPath, []byte(cResp.TLSCertPem), 0600); err != nil {
		return fmt.Errorf("write cert_pem failed: %w", err)
	}
	if err := os.WriteFile(keyPath, []byte(cResp.TLSKeyPem), 0600); err != nil {
		return fmt.Errorf("write key_pem failed: %w", err)
	}

	log.Printf("[Agent] 成功加载中心下发的专属 TLS 证书: %s", cResp.Domain)
	return nil
}

func connectAndServe(ctx context.Context, serverHost, secret string) error {
	// 0.5. Fetch and Cache Assigned Certificate (Temporarily disabled)
	// if err := fetchCertificate(ctx, serverHost, secret); err != nil {
	// 	log.Printf("[Agent] 拉取证书时发生错误: %v", err)
	// }

	// 1. Discover Real Address
	nonce, err := fetchChallengeNonce(ctx, serverHost)
	if err != nil {
		log.Printf("[Agent] Failed to fetch challenge nonce, will try without it: %v", err)
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

	reportInterval := dResp.ReportInterval
	if reportInterval <= 0 {
		reportInterval = 3
	}

	wsAddress := dResp.Address
	log.Printf("[Agent] 寻址成功: 节点ID=%d, 专属入口=%s, 汇报周期=%ds", dResp.NodeID, wsAddress, reportInterval)

	// 2. Establish WebSocket direct to private port
	dialer := websocket.DefaultDialer
	wsHeader := http.Header{}

	// Re-calculate nonce and sig for WS handshake to avoid replay
	wsNonce, err := fetchChallengeNonce(ctx, serverHost)
	if err != nil {
		log.Printf("[Agent] Failed to fetch nonce for tunnel: %v", err)
	}
	var wsSig string
	var wsProbeID string
	if wsNonce != "" {
		hID := sha256.Sum256([]byte(secret))
		wsProbeID = hex.EncodeToString(hID[:])

		wsMac := hmac.New(sha256.New, []byte(secret))
		wsMac.Write([]byte(wsNonce))
		wsSig = hex.EncodeToString(wsMac.Sum(nil))
	}

	wsHeader.Set("X-Probe-Version", version.Version)
	if wsNonce != "" {
		wsHeader.Set("X-Probe-ID", wsProbeID)
		wsHeader.Set("X-Probe-Nonce", wsNonce)
		wsHeader.Set("X-Probe-Signature", wsSig)
	}

	reportedIP := fetchOutboundIPs(ctx)
	if reportedIP != "" {
		wsHeader.Set("X-Probe-IP", reportedIP)
		log.Printf("[Agent] 已自主探明外网出口IP: %s", reportedIP)
	}

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
	intervalCh := make(chan int, 4)
	pingIntervalCh := make(chan int, 4)
	// pingTasksCh receives new ping tasks configurations from server
	pingTasksCh := make(chan []PingTaskInfo, 2)
	pingTasksCh <- dResp.PingTasks // Initial set from discover

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
			go handleIncomingControlStream(stream, session, intervalCh, pingIntervalCh, pingTasksCh, secret)
		}
	}()

	// Start ping worker loop
	go startPingWorker(ctx, session, dResp.PingTasks, reportInterval, pingTasksCh, pingIntervalCh, errCh)

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
func handleIncomingControlStream(stream *yamux.Stream, session *yamux.Session, intervalCh chan int, pingIntervalCh chan int, pingTasksCh chan []PingTaskInfo, currentSecret string) {
	defer stream.Close()

	var msg tunnel.ControlMsg
	decoder := json.NewDecoder(stream)
	if err := decoder.Decode(&msg); err != nil {
		log.Printf("[Agent] control stream decode error: %v", err)
		return
	}

	switch msg.Type {
	case "shell":
		// Hijack the stream for raw PTY shell interaction.
		// decoder.Buffered() contains any bytes the JSON decoder consumed past the first JSON message.
		handleAgentShell(stream, decoder.Buffered())
		return
	case "log":
		stream.Write([]byte(logger.GetLogs()))
		return
	case "exec_cmd":
		var payload struct {
			CWD     string `json:"cwd"`
			Command string `json:"command"`
		}
		if err := json.Unmarshal(msg.Payload, &payload); err == nil {
			cwd := shell.ResolveCWD(payload.CWD)
			if newCWD, ok, outMsg := shell.ApplyCD(cwd, payload.Command); ok {
				resp, _ := json.Marshal(map[string]interface{}{
					"ok":     true,
					"output": outMsg,
					"cwd":    newCWD,
				})
				stream.Write(resp)
				return
			}
			ok, output, _ := shell.Run(context.Background(), cwd, payload.Command)
			resp, _ := json.Marshal(map[string]interface{}{
				"ok":     ok,
				"output": output,
				"cwd":    cwd,
			})
			stream.Write(resp)
		}
		return
	case "config":
		var cfg struct {
			ReportInterval     *int `json:"report_interval"`
			PingReportInterval *int `json:"ping_report_interval"`
		}
		if err := json.Unmarshal(msg.Payload, &cfg); err == nil {
			if cfg.ReportInterval != nil && *cfg.ReportInterval > 0 {
				log.Printf("[Agent] 服务端推送新系统状态汇报周期: %ds", *cfg.ReportInterval)
				select {
				case intervalCh <- *cfg.ReportInterval:
				default:
				}
			}
			if cfg.PingReportInterval != nil && *cfg.PingReportInterval > 0 {
				log.Printf("[Agent] 服务端推送新网络拨测汇报周期: %ds", *cfg.PingReportInterval)
				select {
				case pingIntervalCh <- *cfg.PingReportInterval:
				default:
				}
			}
		}

	case "ping_tasks":
		var tasks []PingTaskInfo
		if err := json.Unmarshal(msg.Payload, &tasks); err == nil {
			log.Printf("[Agent] 服务端推送新拨测任务配置: 收到 %d 个任务", len(tasks))
			select {
			case pingTasksCh <- tasks:
			default:
			}
		}

	case "upgrade":
		var payload struct {
			Secret   string `json:"secret"`
			Host     string `json:"host"`
			UseProxy string `json:"use_proxy"`
			Version  string `json:"version"`
			URLs     string `json:"urls"`
		}
		if err := json.Unmarshal(msg.Payload, &payload); err == nil && payload.Secret != "" {
			useProxy := payload.UseProxy == "proxy"
			handleAgentUpgradeTrigger(payload.Secret, payload.Host, useProxy, payload.Version, payload.URLs, session)
		}

	case "update_master_address":
		var payload struct {
			Host string `json:"host"`
		}
		if err := json.Unmarshal(msg.Payload, &payload); err == nil && payload.Host != "" {
			log.Printf("[Agent] 服务端推送了新的主控地址: %s, 正在更新本地配置文件...", payload.Host)
			cfg, _ := LoadConfig()
			cfg.Host = payload.Host
			if cfg.Secret == "" {
				cfg.Secret = currentSecret
			}
			if err := SaveConfig(cfg); err != nil {
				log.Printf("[Agent] 报错：无法保存主控地址到配置文件: %v", err)
			} else {
				log.Printf("[Agent] 配置文件更新成功，准备重启探针以应用配置...")
				go func() {
					time.Sleep(2 * time.Second)
					os.Exit(0)
				}()
			}
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

func startPingWorker(ctx context.Context, session *yamux.Session, initialTasks []PingTaskInfo, initialInterval int, pingTasksCh <-chan []PingTaskInfo, pingIntervalCh <-chan int, errCh chan<- error) {
	tasks := initialTasks

	// Start with default 60s unless dynamically updated to something else.
	// But if initial is passed, maybe use it? Let's cap at 60s minimum for default ping, except when dashboard forces 5s.
	globalOverride := 0
	if initialInterval == 5 {
		globalOverride = 5
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	lastRun := make(map[int64]time.Time)

	for {
		select {
		case <-ctx.Done():
			return
		case newTasks := <-pingTasksCh:
			tasks = newTasks
			log.Printf("[Agent] Ping Worker 检测到任务列表更新，当前共 %d 个任务", len(tasks))

			// cleanup removed tasks from lastRun tracker
			active := make(map[int64]bool)
			for _, t := range tasks {
				active[t.ID] = true
			}
			for id := range lastRun {
				if !active[id] {
					delete(lastRun, id)
				}
			}

		case newInterval := <-pingIntervalCh:
			if newInterval > 0 {
				if newInterval <= 5 {
					globalOverride = newInterval
				} else {
					globalOverride = 0
				}
				log.Printf("[Agent] 拨测采集周期收到动态指令: globalOverride=%ds", globalOverride)
			}
		case <-ticker.C:
			if len(tasks) > 0 {
				now := time.Now()
				var toRun []PingTaskInfo

				for _, t := range tasks {
					interval := t.ReportInterval
					if interval <= 0 {
						interval = 60
					}
					if globalOverride > 0 {
						interval = globalOverride
					}

					last, ok := lastRun[t.ID]
					if !ok || now.Sub(last) >= time.Duration(interval)*time.Second {
						toRun = append(toRun, t)
						lastRun[t.ID] = now
					}
				}

				if len(toRun) == 0 {
					continue
				}

				results := make(map[int64]map[string]float64)
				for _, t := range toRun {
					latencyMs, lossPct, ok := doPing(ctx, t.Target)
					if ok || lossPct == 100 {
						results[t.ID] = map[string]float64{
							"latency": latencyMs,
							"loss":    lossPct,
						}
					}
				}

				if len(results) > 0 {
					payload, _ := json.Marshal(results)
					msg := tunnel.TelemetryMsg{
						Type:    "ping_results",
						Payload: payload,
					}

					// Open a short-lived stream to push the results
					go func(msg tunnel.TelemetryMsg) {
						if session.IsClosed() {
							return
						}
						stream, err := session.OpenStream()
						if err != nil {
							return
						}
						defer stream.Close()
						fmt.Fprintln(stream, "STATS")
						_ = json.NewEncoder(stream).Encode(msg)
					}(msg)
				}
			}
		}
	}
}
