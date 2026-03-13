package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"NetHelper/internal/config"
)

type ProbeNodeInfo struct {
	NodeID         int64  `json:"node_id"`
	Name           string `json:"name"`
	Address        string `json:"address"`
	DDNSAddress    string `json:"ddns_address"`
	ReportInterval int    `json:"report_interval"`
	Online         bool   `json:"online"`
	Version        string `json:"version"`
	LastPing       int64  `json:"last_ping"`
	LastPingStr    string `json:"last_ping_str"`
	ServerURL      string `json:"server_url"`
	UpdatedAt      string `json:"updated_at"`
}

type cachedProbeNodeInfo struct {
	NodeID      int64  `json:"node_id"`
	Name        string `json:"name"`
	Address     string `json:"address"`
	DDNSAddress string `json:"ddns_address"`
	ServerURL   string `json:"server_url"`
}

var (
	probeNodesCacheMu     sync.RWMutex
	probeNodesCacheLoaded bool
	probeNodesCache       []cachedProbeNodeInfo
)

func GetProbeNodesInfo(ctx context.Context, cfg *config.Config, forceRefresh bool) ([]ProbeNodeInfo, error) {
	if !forceRefresh {
		cached, err := loadCachedProbeNodesInfo()
		if err == nil {
			return cached, nil
		}
	}

	if cfg == nil || strings.TrimSpace(cfg.ServerUrl) == "" || strings.TrimSpace(cfg.SecretKey) == "" {
		cached, err := loadCachedProbeNodesInfo()
		if err == nil {
			return cached, nil
		}
		return nil, errors.New("主控服务地址或密钥未配置")
	}

	serverHost := strings.TrimSpace(cfg.ServerUrl)
	if !strings.HasPrefix(serverHost, "http") {
		serverHost = "https://" + serverHost
	}

	nonce, _ := fetchChallengeNonce(ctx, serverHost)
	apiURL := strings.TrimSuffix(serverHost, "/") + "/api/probe/nodes"

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create probe nodes request: %w", err)
	}
	AddProbeAuthHeaders(req, cfg.SecretKey, nonce)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch probe nodes failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("主控返回异常状态: %d", resp.StatusCode)
	}

	var apiResp struct {
		Success bool `json:"success"`
		Nodes   []struct {
			NodeID         int64  `json:"node_id"`
			Name           string `json:"name"`
			Address        string `json:"address"`
			DDNSAddress    string `json:"ddns_address"`
			ReportInterval int    `json:"report_interval"`
			Online         bool   `json:"online"`
			Version        string `json:"version"`
			LastPing       int64  `json:"last_ping"`
			LastPingStr    string `json:"last_ping_str"`
		} `json:"nodes"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decode probe nodes response: %w", err)
	}
	if !apiResp.Success {
		if apiResp.Error == "" {
			apiResp.Error = "unknown error"
		}
		return nil, fmt.Errorf("probe nodes api error: %s", apiResp.Error)
	}

	now := time.Now().Format(time.RFC3339)
	serverURL := strings.TrimSpace(cfg.ServerUrl)
	nodes := make([]ProbeNodeInfo, 0, len(apiResp.Nodes))
	for _, n := range apiResp.Nodes {
		nodes = append(nodes, ProbeNodeInfo{
			NodeID:         n.NodeID,
			Name:           n.Name,
			Address:        n.Address,
			DDNSAddress:    n.DDNSAddress,
			ReportInterval: n.ReportInterval,
			Online:         n.Online,
			Version:        n.Version,
			LastPing:       n.LastPing,
			LastPingStr:    n.LastPingStr,
			ServerURL:      serverURL,
			UpdatedAt:      now,
		})
	}

	if err := saveCachedProbeNodesInfo(nodes); err != nil {
		return nil, fmt.Errorf("save cached probe nodes failed: %w", err)
	}

	return nodes, nil
}

func nodeInfoFilePath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	exeDir := filepath.Dir(exePath)
	dataDir := filepath.Join(exeDir, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dataDir, "probe_nodes_info.json"), nil
}

func loadCachedProbeNodesInfo() ([]ProbeNodeInfo, error) {
	probeNodesCacheMu.RLock()
	if probeNodesCacheLoaded {
		cached := make([]cachedProbeNodeInfo, len(probeNodesCache))
		copy(cached, probeNodesCache)
		probeNodesCacheMu.RUnlock()
		return cachedToProbeNodes(cached), nil
	}
	probeNodesCacheMu.RUnlock()

	path, err := nodeInfoFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cached := make([]cachedProbeNodeInfo, 0)
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, err
	}

	probeNodesCacheMu.Lock()
	probeNodesCacheLoaded = true
	probeNodesCache = make([]cachedProbeNodeInfo, len(cached))
	copy(probeNodesCache, cached)
	probeNodesCacheMu.Unlock()

	return cachedToProbeNodes(cached), nil
}

func saveCachedProbeNodesInfo(nodes []ProbeNodeInfo) error {
	path, err := nodeInfoFilePath()
	if err != nil {
		return err
	}

	cached := make([]cachedProbeNodeInfo, 0, len(nodes))
	for _, n := range nodes {
		cached = append(cached, cachedProbeNodeInfo{
			NodeID:      n.NodeID,
			Name:        n.Name,
			Address:     n.Address,
			DDNSAddress: n.DDNSAddress,
			ServerURL:   n.ServerURL,
		})
	}

	probeNodesCacheMu.Lock()
	if probeNodesCacheLoaded && cachedNodesEqual(probeNodesCache, cached) {
		probeNodesCacheMu.Unlock()
		return nil
	}
	probeNodesCacheLoaded = true
	probeNodesCache = make([]cachedProbeNodeInfo, len(cached))
	copy(probeNodesCache, cached)
	probeNodesCacheMu.Unlock()

	data, err := json.MarshalIndent(cached, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func cachedToProbeNodes(cached []cachedProbeNodeInfo) []ProbeNodeInfo {
	nodes := make([]ProbeNodeInfo, 0, len(cached))
	for _, c := range cached {
		nodes = append(nodes, ProbeNodeInfo{
			NodeID:      c.NodeID,
			Name:        c.Name,
			Address:     c.Address,
			DDNSAddress: c.DDNSAddress,
			ServerURL:   c.ServerURL,
		})
	}
	return nodes
}

func cachedNodesEqual(a, b []cachedProbeNodeInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].NodeID != b[i].NodeID ||
			a[i].Name != b[i].Name ||
			a[i].Address != b[i].Address ||
			a[i].DDNSAddress != b[i].DDNSAddress ||
			a[i].ServerURL != b[i].ServerURL {
			return false
		}
	}
	return true
}
