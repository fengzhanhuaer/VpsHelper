package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	nurl "net/url"
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
	ServerURL      string `json:"server_url"`
	UpdatedAt      string `json:"updated_at"`
}

type cachedProbeNodeInfo struct {
	NodeID    int64  `json:"node_id"`
	Name      string `json:"name"`
	Address   string `json:"address"`
	DDNSAddress string `json:"ddns_address"`
	ServerURL string `json:"server_url"`
}

var (
	nodeInfoCacheMu     sync.RWMutex
	nodeInfoCacheLoaded bool
	nodeInfoCache       *cachedProbeNodeInfo
)

func GetProbeNodeInfo(ctx context.Context, cfg *config.Config, forceRefresh bool) (*ProbeNodeInfo, error) {
	if !forceRefresh {
		cached, err := loadCachedProbeNodeInfo()
		if err == nil {
			return cached, nil
		}
	}

	if cfg == nil || strings.TrimSpace(cfg.ServerUrl) == "" || strings.TrimSpace(cfg.SecretKey) == "" {
		cached, err := loadCachedProbeNodeInfo()
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
	discoverURL := strings.TrimSuffix(serverHost, "/") + "/api/probe/discover"

	req, err := http.NewRequestWithContext(ctx, "GET", discoverURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create discover request: %w", err)
	}
	AddProbeAuthHeaders(req, cfg.SecretKey, nonce)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch probe node info failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("主控返回异常状态: %d", resp.StatusCode)
	}

	var dResp DiscoverResponse
	if err := json.NewDecoder(resp.Body).Decode(&dResp); err != nil {
		return nil, fmt.Errorf("decode discover response: %w", err)
	}
	if !dResp.Success {
		return nil, fmt.Errorf("discover returned error: %s", dResp.Error)
	}

	info := &ProbeNodeInfo{
		NodeID:         dResp.NodeID,
		Name:           dResp.Name,
		Address:        dResp.Address,
		DDNSAddress:    deriveDDNSAddress(dResp.Address),
		ReportInterval: dResp.ReportInterval,
		ServerURL:      strings.TrimSpace(cfg.ServerUrl),
		UpdatedAt:      time.Now().Format(time.RFC3339),
	}

	if err := saveCachedProbeNodeInfo(info); err != nil {
		return nil, fmt.Errorf("save cached node info failed: %w", err)
	}

	return info, nil
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
	return filepath.Join(dataDir, "probe_node_info.json"), nil
}

func loadCachedProbeNodeInfo() (*ProbeNodeInfo, error) {
	nodeInfoCacheMu.RLock()
	if nodeInfoCacheLoaded && nodeInfoCache != nil {
		cache := *nodeInfoCache
		nodeInfoCacheMu.RUnlock()
		return cachedToProbeInfo(&cache), nil
	}
	nodeInfoCacheMu.RUnlock()

	path, err := nodeInfoFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cache := &cachedProbeNodeInfo{}
	if err := json.Unmarshal(data, cache); err != nil {
		return nil, err
	}

	nodeInfoCacheMu.Lock()
	nodeInfoCacheLoaded = true
	nodeInfoCache = &cachedProbeNodeInfo{
		NodeID:      cache.NodeID,
		Name:        cache.Name,
		Address:     cache.Address,
		DDNSAddress: cache.DDNSAddress,
		ServerURL:   cache.ServerURL,
	}
	nodeInfoCacheMu.Unlock()

	return cachedToProbeInfo(cache), nil
}

func saveCachedProbeNodeInfo(info *ProbeNodeInfo) error {
	path, err := nodeInfoFilePath()
	if err != nil {
		return err
	}
	cache := &cachedProbeNodeInfo{
		NodeID:    info.NodeID,
		Name:      info.Name,
		Address:   info.Address,
		DDNSAddress: info.DDNSAddress,
		ServerURL: info.ServerURL,
	}

	nodeInfoCacheMu.Lock()
	if nodeInfoCacheLoaded && nodeInfoCache != nil &&
		nodeInfoCache.NodeID == cache.NodeID &&
		nodeInfoCache.Name == cache.Name &&
		nodeInfoCache.Address == cache.Address &&
		nodeInfoCache.DDNSAddress == cache.DDNSAddress &&
		nodeInfoCache.ServerURL == cache.ServerURL {
		nodeInfoCacheMu.Unlock()
		return nil
	}
	nodeInfoCacheLoaded = true
	nodeInfoCache = &cachedProbeNodeInfo{
		NodeID:      cache.NodeID,
		Name:        cache.Name,
		Address:     cache.Address,
		DDNSAddress: cache.DDNSAddress,
		ServerURL:   cache.ServerURL,
	}
	nodeInfoCacheMu.Unlock()

	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func cachedToProbeInfo(cache *cachedProbeNodeInfo) *ProbeNodeInfo {
	return &ProbeNodeInfo{
		NodeID:      cache.NodeID,
		Name:        cache.Name,
		Address:     cache.Address,
		DDNSAddress: cache.DDNSAddress,
		ServerURL:   cache.ServerURL,
	}
}

func deriveDDNSAddress(address string) string {
	address = strings.TrimSpace(address)
	if address == "" {
		return ""
	}

	u, err := nurl.Parse(address)
	if err == nil && u.Hostname() != "" {
		return u.Hostname()
	}

	if strings.Contains(address, "://") {
		return ""
	}
	if strings.Contains(address, "/") {
		parts := strings.Split(address, "/")
		if len(parts) > 0 {
			address = parts[0]
		}
	}
	if strings.Contains(address, ":") {
		host := strings.Split(address, ":")[0]
		return strings.TrimSpace(host)
	}
	return address
}
