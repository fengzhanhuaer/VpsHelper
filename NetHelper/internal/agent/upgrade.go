package agent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"NetHelper/internal/config"
	"NetHelper/internal/update"
	"NetHelper/internal/version"
)

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

// CheckUpdate checks for the latest version either directly or via the proxy endpoint
func CheckUpdate(ctx context.Context, cfg *config.Config, useProxy bool) (map[string]interface{}, error) {
	if !useProxy {
		info, rel, err := update.FetchLatestGitHubRelease(ctx, "fengzhanhuaer", "VpsHelper", "")
		if err != nil {
			return nil, fmt.Errorf("直连检查更新失败: %w", err)
		}
		if !info.OK {
			return nil, fmt.Errorf("直连检查更新返回错误: %s", info.Note)
		}
		
		urlsMap := make(map[string]string)
		for _, asset := range rel.Assets {
			name := strings.ToLower(asset.Name)
			if !strings.Contains(name, "nethelper") {
				continue
			}
			osName := "linux"
			if strings.Contains(name, "windows") {
				osName = "windows"
			} else if strings.Contains(name, "darwin") {
				osName = "darwin"
			}
			archName := "amd64"
			if strings.Contains(name, "arm64") || strings.Contains(name, "aarch64") {
				archName = "arm64"
			} else if strings.Contains(name, "386") {
				archName = "386"
			} else if strings.Contains(name, "arm") {
				archName = "arm"
			}
			urlsMap[osName+"_"+archName] = asset.BrowserDownload
		}
		
		urlsJSON, _ := json.Marshal(urlsMap)
		hasUpdate := false
		if version.Version != "dev" && info.TagName != version.Version {
			hasUpdate = true
		}

		return map[string]interface{}{
			"has_update": hasUpdate,
			"version":    info.TagName,
			"urls":       string(urlsJSON),
		}, nil
	}
	
	// Proxy fetch strategy
	if cfg.ServerUrl == "" || cfg.SecretKey == "" {
		return nil, errors.New("主控服务地址和密钥未配置")
	}
	
	baseURL := strings.TrimSuffix(cfg.ServerUrl, "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}
	
	// Assuming Master exposes an endpoint to query NetHelper releases via proxy, but vpsprobe API supports arbitrary URL proxy.
	// We will use the VpsHelper API directly and parse it via the generic download proxy.
	targetAPI := "https://api.github.com/repos/fengzhanhuaer/VpsHelper/releases/latest"
	proxyURL := fmt.Sprintf("%s/api/probe/download?url=%s", baseURL, url.QueryEscape(targetAPI))
	
	req, err := http.NewRequestWithContext(ctx, "GET", proxyURL, nil)
	if err != nil {
		return nil, err
	}
	
	nonce, _ := fetchChallengeNonce(ctx, baseURL) 
	req.Header.Set("Authorization", "Bearer "+cfg.SecretKey)
	AddProbeAuthHeaders(req, cfg.SecretKey, nonce)
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("代理检查更新失败: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("代理服务器返回状态异常: %d", resp.StatusCode)
	}
	
	// Parse GitHub release format locally
	var rel struct {
		TagName string `json:"tag_name"`
		Assets []struct {
			Name string `json:"name"`
			BrowserDownload string `json:"browser_download_url"`
		} `json:"assets"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("解析 Release 信息失败: %w", err)
	}
	
	urlsMap := make(map[string]string)
	for _, asset := range rel.Assets {
		name := strings.ToLower(asset.Name)
		if !strings.Contains(name, "nethelper") {
			continue
		}
		osName := "linux"
		if strings.Contains(name, "windows") {
			osName = "windows"
		} else if strings.Contains(name, "darwin") {
			osName = "darwin"
		}
		archName := "amd64"
		if strings.Contains(name, "arm64") || strings.Contains(name, "aarch64") {
			archName = "arm64"
		} else if strings.Contains(name, "386") {
			archName = "386"
		} else if strings.Contains(name, "arm") {
			archName = "arm"
		}
		urlsMap[osName+"_"+archName] = asset.BrowserDownload
	}
	urlsJSON, _ := json.Marshal(urlsMap)
	
	hasUpdate := false
	if version.Version != "dev" && rel.TagName != version.Version {
		hasUpdate = true
	}

	return map[string]interface{}{
		"has_update": hasUpdate,
		"version":    rel.TagName,
		"urls":       string(urlsJSON),
	}, nil
}

// probeDownloadViaProxy downloads an arbitrary URL through the master's proxy.
func probeDownloadViaProxy(ctx context.Context, host, secret, rawURL, destPath string) (string, error) {
	baseURL := strings.TrimSuffix(host, "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}
	proxyURL := fmt.Sprintf("%s/api/probe/download?url=%s", baseURL, url.QueryEscape(rawURL))

	req, err := http.NewRequestWithContext(ctx, "GET", proxyURL, nil)
	if err != nil {
		return "", err
	}

	nonce, _ := fetchChallengeNonce(ctx, baseURL) 
	req.Header.Set("Authorization", "Bearer "+secret)
	AddProbeAuthHeaders(req, secret, nonce)

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("通用代理下载失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("通用代理返回状态 %d", resp.StatusCode)
	}

	tmpPath := destPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return "", fmt.Errorf("创建临时文件失败: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()

	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := f.Write(buf[:n]); writeErr != nil {
				_ = f.Close()
				err = writeErr
				return "", fmt.Errorf("写入文件失败: %w", writeErr)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = f.Close()
			err = readErr
			return "", fmt.Errorf("下载流读取失败: %w", readErr)
		}
	}
	if err = f.Close(); err != nil {
		return "", fmt.Errorf("关闭文件失败: %w", err)
	}
	if err = os.Chmod(tmpPath, 0o755); err != nil {
		return "", fmt.Errorf("设置文件权限失败: %w", err)
	}
	if err = os.Rename(tmpPath, destPath); err != nil {
		return "", fmt.Errorf("移动文件失败: %w", err)
	}
	return destPath, nil
}

// directDownload downloads a given full string URL directly.
func directDownload(ctx context.Context, targetURL, destPath string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("直连下载失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("直连下载返回状态 %d", resp.StatusCode)
	}

	tmpPath := destPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return "", fmt.Errorf("创建临时文件失败: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()

	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := f.Write(buf[:n]); writeErr != nil {
				_ = f.Close()
				err = writeErr
				return "", fmt.Errorf("写入文件失败: %w", writeErr)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = f.Close()
			err = readErr
			return "", fmt.Errorf("流读取失败: %w", readErr)
		}
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	if err = os.Chmod(tmpPath, 0o755); err != nil {
		return "", err
	}
	if err = os.Rename(tmpPath, destPath); err != nil {
		return "", err
	}
	return destPath, nil
}

// DoUpdate performs the upgrade logic
func DoUpdate(ctx context.Context, cfg *config.Config, useProxy bool, targetVersion string, urlsDict string) error {
	log.Printf("[Agent] 准备执行自更新流程 (version=%s, use_proxy=%v)...", targetVersion, useProxy)

	if version.Version != "dev" && targetVersion == version.Version {
		log.Printf("[Agent] 当前版本 %s 已是目标版本，跳过升级", version.Version)
		return nil
	}

	// 1. Parse URLs Map
	var urls map[string]string
	if err := json.Unmarshal([]byte(urlsDict), &urls); err != nil {
		return fmt.Errorf("无法解析下载地址字典: %w", err)
	}

	// 2. Determine OS & Arch
	osArchKey := runtime.GOOS + "_" + runtime.GOARCH
	targetURL, ok := urls[osArchKey]
	if !ok {
		return fmt.Errorf("未找到适用于 %s 架构的发布程序", osArchKey)
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("无法获取当前执行路径: %w", err)
	}

	downloadPath := filepath.Join(filepath.Dir(exePath), "nethelper.download")
	backupPath := filepath.Join(filepath.Dir(exePath), "nethelper.backup")

	var tmpFile string

	if useProxy {
		if cfg.ServerUrl == "" || cfg.SecretKey == "" {
			return errors.New("通过代理下载失败：主控服务地址和密钥未配置")
		}
		log.Printf("[Agent] 将通过主控代理下载: %s", targetURL)
		tmpFile, err = probeDownloadViaProxy(ctx, cfg.ServerUrl, cfg.SecretKey, targetURL, downloadPath)
		if err != nil {
			return fmt.Errorf("主控代理下载失败: %w", err)
		}
	} else {
		log.Printf("[Agent] 将直接从 GitHub 下载: %s", targetURL)
		tmpFile, err = directDownload(ctx, targetURL, downloadPath)
		if err != nil {
			return fmt.Errorf("直连下载失败: %w", err)
		}
	}

	defer os.Remove(tmpFile)

	// ── 预检 ────────────────────────────────────────────────────────
	log.Printf("[Agent] 新版下载完成，执行可用性预检测试...")

	cmd := exec.CommandContext(ctx, tmpFile, "version")
	output, testErr := cmd.CombinedOutput()

	if testErr != nil && !strings.Contains(string(output), "NetHelper") {
		return fmt.Errorf("预检失败，拒绝升级: %v, 输出: %s", testErr, string(output))
	}

	// ── 热替换 ──────────────────────────────────────────────────────
	log.Printf("[Agent] 预检通过，正在执行程序文件热替换...")

	_ = os.Rename(exePath, backupPath)
	if replaceErr := os.Rename(tmpFile, exePath); replaceErr != nil {
		_ = os.Rename(backupPath, exePath)
		return fmt.Errorf("核心文件替换失败，尝试回滚: %w", replaceErr)
	}

	_ = os.Chmod(exePath, 0o755)
	log.Printf("[Agent] 文件替换完成，准备重启进程...")

	go func() {
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}()
	
	return nil
}
