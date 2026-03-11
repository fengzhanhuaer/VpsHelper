package agent

import (
	"context"
	"encoding/json"
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
	"vpshelper-go/internal/update"
	"vpshelper-go/internal/version"

	"github.com/hashicorp/yamux"
)

// probeDownloadViaProxy downloads an arbitrary URL through the master's
// generic /api/probe/download proxy endpoint (authenticated with probe secret).
func probeDownloadViaProxy(ctx context.Context, host, secret, rawURL, destPath string, onProgress update.ProgressCallback) (string, error) {
	baseURL := strings.TrimSuffix(host, "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}
	proxyURL := fmt.Sprintf("%s/api/probe/download?url=%s", baseURL, url.QueryEscape(rawURL))

	req, err := http.NewRequestWithContext(ctx, "GET", proxyURL, nil)
	if err != nil {
		return "", err
	}

	nonce, _ := fetchChallengeNonce(ctx, baseURL) // Allow silent failure, AddProbeAuthHeaders handles empty nonce

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

	total := resp.ContentLength
	var received int64
	lastPercent := -1
	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := f.Write(buf[:n]); writeErr != nil {
				_ = f.Close()
				err = writeErr
				return "", fmt.Errorf("写入文件失败: %w", writeErr)
			}
			received += int64(n)
			if total > 0 && onProgress != nil {
				percent := int(float64(received) / float64(total) * 100)
				if percent%10 == 0 && percent != lastPercent {
					onProgress(update.DownloadProgress{Received: received, Total: total})
					lastPercent = percent
				}
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

// directDownload downloads a given full string URL directly (without GitHub API wrapper).
func directDownload(ctx context.Context, targetURL, destPath string, onProgress update.ProgressCallback) (string, error) {
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

	total := resp.ContentLength
	var received int64
	lastPercent := -1
	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := f.Write(buf[:n]); writeErr != nil {
				_ = f.Close()
				err = writeErr
				return "", fmt.Errorf("写入文件失败: %w", writeErr)
			}
			received += int64(n)
			if total > 0 && onProgress != nil {
				percent := int(float64(received) / float64(total) * 100)
				if percent%10 == 0 && percent != lastPercent {
					onProgress(update.DownloadProgress{Received: received, Total: total})
					lastPercent = percent
				}
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

// handleAgentUpgradeTrigger is called when the server sends an "upgrade" control message.
// The server has already queried the GitHub release and packed all URLs into a dictionary.
func handleAgentUpgradeTrigger(secret, host string, useProxy bool, targetVersion, urlsDict string, session *yamux.Session) {
	log.Printf("[Agent] 收到服务端在线更新指令 (version=%s, use_proxy=%v)，准备执行自更新流程...", targetVersion, useProxy)

	sendProgress := func(msg string) {
		if session == nil || session.IsClosed() {
			return
		}
		stream, err := session.OpenStream()
		if err == nil {
			defer stream.Close()
			_, _ = stream.Write([]byte("UPGRADE_PROGRESS\n"))
			_ = json.NewEncoder(stream).Encode(map[string]string{"progress": msg})
		}
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		if version.Version != "dev" && targetVersion == version.Version {
			log.Printf("[Agent] 当前版本 %s 已是目标版本，跳过升级", version.Version)
			sendProgress("当前已是最新版，无需升级")
			return
		}

		// 1. Parse URLs Map
		var urls map[string]string
		if err := json.Unmarshal([]byte(urlsDict), &urls); err != nil {
			log.Printf("[Agent] 无法解析主控下发的下载地址字典: %v", err)
			sendProgress("解析下载地址失败，升级中止")
			return
		}

		// 2. Determine OS & Arch
		osArchKey := runtime.GOOS + "_" + runtime.GOARCH
		targetURL, ok := urls[osArchKey]
		if !ok {
			log.Printf("[Agent] 主控字典中找不到适配当前平台 %s 的下载链接: %s", osArchKey, urlsDict)
			sendProgress(fmt.Sprintf("未找到适用于 %s 架构的发布程序", osArchKey))
			return
		}

		exePath, err := os.Executable()
		if err != nil {
			log.Printf("[Agent] 无法获取当前执行路径: %v", err)
			return
		}

		downloadPath := filepath.Join(filepath.Dir(exePath), "vpsprobe.download")
		backupPath := filepath.Join(filepath.Dir(exePath), "vpsprobe.backup")

		lastPercent := -1
		progressCb := func(p update.DownloadProgress) {
			if p.Total > 0 {
				percent := int(float64(p.Received) / float64(p.Total) * 100)
				if percent%10 == 0 && percent != lastPercent {
					log.Printf("[Agent] 下载进度: %d%% (%d / %d bytes)", percent, p.Received, p.Total)
					sendProgress(fmt.Sprintf("下载进度: %d%%", percent))
					lastPercent = percent
				}
			}
		}

		var tmpFile string

		if useProxy {
			// ── 代理下载路径 ────────────────────────────────────────────────
			log.Printf("[Agent] 将通过主控代理下载探针包: %s", targetURL)
			sendProgress("通过主控代理下载最新探针包...")
			tmpFile, err = probeDownloadViaProxy(ctx, host, secret, targetURL, downloadPath, progressCb)
			if err != nil {
				log.Printf("[Agent] 主控代理下载失败: %v", err)
				sendProgress("更新失败: 主控代理下载失败 - " + err.Error())
				return
			}
		} else {
			// ── 直连 GitHub 下载路径 ──────────────────────────────────────
			log.Printf("[Agent] 将直接从 GitHub 下载探针包: %s", targetURL)
			sendProgress("开始从 GitHub 直连下载新版本...")
			tmpFile, err = directDownload(ctx, targetURL, downloadPath, progressCb)
			if err != nil {
				log.Printf("[Agent] GitHub 直连下载失败: %v", err)
				sendProgress("直连下载失败: " + err.Error())
				return
			}
		}

		defer os.Remove(tmpFile)

		// ── 预检 ────────────────────────────────────────────────────────
		log.Printf("[Agent] 新版下载完成，执行预检测试...")
		sendProgress("下载完成，执行预检测试...")

		cmd := exec.CommandContext(ctx, tmpFile)
		cmd.Env = append(os.Environ(), "VPSHELPER_UPDATE_TEST=1")
		output, testErr := cmd.CombinedOutput()

		if testErr != nil {
			log.Printf("[Agent] 新版预检失败，拒绝升级: %v, 输出: %s", testErr, string(output))
			sendProgress("预检失败，拒绝升级")
			return
		}

		if !strings.Contains(string(output), "VPSHELPER_UPDATE_TEST is active") {
			log.Printf("[Agent] 警告: 未在预检中检测出测试输出标记。输出: %s", string(output))
		}

		// ── 热替换 ──────────────────────────────────────────────────────
		log.Printf("[Agent] 预检通过，正在执行程序文件热替换...")
		sendProgress("预检通过，正在替换内核程序...")

		_ = os.Rename(exePath, backupPath)
		if replaceErr := os.Rename(tmpFile, exePath); replaceErr != nil {
			log.Printf("[Agent] 核心文件替换失败，尝试回滚: %v", replaceErr)
			sendProgress("文件替换失败，操作中止")
			_ = os.Rename(backupPath, exePath)
			return
		}

		_ = os.Chmod(exePath, 0o755)
		log.Printf("[Agent] 文件替换完成，触发生态热启 (%s)...", exePath)
		sendProgress("更新成功！准备重启...")

		go func() {
			time.Sleep(2 * time.Second)
			log.Printf("[Agent] 准备退出进程移交运行空间给 Systemd...")
			os.Exit(0)
		}()
	}()
}
