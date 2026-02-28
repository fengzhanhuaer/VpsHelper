package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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

func fallbackDownloadWithProgress(ctx context.Context, host, secret, osParam, archParam string, destPath string, onProgress update.ProgressCallback) (string, error) {
	baseURL := strings.TrimSuffix(host, "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}
	infoURL := fmt.Sprintf("%s/api/probe/latest_binary?os=%s&arch=%s&info=true", baseURL, osParam, archParam)

	req, err := http.NewRequestWithContext(ctx, "GET", infoURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+secret)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("control center returned status %d", resp.StatusCode)
	}

	var data struct {
		Name    string `json:"name"`
		URL     string `json:"url"`
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}

	if version.Version != "dev" && data.TagName == version.Version {
		log.Printf("[Agent] (Fallback) 当前已是最新的主控指定版本 %s，无需下载。", data.TagName)
		return "", fmt.Errorf("ALREADY_LATEST")
	}

	asset := update.SelectedAsset{
		Name:       data.Name,
		BrowserURL: baseURL + data.URL,
		APIURL:     baseURL + data.URL,
	}

	return update.DownloadReleaseAssetWithProgress(ctx, asset, secret, destPath, onProgress)
}

func handleAgentUpgradeTrigger(secret, host string, session *yamux.Session) {
	log.Printf("[Agent] 收到服务端在线更新指令，准备执行自更新流程...")

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

		log.Printf("[Agent] 正在向 GitHub 拉取释放版本元数据...")
		sendProgress("正在拉取最新版本元数据...")
		var tmpFile string

		info, release, err := update.FetchLatestGitHubRelease(ctx, "fengzhanhuaer", "VpsHelper", "")
		if err == nil && info.OK {
			if version.Version != "dev" && info.TagName == version.Version {
				log.Printf("[Agent] 当前版本 %s 已是最新版，跳过升级", version.Version)
				sendProgress("当前已是最新版，无需升级")
				return
			}
			asset, err := update.SelectReleaseAsset(release, "vpsprobe")
			if err == nil {
				log.Printf("[Agent] 开始从 GitHub 下载新探针包: %s (版本: %s)...", asset.Name, info.TagName)
				sendProgress("开始从 GitHub 下载新探针包...")
				tmpFile, err = update.DownloadReleaseAssetWithProgress(ctx, asset, "", downloadPath, progressCb)
			}
		}

		if err != nil || tmpFile == "" {
			if err != nil && err.Error() == "ALREADY_LATEST" {
				sendProgress("当前已是最新版，无需升级")
				return
			}
			log.Printf("[Agent] 从 GitHub 获取版本失败 (%v)，回退请求主控代理转发探针文件...", err)
			sendProgress("直连获取失败，回退至主控代理下载...")
			tmpFile, err = fallbackDownloadWithProgress(ctx, host, secret, runtime.GOOS, runtime.GOARCH, downloadPath, progressCb)
			if err != nil {
				if err.Error() == "ALREADY_LATEST" {
					sendProgress("当前已是最新版，无需升级")
					_ = os.Remove(downloadPath + ".download")
					return
				}
				log.Printf("[Agent] 代理转发下载依然失败: %v", err)
				sendProgress("更新失败: 下载探针文件失败")
				_ = os.Remove(downloadPath + ".download")
				return
			}
		}
		defer os.Remove(tmpFile) // clean up

		log.Printf("[Agent] 新版下载完成，执行预检测试生存能力...")
		sendProgress("下载完成，执行预检测试...")

		cmd := exec.CommandContext(ctx, tmpFile)
		cmd.Env = append(os.Environ(), "VPSHELPER_UPDATE_TEST=1")
		output, err := cmd.CombinedOutput()

		if err != nil {
			log.Printf("[Agent] 新版预检失败，拒绝升级: %v, 输出: %s", err, string(output))
			sendProgress("预检失败，拒绝升级")
			return
		}

		// 简单的错误预防，确认测试模式真实触发了
		if !strings.Contains(string(output), "VPSHELPER_UPDATE_TEST is active") {
			log.Printf("[Agent] 警告: 未在预检中检测出测试输出标记。输出: %s", string(output))
		}

		log.Printf("[Agent] 预检存活通过，正在执行程序文件热替换...")
		sendProgress("预检通过，正在替换内核程序...")

		_ = os.Rename(exePath, backupPath)
		if err := os.Rename(tmpFile, exePath); err != nil {
			log.Printf("[Agent] 核心文件替换失败，尝试回滚并中止操作: %v", err)
			sendProgress("文件替换失败，操作中止")
			_ = os.Rename(backupPath, exePath)
			return
		}

		_ = os.Chmod(exePath, 0o755)

		log.Printf("[Agent] 文件替换完成，触发生态热启 (%s)...", exePath)
		sendProgress("更新成功！准备重启...")

		// 让当前进程直接退出，交给 Systemd 将新文件重新拉起。
		// 给一个很小的延迟，确保日志能写完。
		go func() {
			time.Sleep(2 * time.Second)
			log.Printf("[Agent] 准备退出进程移交运行空间给 Systemd...")
			os.Exit(0) // Systemd (Restart=always) 会立即接管并重新启动这个 exePath
		}()
	}()
}
