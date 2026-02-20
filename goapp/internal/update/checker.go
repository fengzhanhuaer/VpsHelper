package update

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"vpshelper-go/internal/store"
	"vpshelper-go/internal/version"
)

// PreDownloadState holds info about a pre-downloaded release binary.
type PreDownloadState struct {
	Available   bool   // a newer release has been pre-downloaded
	TagName     string // e.g. "v0.2.46"
	AssetName   string
	BinaryPath  string // local path of the downloaded binary
	DownloadedAt time.Time
	Downloading bool   // currently downloading
	Error       string // last check/download error (transient)
}

var (
	checkerMu    sync.RWMutex
	checkerState PreDownloadState
)

// GetPreDownloadState returns the current pre-download state (thread-safe).
func GetPreDownloadState() PreDownloadState {
	checkerMu.RLock()
	defer checkerMu.RUnlock()
	return checkerState
}

func setPreDownloadState(fn func(*PreDownloadState)) {
	checkerMu.Lock()
	defer checkerMu.Unlock()
	fn(&checkerState)
}

// StartBackgroundChecker launches a goroutine that periodically checks
// for new GitHub releases and pre-downloads them. The check interval
// is 30 minutes. The first check happens 30 seconds after startup.
func StartBackgroundChecker(ctx context.Context, dbConn *sql.DB, baseDir string) {
	go func() {
		// Wait a bit after startup before first check.
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}

		runCheck(ctx, dbConn, baseDir)

		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runCheck(ctx, dbConn, baseDir)
			}
		}
	}()
}

func runCheck(ctx context.Context, dbConn *sql.DB, baseDir string) {
	ghOwner := "fengzhanhuaer"
	ghRepo := "VpsHelper"
	ghToken := ""
	ghAsset := ""

	if settings, err := store.GetSettings(dbConn, []string{"github_release_token", "github_release_asset"}); err == nil {
		ghToken = settings["github_release_token"]
		ghAsset = settings["github_release_asset"]
	}

	checkCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	info, rel, err := FetchLatestGitHubRelease(checkCtx, ghOwner, ghRepo, ghToken)
	if err != nil && strings.TrimSpace(ghToken) != "" {
		// Fallback to anonymous.
		if info2, rel2, err2 := FetchLatestGitHubRelease(checkCtx, ghOwner, ghRepo, ""); err2 == nil {
			info, rel, err = info2, rel2, nil
			ghToken = ""
		}
	}
	if err != nil {
		setPreDownloadState(func(s *PreDownloadState) {
			s.Error = "检查更新失败: " + err.Error()
		})
		log.Printf("[auto-update] check failed: %v", err)
		return
	}

	// Compare with current version.
	latest := strings.TrimPrefix(info.TagName, "v")
	current := strings.TrimPrefix(version.Version, "v")
	if latest == current {
		setPreDownloadState(func(s *PreDownloadState) {
			s.Error = ""
		})
		return
	}

	// Already downloaded this version?
	st := GetPreDownloadState()
	if st.Available && st.TagName == info.TagName {
		return
	}

	asset, err := SelectReleaseAsset(rel, ghAsset)
	if err != nil {
		setPreDownloadState(func(s *PreDownloadState) {
			s.Error = "选择 asset 失败: " + err.Error()
		})
		return
	}

	// Start downloading.
	setPreDownloadState(func(s *PreDownloadState) {
		s.Downloading = true
		s.Error = ""
	})

	log.Printf("[auto-update] new release found: %s (current: %s), downloading %s...", info.TagName, version.Version, asset.Name)

	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	destDir := filepath.Join(baseDir, "bin")
	_ = os.MkdirAll(destDir, 0o755)
	dest := filepath.Join(destDir, "vpshelper-predownload"+ext)

	dlCtx, dlCancel := context.WithTimeout(ctx, 15*time.Minute)
	defer dlCancel()

	bin, err := DownloadReleaseAsset(dlCtx, asset, ghToken, dest)
	if err != nil {
		setPreDownloadState(func(s *PreDownloadState) {
			s.Downloading = false
			s.Error = "预下载失败: " + err.Error()
		})
		log.Printf("[auto-update] pre-download failed: %v", err)
		return
	}

	setPreDownloadState(func(s *PreDownloadState) {
		s.Available = true
		s.TagName = info.TagName
		s.AssetName = asset.Name
		s.BinaryPath = bin
		s.DownloadedAt = time.Now()
		s.Downloading = false
		s.Error = ""
	})
	log.Printf("[auto-update] pre-downloaded %s to %s", info.TagName, bin)
}

// ApplyPreDownload replaces the current executable with the pre-downloaded
// binary and triggers a restart. Returns an error message if something fails.
func ApplyPreDownload() (string, bool) {
	st := GetPreDownloadState()
	if !st.Available || st.BinaryPath == "" {
		return "没有预下载的更新可用。", false
	}

	// Verify the pre-downloaded binary exists.
	if _, err := os.Stat(st.BinaryPath); err != nil {
		setPreDownloadState(func(s *PreDownloadState) {
			s.Available = false
			s.Error = "预下载文件已丢失"
		})
		return "预下载的二进制文件已丢失，请重新检查更新。", false
	}

	targetPath := st.BinaryPath
	if IsSystemdManaged() {
		if currentExe, e := os.Executable(); e == nil && currentExe != "" {
			if filepath.Clean(st.BinaryPath) != filepath.Clean(currentExe) {
				_ = os.Remove(currentExe)
				if err := os.Rename(st.BinaryPath, currentExe); err != nil {
					return "替换可执行文件失败：" + err.Error(), false
				}
				_ = os.Chmod(currentExe, 0o755)
				targetPath = currentExe
			}
		}
	}

	msg := fmt.Sprintf("已应用预下载版本 %s，服务将在 1 秒后自动重启。", st.TagName)

	// Clear state.
	setPreDownloadState(func(s *PreDownloadState) {
		s.Available = false
		s.BinaryPath = ""
	})

	RestartToDelayed(targetPath, os.Args[1:], 1*time.Second)
	return msg, true
}
