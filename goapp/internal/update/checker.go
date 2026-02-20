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

	"vpshelper-go/internal/version"
)

// PreDownloadState holds info about a pre-downloaded release binary.
type PreDownloadState struct {
	Available    bool   // a newer release has been pre-downloaded
	TagName      string // e.g. "v0.2.46"
	AssetName    string
	BinaryPath   string // local path of the downloaded binary
	DownloadedAt time.Time
	Downloading  bool   // currently downloading in background
	Error        string // last check/download error (transient)
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

// TriggerPreDownload starts a background download of the latest release
// if a newer version is available. Called when user manually checks.
// Returns immediately; download happens in a goroutine.
func TriggerPreDownload(dbConn *sql.DB, baseDir string, info GitHubReleaseInfo, rel *ghRelease, ghToken, ghAsset string) {
	latest := strings.TrimPrefix(info.TagName, "v")
	current := strings.TrimPrefix(version.Version, "v")
	if latest == current {
		return
	}

	// Already downloaded this version?
	st := GetPreDownloadState()
	if st.Available && st.TagName == info.TagName {
		return
	}
	if st.Downloading {
		return
	}

	asset, err := SelectReleaseAsset(rel, ghAsset)
	if err != nil {
		setPreDownloadState(func(s *PreDownloadState) {
			s.Error = "选择 asset 失败: " + err.Error()
		})
		return
	}

	setPreDownloadState(func(s *PreDownloadState) {
		s.Downloading = true
		s.Error = ""
	})

	go func() {
		log.Printf("[pre-download] downloading %s (%s)...", info.TagName, asset.Name)

		ext := ""
		if runtime.GOOS == "windows" {
			ext = ".exe"
		}
		destDir := filepath.Join(baseDir, "bin")
		_ = os.MkdirAll(destDir, 0o755)
		dest := filepath.Join(destDir, "vpshelper-predownload"+ext)

		dlCtx, dlCancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer dlCancel()

		bin, err := DownloadReleaseAsset(dlCtx, asset, ghToken, dest)
		if err != nil {
			setPreDownloadState(func(s *PreDownloadState) {
				s.Downloading = false
				s.Error = "预下载失败: " + err.Error()
			})
			log.Printf("[pre-download] failed: %v", err)
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
		log.Printf("[pre-download] ready: %s -> %s", info.TagName, bin)
	}()
}

// ApplyPreDownload replaces the current executable with the pre-downloaded
// binary and triggers a restart. Returns an error message if something fails.
func ApplyPreDownload() (string, bool) {
	st := GetPreDownloadState()
	if !st.Available || st.BinaryPath == "" {
		return "没有预下载的更新可用。", false
	}

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

	setPreDownloadState(func(s *PreDownloadState) {
		s.Available = false
		s.BinaryPath = ""
	})

	RestartToDelayed(targetPath, os.Args[1:], 1*time.Second)
	return msg, true
}
