package update

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type GitHubReleaseInfo struct {
	OK          bool
	TagName     string
	Name        string
	PublishedAt string
	AssetName   string
	Note        string
}

type ghRelease struct {
	TagName     string     `json:"tag_name"`
	Name        string     `json:"name"`
	PublishedAt string     `json:"published_at"`
	Draft       bool       `json:"draft"`
	Prerelease  bool       `json:"prerelease"`
	Assets      []ghAsset  `json:"assets"`
	Message     string     `json:"message"`
	Errors      []ghErrObj `json:"errors"`
}

type ghErrObj struct {
	Message string `json:"message"`
}

type ghAsset struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	Size            int64  `json:"size"`
	ContentType     string `json:"content_type"`
	BrowserDownload string `json:"browser_download_url"`
	APIURL          string `json:"url"`
}

func FetchLatestGitHubRelease(ctx context.Context, owner, repo, token string) (GitHubReleaseInfo, *ghRelease, error) {
	info := GitHubReleaseInfo{OK: false}
	owner = strings.TrimSpace(owner)
	repo = strings.TrimSpace(repo)
	if owner == "" || repo == "" {
		info.Note = "请先填写 GitHub owner/repo。"
		return info, nil, errors.New("missing owner/repo")
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return info, nil, err
	}
	setGitHubHeaders(req, token, "application/vnd.github+json")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		info.Note = "请求 GitHub API 失败。"
		return info, nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		info.Note = fmt.Sprintf("GitHub API 返回 %d：%s", resp.StatusCode, strings.TrimSpace(string(body)))
		return info, nil, fmt.Errorf("github api status: %d", resp.StatusCode)
	}

	var rel ghRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		info.Note = "解析 GitHub API 返回数据失败。"
		return info, nil, err
	}

	info.OK = true
	info.TagName = rel.TagName
	info.Name = rel.Name
	info.PublishedAt = formatPublishedAt(rel.PublishedAt)
	return info, &rel, nil
}

type SelectedAsset struct {
	Name       string
	APIURL     string
	BrowserURL string
}

type DownloadProgress struct {
	Received int64
	Total    int64
}

type ProgressCallback func(DownloadProgress)

type downloadHTTPStatusError struct {
	Status int
	Body   string
}

func (e *downloadHTTPStatusError) Error() string {
	return fmt.Sprintf("download status %d: %s", e.Status, strings.TrimSpace(e.Body))
}

func SelectReleaseAsset(rel *ghRelease, preferredName string) (SelectedAsset, error) {
	if rel == nil {
		return SelectedAsset{}, errors.New("nil release")
	}
	if len(rel.Assets) == 0 {
		return SelectedAsset{}, errors.New("release has no assets")
	}

	preferredName = strings.TrimSpace(preferredName)
	if preferredName != "" {
		for _, a := range rel.Assets {
			if strings.EqualFold(a.Name, preferredName) {
				return SelectedAsset{Name: a.Name, APIURL: a.APIURL, BrowserURL: a.BrowserDownload}, nil
			}
		}
		return SelectedAsset{}, fmt.Errorf("未找到指定 asset：%s", preferredName)
	}

	// Auto select by GOOS/GOARCH.
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	score := func(name string) int {
		n := strings.ToLower(name)
		s := 0
		if strings.Contains(n, strings.ToLower(goos)) {
			s += 4
		}
		if strings.Contains(n, strings.ToLower(goarch)) {
			s += 4
		}
		if goos == "windows" {
			if strings.HasSuffix(n, ".exe") {
				s += 3
			}
		} else {
			if !strings.Contains(n, ".") || strings.HasSuffix(n, ".bin") {
				s += 1
			}
		}
		if strings.HasSuffix(n, ".zip") {
			s -= 1
		}
		return s
	}

	best := rel.Assets[0]
	bestScore := score(best.Name)
	for _, a := range rel.Assets[1:] {
		s := score(a.Name)
		if s > bestScore {
			best = a
			bestScore = s
		}
	}

	if bestScore <= 0 && len(rel.Assets) > 1 {
		return SelectedAsset{}, errors.New("无法自动选择合适的 asset，请在页面里填写 asset 名称")
	}

	return SelectedAsset{Name: best.Name, APIURL: best.APIURL, BrowserURL: best.BrowserDownload}, nil
}

func DownloadReleaseAsset(ctx context.Context, asset SelectedAsset, token string, destPath string) (string, error) {
	return DownloadReleaseAssetWithProgress(ctx, asset, token, destPath, nil)
}

func DownloadReleaseAssetWithProgress(ctx context.Context, asset SelectedAsset, token string, destPath string, onProgress ProgressCallback) (string, error) {
	if asset.Name == "" {
		return "", errors.New("empty asset")
	}
	if destPath == "" {
		return "", errors.New("empty destPath")
	}

	_ = os.MkdirAll(filepath.Dir(destPath), 0o755)
	tmp := destPath + ".download"
	if err := downloadAssetToTempWithRetry(ctx, asset, token, tmp, onProgress); err != nil {
		return "", err
	}

	finalPath := destPath
	if strings.HasSuffix(strings.ToLower(asset.Name), ".zip") {
		unzipped, err := unzipSingleBinary(tmp, filepath.Dir(destPath))
		_ = os.Remove(tmp)
		if err != nil {
			return "", err
		}
		finalPath = unzipped
	} else {
		_ = os.Remove(destPath)
		if err := os.Rename(tmp, destPath); err != nil {
			_ = os.Remove(tmp)
			return "", err
		}
	}

	// Ensure executable bit on unix.
	if runtime.GOOS != "windows" {
		_ = os.Chmod(finalPath, 0o755)
	}

	return finalPath, nil
}

func downloadAssetToTempWithRetry(ctx context.Context, asset SelectedAsset, token string, tmp string, onProgress ProgressCallback) error {
	const maxAttempts = 5
	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if err := downloadAssetToTempOnce(ctx, asset, token, tmp, onProgress); err == nil {
			return nil
		} else {
			lastErr = err
			if !isRetryableDownloadErr(err) || attempt == maxAttempts {
				return err
			}

			backoff := time.Duration(attempt) * 2 * time.Second
			if backoff > 10*time.Second {
				backoff = 10 * time.Second
			}
			if !sleepWithContext(ctx, backoff) {
				return ctx.Err()
			}
		}
	}

	if lastErr != nil {
		return lastErr
	}
	return errors.New("download failed")
}

func downloadAssetToTempOnce(ctx context.Context, asset SelectedAsset, token string, tmp string, onProgress ProgressCallback) error {
	url := asset.BrowserURL
	accept := ""
	if strings.TrimSpace(token) != "" {
		// Use API asset download for private repos.
		url = asset.APIURL
		accept = "application/octet-stream"
	}

	client := &http.Client{
		Timeout: 0,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			setGitHubHeaders(req, token, req.Header.Get("Accept"))
			return nil
		},
	}

	existing := int64(0)
	if st, err := os.Stat(tmp); err == nil {
		existing = st.Size()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	tryResume := existing > 0
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if tryResume && existing > 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", existing))
		}
		setGitHubHeaders(req, token, req.Header.Get("Accept"))

		resp, err := client.Do(req)
		if err != nil {
			return err
		}

		// Local partial file is stale or larger than upstream file. Restart once.
		if tryResume && resp.StatusCode == http.StatusRequestedRangeNotSatisfiable {
			_ = resp.Body.Close()
			_ = os.Remove(tmp)
			existing = 0
			tryResume = false
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
			_ = resp.Body.Close()
			return &downloadHTTPStatusError{Status: resp.StatusCode, Body: string(b)}
		}

		appendMode := tryResume && resp.StatusCode == http.StatusPartialContent
		start := int64(0)
		if appendMode {
			start = existing
		}

		flags := os.O_CREATE | os.O_WRONLY
		if appendMode {
			flags |= os.O_APPEND
		} else {
			flags |= os.O_TRUNC
		}

		f, err := os.OpenFile(tmp, flags, 0o755)
		if err != nil {
			_ = resp.Body.Close()
			return err
		}

		total := resp.ContentLength
		if appendMode && total >= 0 {
			total += start
		}

		var cpErr error
		if onProgress == nil {
			_, cpErr = io.Copy(f, resp.Body)
		} else {
			cpErr = copyWithProgress(resp.Body, f, start, total, onProgress)
		}

		bodyCloseErr := resp.Body.Close()
		fileCloseErr := f.Close()

		if cpErr != nil {
			return cpErr
		}
		if bodyCloseErr != nil {
			return bodyCloseErr
		}
		if fileCloseErr != nil {
			return fileCloseErr
		}
		return nil
	}
}

func copyWithProgress(src io.Reader, dst io.Writer, initial int64, total int64, onProgress ProgressCallback) error {
	copied := initial
	buf := make([]byte, 64*1024)
	lastReport := time.Time{}

	report := func(force bool) {
		if !force && !lastReport.IsZero() && time.Since(lastReport) < 200*time.Millisecond {
			return
		}
		lastReport = time.Now()
		onProgress(DownloadProgress{Received: copied, Total: total})
	}

	report(true)
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
			copied += int64(n)
			report(false)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				report(true)
				return nil
			}
			return readErr
		}
	}
}

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func isRetryableDownloadErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var hs *downloadHTTPStatusError
	if errors.As(err, &hs) {
		return hs.Status == http.StatusTooManyRequests || hs.Status >= 500
	}

	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}

	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "unexpected eof") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "timeout") {
		return true
	}
	return false
}

func unzipSingleBinary(zipPath, outDir string) (string, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", err
	}
	defer r.Close()

	var candidates []*zip.File
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		name := filepath.Base(f.Name)
		if name == "" || strings.HasPrefix(name, ".") {
			continue
		}
		candidates = append(candidates, f)
	}
	if len(candidates) == 0 {
		return "", errors.New("zip 内没有可解压文件")
	}

	pick := candidates[0]
	if len(candidates) > 1 {
		// Prefer OS-specific executable-ish name.
		for _, f := range candidates {
			n := strings.ToLower(filepath.Base(f.Name))
			if runtime.GOOS == "windows" {
				if strings.HasSuffix(n, ".exe") {
					pick = f
					break
				}
			} else {
				if !strings.Contains(n, ".") || strings.HasSuffix(n, ".bin") {
					pick = f
					break
				}
			}
		}
	}

	src, err := pick.Open()
	if err != nil {
		return "", err
	}
	defer src.Close()

	outName := filepath.Base(pick.Name)
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(outName), ".exe") {
		outName += ".exe"
	}
	outPath := filepath.Join(outDir, outName)

	_ = os.MkdirAll(outDir, 0o755)
	_ = os.Remove(outPath)
	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return "", err
	}
	_, cpErr := io.Copy(out, src)
	closeErr := out.Close()
	if cpErr != nil {
		_ = os.Remove(outPath)
		return "", cpErr
	}
	if closeErr != nil {
		_ = os.Remove(outPath)
		return "", closeErr
	}
	return outPath, nil
}

func setGitHubHeaders(req *http.Request, token string, accept string) {
	req.Header.Set("User-Agent", "vpshelper-go")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if t := strings.TrimSpace(token); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
}

func formatPublishedAt(raw string) string {
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return raw
	}
	tz := os.Getenv("VPSHELPER_TZ")
	if tz == "" {
		tz = os.Getenv("TZ")
	}
	if tz == "" {
		tz = "Asia/Shanghai"
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return t.Format("2006-01-02 15:04:05")
	}
	return t.In(loc).Format("2006-01-02 15:04:05")
}
