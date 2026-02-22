package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	parallelWorkers   = 8              // number of concurrent download goroutines
	minChunkSize      = 512 * 1024     // 512 KB — don't split below this
	parallelThreshold = 2 * 1024 * 1024 // 2 MB — only parallelize files larger than this
)

// downloadParallel attempts a multi-connection parallel download of the given URL.
// It returns false as second value if parallel download is not possible (e.g. server
// doesn't support Range), so the caller can fall back to single-stream.
func downloadParallel(ctx context.Context, url string, token string, destPath string, totalSize int64, onProgress ProgressCallback) (bool, error) {
	if totalSize <= parallelThreshold {
		return false, nil // too small, not worth parallelizing
	}

	// Verify Range support with a small test request.
	if !supportsRange(ctx, url, token) {
		return false, nil
	}

	workers := parallelWorkers
	chunkSize := totalSize / int64(workers)
	if chunkSize < minChunkSize {
		workers = int(totalSize / minChunkSize)
		if workers < 2 {
			return false, nil
		}
		chunkSize = totalSize / int64(workers)
	}

	// Create output file.
	_ = os.MkdirAll(fileDir(destPath), 0o755)
	f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return true, err
	}
	// Pre-allocate file size.
	_ = f.Truncate(totalSize)
	f.Close()

	// Build chunk ranges.
	type chunk struct {
		index int
		start int64
		end   int64 // inclusive
	}
	var chunks []chunk
	for i := 0; i < workers; i++ {
		start := int64(i) * chunkSize
		end := start + chunkSize - 1
		if i == workers-1 {
			end = totalSize - 1 // last chunk gets remainder
		}
		chunks = append(chunks, chunk{index: i, start: start, end: end})
	}

	// Track progress across all workers.
	var downloaded int64
	var progressMu sync.Mutex
	lastReport := time.Time{}

	reportProgress := func() {
		if onProgress == nil {
			return
		}
		progressMu.Lock()
		defer progressMu.Unlock()
		now := time.Now()
		if !lastReport.IsZero() && now.Sub(lastReport) < 200*time.Millisecond {
			return
		}
		lastReport = now
		onProgress(DownloadProgress{Received: atomic.LoadInt64(&downloaded), Total: totalSize})
	}

	// Download chunks in parallel.
	var wg sync.WaitGroup
	errs := make([]error, workers)

	for _, ch := range chunks {
		wg.Add(1)
		go func(c chunk) {
			defer wg.Done()
			errs[c.index] = downloadChunk(ctx, url, token, destPath, c.start, c.end, &downloaded, reportProgress)
		}(ch)
	}
	wg.Wait()

	// Final progress report.
	if onProgress != nil {
		onProgress(DownloadProgress{Received: atomic.LoadInt64(&downloaded), Total: totalSize})
	}

	// Check for errors.
	for _, e := range errs {
		if e != nil {
			_ = os.Remove(destPath)
			return true, fmt.Errorf("parallel download chunk failed: %w", e)
		}
	}

	// Verify file size.
	st, err := os.Stat(destPath)
	if err != nil || st.Size() != totalSize {
		_ = os.Remove(destPath)
		return true, fmt.Errorf("size mismatch: expected %d, got %d", totalSize, st.Size())
	}

	return true, nil
}

func downloadChunk(ctx context.Context, url string, token string, destPath string, start, end int64, downloaded *int64, report func()) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	setGitHubHeaders(req, token, req.Header.Get("Accept"))

	client := &http.Client{Timeout: 0}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("chunk %d-%d: status %d: %s", start, end, resp.StatusCode, string(b))
	}

	// Open file for writing at the correct offset.
	f, err := os.OpenFile(destPath, os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return err
	}

	buf := make([]byte, 64*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := f.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
			atomic.AddInt64(downloaded, int64(n))
			report()
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

func supportsRange(ctx context.Context, url string, token string) bool {
	rctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(rctx, http.MethodHead, url, nil)
	if err != nil {
		return false
	}
	setGitHubHeaders(req, token, "")

	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			setGitHubHeaders(req, token, req.Header.Get("Accept"))
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.Header.Get("Accept-Ranges") == "bytes" && resp.ContentLength > 0
}

func fileDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return "."
}

// getContentLength does a HEAD request and returns Content-Length, or 0 on failure.
func getContentLength(ctx context.Context, url string, token string) int64 {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return 0
	}
	setGitHubHeaders(req, token, "")

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			setGitHubHeaders(req, token, req.Header.Get("Accept"))
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && resp.ContentLength > 0 {
		return resp.ContentLength
	}
	return 0
}
