package update

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// HandleProcessMode handles update-specific process modes.
// Return handled=true means caller should exit and not start UI runtime.
func HandleProcessMode() (handled bool, err error) {
	mode, _ := findArgValue(os.Args[1:], "--update-mode")
	if mode == "worker" {
		return true, runUpdateWorker(os.Args[1:])
	}

	cleanupEnabled := hasArg(os.Args[1:], "--update-cleanup")
	if cleanupEnabled {
		runUpdateCleanup(os.Args[1:])
		runUpdateCleanupAsync(os.Args[1:])
		stripUpdateArgs()
	}

	return false, nil
}

func runUpdateWorker(args []string) error {
	oldExe, ok := findArgValue(args, "--update-old-exe")
	if !ok || oldExe == "" {
		return fmt.Errorf("missing --update-old-exe")
	}
	downloadPath, ok := findArgValue(args, "--update-download")
	if !ok || downloadPath == "" {
		return fmt.Errorf("missing --update-download")
	}
	backupPath, ok := findArgValue(args, "--update-backup")
	if !ok || backupPath == "" {
		return fmt.Errorf("missing --update-backup")
	}

	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get self executable failed: %w", err)
	}

	if err := waitAndMove(oldExe, backupPath, 180); err != nil {
		return fmt.Errorf("move old executable failed: %w", err)
	}

	if err := waitAndMove(downloadPath, oldExe, 180); err != nil {
		_ = waitAndMove(backupPath, oldExe, 10)
		return fmt.Errorf("move downloaded executable failed: %w", err)
	}

	cmd := exec.Command(oldExe,
		"--update-cleanup",
		"--update-backup", backupPath,
		"--update-temp", selfPath,
		"--update-download", downloadPath,
	)
	cmd.Dir = filepath.Dir(oldExe)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start updated executable failed: %w", err)
	}

	return nil
}

func runUpdateCleanup(args []string) {
	if backupPath, ok := findArgValue(args, "--update-backup"); ok && backupPath != "" {
		_ = removeWithRetry(backupPath, 120, 500*time.Millisecond)
	}
	if tempPath, ok := findArgValue(args, "--update-temp"); ok && tempPath != "" {
		_ = removeWithRetry(tempPath, 120, 500*time.Millisecond)
	}
	if downloadPath, ok := findArgValue(args, "--update-download"); ok && downloadPath != "" {
		_ = removeWithRetry(downloadPath, 120, 500*time.Millisecond)
	}
}

func runUpdateCleanupAsync(args []string) {
	go func() {
		time.Sleep(3 * time.Second)
		if backupPath, ok := findArgValue(args, "--update-backup"); ok && backupPath != "" {
			_ = removeWithRetry(backupPath, 60, 1*time.Second)
		}
		if tempPath, ok := findArgValue(args, "--update-temp"); ok && tempPath != "" {
			_ = removeWithRetry(tempPath, 60, 1*time.Second)
		}
		if downloadPath, ok := findArgValue(args, "--update-download"); ok && downloadPath != "" {
			_ = removeWithRetry(downloadPath, 60, 1*time.Second)
		}
	}()
}

func waitAndMove(src, dst string, retries int) error {
	_ = os.Remove(dst)
	var lastErr error
	for i := 0; i < retries; i++ {
		err := os.Rename(src, dst)
		if err == nil {
			return nil
		}
		if os.IsNotExist(err) {
			return nil
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("rename timeout")
	}
	return lastErr
}

func removeWithRetry(path string, retries int, delay time.Duration) error {
	var lastErr error
	for i := 0; i < retries; i++ {
		err := os.Remove(path)
		if err == nil || os.IsNotExist(err) {
			return nil
		}
		lastErr = err
		time.Sleep(delay)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("remove timeout")
	}
	return lastErr
}

func hasArg(args []string, key string) bool {
	for _, a := range args {
		if a == key {
			return true
		}
	}
	return false
}

func findArgValue(args []string, key string) (string, bool) {
	for i := 0; i < len(args); i++ {
		if args[i] == key {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		}
		if strings.HasPrefix(args[i], key+"=") {
			return strings.TrimPrefix(args[i], key+"="), true
		}
	}
	return "", false
}

func stripUpdateArgs() {
	args := os.Args
	if len(args) <= 1 {
		return
	}
	filtered := []string{args[0]}
	keysWithValues := map[string]struct{}{
		"--update-mode":     {},
		"--update-old-exe":  {},
		"--update-download": {},
		"--update-backup":   {},
		"--update-temp":     {},
	}
	flagsOnly := map[string]struct{}{
		"--update-cleanup": {},
	}

	skipNext := false
	for i := 1; i < len(args); i++ {
		if skipNext {
			skipNext = false
			continue
		}
		a := args[i]
		if _, ok := flagsOnly[a]; ok {
			continue
		}
		if _, ok := keysWithValues[a]; ok {
			skipNext = true
			continue
		}
		isKV := false
		for k := range keysWithValues {
			if strings.HasPrefix(a, k+"=") {
				isKV = true
				break
			}
		}
		if isKV {
			continue
		}
		filtered = append(filtered, a)
	}
	os.Args = filtered
}
