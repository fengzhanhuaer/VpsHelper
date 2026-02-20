package update

import (
	"os"
	"os/exec"
	"runtime"
	"time"
)

// RestartDelayed starts a new process with the same executable and args, then exits.
// This works on Windows too (unlike execve), assuming the new binary path is different
// or the old one exits before overwrite attempts.
func RestartDelayed(delay time.Duration) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	RestartToDelayed(exe, os.Args[1:], delay)
}

// RestartToDelayed restarts into a specific executable path.
func RestartToDelayed(exe string, args []string, delay time.Duration) {
	env := os.Environ()
	wd, _ := os.Getwd()

	go func() {
		time.Sleep(delay)
		// When managed by systemd, let systemd restart the service instead of
		// spawning a child process that would be killed with the cgroup.
		if IsSystemdManaged() {
			os.Exit(1)
		}
		cmd := exec.Command(exe, args...)
		cmd.Env = env
		if wd != "" {
			cmd.Dir = wd
		}
		_ = cmd.Start()
		os.Exit(0)
	}()
}

// IsSystemdManaged reports whether current process is running under systemd.
func IsSystemdManaged() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	// INVOCATION_ID and JOURNAL_STREAM are both injected by systemd.
	return os.Getenv("INVOCATION_ID") != "" || os.Getenv("JOURNAL_STREAM") != ""
}
