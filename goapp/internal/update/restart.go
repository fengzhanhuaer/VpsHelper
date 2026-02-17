package update

import (
    "os"
    "os/exec"
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
        cmd := exec.Command(exe, args...)
        cmd.Env = env
        if wd != "" {
            cmd.Dir = wd
        }
        _ = cmd.Start()
        os.Exit(0)
    }()
}
