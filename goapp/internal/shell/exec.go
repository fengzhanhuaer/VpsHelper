package shell

import (
    "bytes"
    "context"
    "errors"
    "os"
    "os/exec"
    "path/filepath"
    "runtime"
    "strings"
    "time"
)

var ErrDangerous = errors.New("dangerous command disabled")

func IsDangerous(cmd string) bool {
    lower := strings.ToLower(cmd)
    banned := []string{"reboot", "shutdown", "poweroff", "halt", "init 0", "init 6"}
    for _, b := range banned {
        if strings.Contains(lower, b) {
            return true
        }
    }
    return false
}

func ResolveCWD(current string) string {
    if current == "" {
        if home, err := os.UserHomeDir(); err == nil {
            return home
        }
        return "."
    }
    if st, err := os.Stat(current); err == nil && st.IsDir() {
        return current
    }
    if home, err := os.UserHomeDir(); err == nil {
        return home
    }
    return "."
}

func ApplyCD(current, command string) (newCWD string, ok bool, msg string) {
    cmd := strings.TrimSpace(command)
    if cmd == "cd" || strings.HasPrefix(cmd, "cd ") {
        target := "~"
        if strings.HasPrefix(cmd, "cd ") {
            target = strings.TrimSpace(strings.TrimPrefix(cmd, "cd "))
            if target == "" {
                target = "~"
            }
        }

        if target == "~" {
            if home, err := os.UserHomeDir(); err == nil {
                target = home
            }
        }

        // Expand relative path.
        if !filepath.IsAbs(target) {
            target = filepath.Clean(filepath.Join(current, target))
        }

        st, err := os.Stat(target)
        if err != nil || !st.IsDir() {
            return current, false, "目录不存在：" + target
        }
        return target, true, target
    }

    return current, false, ""
}

func Run(ctx context.Context, cwd, command string) (ok bool, output string, err error) {
    if IsDangerous(command) {
        return false, "该命令已禁用，请在系统控制台执行。", ErrDangerous
    }

    // 30s timeout like Python.
    ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()

    var cmd *exec.Cmd
    if runtime.GOOS == "windows" {
        cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", command)
    } else {
        cmd = exec.CommandContext(ctx, "bash", "-lc", command)
    }
    cmd.Dir = cwd

    var stdout bytes.Buffer
    var stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr

    runErr := cmd.Run()
    combined := strings.TrimSpace(stdout.String() + stderr.String())
    if combined == "" {
        combined = "(无输出)"
    }

    if runErr != nil {
        if errors.Is(ctx.Err(), context.DeadlineExceeded) {
            return false, "命令执行超时（30秒）。", ctx.Err()
        }
        return false, combined, runErr
    }

    return true, combined, nil
}
