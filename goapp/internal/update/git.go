package update

import (
    "bytes"
    "context"
    "fmt"
    "os/exec"
    "strings"
    "time"
)

type GitRunner struct {
    WorkDir string
}

type Result struct {
    OK  bool
    Out string
}

func (r GitRunner) Run(ctx context.Context, args ...string) Result {
    if len(args) == 0 {
        return Result{OK: false, Out: "missing git args"}
    }

    cmd := exec.CommandContext(ctx, "git", args...)
    if r.WorkDir != "" {
        cmd.Dir = r.WorkDir
    }

    var stdout bytes.Buffer
    var stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr

    if err := cmd.Run(); err != nil {
        out := strings.TrimSpace(stderr.String())
        if out == "" {
            out = strings.TrimSpace(stdout.String())
        }
        if out == "" {
            out = err.Error()
        }
        return Result{OK: false, Out: out}
    }

    out := strings.TrimSpace(stdout.String())
    return Result{OK: true, Out: out}
}

func WithTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
    if d <= 0 {
        return context.WithCancel(parent)
    }
    return context.WithTimeout(parent, d)
}

func Errf(format string, args ...any) error {
    return fmt.Errorf(format, args...)
}
