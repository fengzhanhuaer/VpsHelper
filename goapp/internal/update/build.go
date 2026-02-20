package update

import (
    "bytes"
    "context"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "runtime"
    "strings"
)

type BuildResult struct {
    OK  bool
    Out string
    Bin string
}

// BuildServer builds ./cmd/server into a separate "next" binary under ./bin.
// It avoids overwriting the currently running executable (important on Windows).
func BuildServer(ctx context.Context, goappDir string) BuildResult {
    binDir := filepath.Join(goappDir, "bin")
    _ = os.MkdirAll(binDir, 0o755)

    name := "vpshelper-next"
    if runtime.GOOS == "windows" {
        name += ".exe"
    }
    outPath := filepath.Join(binDir, name)

    cmd := exec.CommandContext(ctx, "go", "build", "-o", outPath, "./cmd/server")
    cmd.Dir = goappDir

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
        return BuildResult{OK: false, Out: fmt.Sprintf("go build failed: %s", out)}
    }

    out := strings.TrimSpace(stdout.String())
    if out == "" {
        out = "go build ok"
    }
    return BuildResult{OK: true, Out: out, Bin: outPath}
}
