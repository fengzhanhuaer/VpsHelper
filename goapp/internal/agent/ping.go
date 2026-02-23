package agent

import (
	"context"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	timeRegexpLinux   = regexp.MustCompile(`time=([\d.]+) ms`)
	timeRegexpWindows = regexp.MustCompile(`[|<] ([\d.]+)ms`)
	lossRegexpLinux   = regexp.MustCompile(`([\d.]+)% packet loss`)
	lossRegexpWindows = regexp.MustCompile(`\(([\d.]+)% (loss|丢失)\)`)
)

func doPing(ctx context.Context, target string) (latencyMs float64, lossPct float64, ok bool) {
	// Simple validation to prevent command injection
	if strings.ContainsAny(target, ";&|\\`$()") {
		return 0, 100, false
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	isWindows := runtime.GOOS == "windows"
	if isWindows {
		cmd = exec.CommandContext(ctxTimeout, "ping", "-n", "4", "-w", "2000", target)
	} else {
		cmd = exec.CommandContext(ctxTimeout, "ping", "-c", "4", "-W", "2", target)
	}

	out, err := cmd.CombinedOutput()
	outputStr := string(out)

	if err != nil && cmd.ProcessState != nil && cmd.ProcessState.ExitCode() != 1 {
		// Exit code 1 usually means some packets lost or host unreachable, which is fine to parse.
		// Other exit codes might mean bad arguments or network down.
	}

	// Parse loss
	lossPct = 100.0 // assume total loss until proven otherwise
	if isWindows {
		if m := lossRegexpWindows.FindStringSubmatch(outputStr); len(m) > 1 {
			if parsed, err := strconv.ParseFloat(m[1], 64); err == nil {
				lossPct = parsed
			}
		}
	} else {
		if m := lossRegexpLinux.FindStringSubmatch(outputStr); len(m) > 1 {
			if parsed, err := strconv.ParseFloat(m[1], 64); err == nil {
				lossPct = parsed
			}
		}
	}

	// Parse latency
	var total float64
	var count int
	
	if isWindows {
		matches := timeRegexpWindows.FindAllStringSubmatch(outputStr, -1)
		for _, m := range matches {
			if len(m) > 1 {
				if parsed, err := strconv.ParseFloat(m[1], 64); err == nil {
					total += parsed
					count++
				}
			}
		}
	} else {
		matches := timeRegexpLinux.FindAllStringSubmatch(outputStr, -1)
		for _, m := range matches {
			if len(m) > 1 {
				if parsed, err := strconv.ParseFloat(m[1], 64); err == nil {
					total += parsed
					count++
				}
			}
		}
	}

	if count > 0 {
		latencyMs = total / float64(count)
		ok = true
	} else if lossPct < 100 {
		ok = true
	}

	return latencyMs, lossPct, ok
}
