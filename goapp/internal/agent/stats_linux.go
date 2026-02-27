//go:build linux

package agent

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type SystemStats struct {
	CPU      float64 `json:"cpu"`       // 0-100
	MemPct   float64 `json:"mem_pct"`   // 0-100
	MemUsed  string  `json:"mem_used"`  // e.g. "1.2G/2.0G"
	SwapPct  float64 `json:"swap_pct"`  // 0-100
	SwapUsed string  `json:"swap_used"` // e.g. "1.2G/2.0G"
	DiskPct  float64 `json:"disk_pct"`  // 0-100
	DiskUsed string  `json:"disk_used"` // e.g. "10G/20G"
	NetIn    uint64  `json:"net_in"`    // Bytes/sec
	NetOut   uint64  `json:"net_out"`   // Bytes/sec
	Uptime   string  `json:"uptime"`
}

var (
	lastCPUTotal uint64
	lastCPUIdle  uint64
	lastNetIn    uint64
	lastNetOut   uint64
	lastTime     time.Time
)

func init() {
	lastTime = time.Now()
	_, _, _ = readCPU()
	_, _ = readNet()
}

func readCPU() (total uint64, idle uint64, err error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 4 && fields[0] == "cpu" {
			for i := 1; i < len(fields); i++ {
				val, _ := strconv.ParseUint(fields[i], 10, 64)
				total += val
				if i == 4 { // idle
					idle = val
				}
			}
		}
	}
	return total, idle, nil
}

func readMem() (float64, string, float64, string) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, "", 0, ""
	}
	defer file.Close()

	var memTotal, memAvailable, swapTotal, swapFree uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				memTotal, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		} else if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				memAvailable, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		} else if strings.HasPrefix(line, "SwapTotal:") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				swapTotal, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		} else if strings.HasPrefix(line, "SwapFree:") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				swapFree, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		}
	}

	var memPct float64
	var memStr string
	if memTotal > 0 {
		memUsed := memTotal - memAvailable
		memPct = float64(memUsed) / float64(memTotal) * 100
		memStr = fmt.Sprintf("%.1fG/%.1fG", float64(memUsed)/1024/1024, float64(memTotal)/1024/1024)
	}

	var swapPct float64
	var swapStr string
	if swapTotal > 0 {
		swapUsed := swapTotal - swapFree
		swapPct = float64(swapUsed) / float64(swapTotal) * 100

		// Adjust display format based on size
		if swapTotal < 1024*1024 { // Less than 1GB -> show MB
			swapStr = fmt.Sprintf("%.1fM/%.1fM", float64(swapUsed)/1024, float64(swapTotal)/1024)
		} else { // Show GB
			swapStr = fmt.Sprintf("%.1fG/%.1fG", float64(swapUsed)/1024/1024, float64(swapTotal)/1024/1024)
		}
	} else {
		swapStr = "0M/0M"
	}

	return memPct, memStr, swapPct, swapStr
}

// pseudoFSTypes lists virtual/kernel filesystems that should never be counted as disk space.
var pseudoFSTypes = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true,
	"tmpfs": true, "cgroup": true, "cgroup2": true, "hugetlbfs": true,
	"mqueue": true, "pstore": true, "securityfs": true, "debugfs": true,
	"tracefs": true, "configfs": true, "fusectl": true, "bpf": true,
	"rpc_pipefs": true, "autofs": true, "overlay": true, "squashfs": true,
	"nsfs": true, "efivarfs": true, "binfmt_misc": true,
}

func readDisk() (float64, string) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		// fallback to root only
		return readDiskSingle("/")
	}
	defer f.Close()

	seen := make(map[uint64]bool) // deduplicate by device ID
	var totalAll, usedAll uint64

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		mountPoint := fields[1]
		fsType := fields[2]

		if pseudoFSTypes[fsType] {
			continue
		}
		// Skip bind mounts that point inside another mount (options contain "bind")
		if len(fields) >= 4 && strings.Contains(fields[3], "bind") {
			continue
		}

		var stat syscall.Statfs_t
		if err := syscall.Statfs(mountPoint, &stat); err != nil {
			continue
		}
		if stat.Blocks == 0 || stat.Bsize == 0 {
			continue
		}

		// Use st_dev equivalent: encode via fsid (unique per backing device)
		devKey := (uint64(stat.Fsid.X__val[0]) << 32) | uint64(uint32(stat.Fsid.X__val[1]))
		// fallback: if fsid is zero, use the mount point string hash — still prevents double-counting
		if devKey == 0 {
			for _, b := range []byte(mountPoint) {
				devKey = devKey*31 + uint64(b)
			}
			devKey |= 1 // ensure non-zero
		}
		if seen[devKey] {
			continue
		}
		seen[devKey] = true

		total := stat.Blocks * uint64(stat.Bsize)
		free := stat.Bfree * uint64(stat.Bsize)
		totalAll += total
		usedAll += total - free
	}

	if totalAll == 0 {
		return readDiskSingle("/")
	}

	pct := float64(usedAll) / float64(totalAll) * 100
	usedStr := formatBytes(usedAll) + "/" + formatBytes(totalAll)
	return pct, usedStr
}

func readDiskSingle(path string) (float64, string) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, ""
	}
	if stat.Blocks == 0 {
		return 0, ""
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	used := total - free
	pct := float64(used) / float64(total) * 100
	return pct, fmt.Sprintf("%.1fG/%.1fG", float64(used)/1073741824, float64(total)/1073741824)
}

func formatBytes(b uint64) string {
	const (
		GB = 1 << 30
		MB = 1 << 20
	)
	if b >= GB {
		return fmt.Sprintf("%.1fG", float64(b)/GB)
	}
	return fmt.Sprintf("%.0fM", float64(b)/MB)
}

func readNet() (uint64, uint64) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	defer file.Close()

	var in, out uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, ":") {
			parts := strings.Split(line, ":")
			iface := strings.TrimSpace(parts[0])
			if iface == "lo" {
				continue // Skip loopback
			}
			fields := strings.Fields(parts[1])
			if len(fields) >= 9 {
				rx, _ := strconv.ParseUint(fields[0], 10, 64)
				tx, _ := strconv.ParseUint(fields[8], 10, 64)
				in += rx
				out += tx
			}
		}
	}
	return in, out
}

func readUptime() string {
	file, err := os.Open("/proc/uptime")
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 {
			upSecs, _ := strconv.ParseFloat(fields[0], 64)
			dur := time.Duration(upSecs) * time.Second
			days := int(dur.Hours()) / 24
			hours := int(dur.Hours()) % 24
			mins := int(dur.Minutes()) % 60
			if days > 0 {
				return fmt.Sprintf("%d天%d小时%d分", days, hours, mins)
			}
			return fmt.Sprintf("%d小时%d分", hours, mins)
		}
	}
	return ""
}

// CollectStats gathers current system load and network data since last collection.
func CollectStats() SystemStats {
	var s SystemStats
	now := time.Now()
	dt := now.Sub(lastTime).Seconds()
	if dt <= 0 {
		dt = 1
	}

	// CPU
	tot, idl, _ := readCPU()
	dTot := tot - lastCPUTotal
	dIdl := idl - lastCPUIdle
	if dTot > 0 {
		s.CPU = float64(dTot-dIdl) / float64(dTot) * 100
	}
	lastCPUTotal = tot
	lastCPUIdle = idl

	// Mem & Swap & Disk
	s.MemPct, s.MemUsed, s.SwapPct, s.SwapUsed = readMem()
	s.DiskPct, s.DiskUsed = readDisk()
	s.Uptime = readUptime()

	// Net
	in, out := readNet()
	s.NetIn = uint64(float64(in-lastNetIn) / dt)
	s.NetOut = uint64(float64(out-lastNetOut) / dt)

	lastNetIn = in
	lastNetOut = out
	lastTime = now

	return s
}
