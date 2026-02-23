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

func readMem() (float64, string) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, ""
	}
	defer file.Close()

	var memTotal, memAvailable uint64
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
		}
	}

	if memTotal == 0 {
		return 0, ""
	}

	memUsed := memTotal - memAvailable
	pct := float64(memUsed) / float64(memTotal) * 100

	usedStr := fmt.Sprintf("%.1fG/%.1fG", float64(memUsed)/1024/1024, float64(memTotal)/1024/1024)
	return pct, usedStr
}

func readDisk() (float64, string) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return 0, ""
	}

	// Blocks * BlockSize
	totalBytes := stat.Blocks * uint64(stat.Bsize)
	freeBytes := stat.Bfree * uint64(stat.Bsize)

	if totalBytes == 0 {
		return 0, ""
	}

	usedBytes := totalBytes - freeBytes
	pct := float64(usedBytes) / float64(totalBytes) * 100

	usedStr := fmt.Sprintf("%.1fG/%.1fG", float64(usedBytes)/1073741824, float64(totalBytes)/1073741824)
	return pct, usedStr
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

	// Mem & Disk
	s.MemPct, s.MemUsed = readMem()
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
