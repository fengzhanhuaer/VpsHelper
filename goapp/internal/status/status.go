package status

import (
    "bufio"
    "fmt"
    "os"
    "path/filepath"
    "runtime"
    "strconv"
    "strings"
    "sync"
    "time"
)

type memStats struct {
    Total        uint64  `json:"total"`
    Used         uint64  `json:"used"`
    Free         uint64  `json:"free"`
    UsagePercent float64 `json:"usage_percent"`
}

type diskStats struct {
    Total        uint64  `json:"total"`
    Used         uint64  `json:"used"`
    Free         uint64  `json:"free"`
    UsagePercent float64 `json:"usage_percent"`
}

type cpuStats struct {
    UsagePercent float64 `json:"usage_percent"`
}

type timeStats struct {
    Timezone string `json:"timezone"`
    Now      string `json:"now"`
    Uptime   string `json:"uptime"`
}

type Data struct {
    Time timeStats `json:"time"`
    RAM  memStats  `json:"ram"`
    CPU  cpuStats  `json:"cpu"`
    Disk diskStats `json:"disk"`
}

var (
    lastCPUTotal uint64
    lastCPUIdle  uint64
    cpuMu        sync.Mutex
    processStart = time.Now()
)

func Collect() Data {
    tz := os.Getenv("VPSHELPER_TZ")
    if tz == "" {
        tz = os.Getenv("TZ")
    }
    if tz == "" {
        tz = "Asia/Shanghai"
    }

    now := time.Now().Format("2006-01-02 15:04:05")

    uptime := readUptime()
    if uptime == 0 {
        uptime = time.Since(processStart)
    }

    return Data{
        Time: timeStats{Timezone: tz, Now: now, Uptime: formatDuration(uptime)},
        RAM:  readMem(),
        CPU:  cpuStats{UsagePercent: readCPUPercent()},
        Disk: readDisk(),
    }
}

func readUptime() time.Duration {
    if runtime.GOOS == "windows" {
        return 0
    }
    b, err := os.ReadFile("/proc/uptime")
    if err != nil {
        return 0
    }
    parts := strings.Fields(string(b))
    if len(parts) == 0 {
        return 0
    }
    seconds, err := strconv.ParseFloat(parts[0], 64)
    if err != nil {
        return 0
    }
    return time.Duration(seconds * float64(time.Second))
}

func formatDuration(d time.Duration) string {
    total := int(d.Seconds())
    if total < 0 {
        total = 0
    }

    days := total / 86400
    total %= 86400
    hours := total / 3600
    total %= 3600
    minutes := total / 60
    seconds := total % 60

    parts := make([]string, 0, 3)
    if days > 0 {
        parts = append(parts, fmt.Sprintf("%d天", days))
    }
    if hours > 0 {
        parts = append(parts, fmt.Sprintf("%d小时", hours))
    }
    if minutes > 0 {
        parts = append(parts, fmt.Sprintf("%d分钟", minutes))
    }
    if len(parts) == 0 {
        parts = append(parts, fmt.Sprintf("%d秒", seconds))
    }
    return strings.Join(parts, " ")
}

func readMem() memStats {
    if runtime.GOOS == "windows" {
        return memStats{}
    }

    f, err := os.Open("/proc/meminfo")
    if err != nil {
        return memStats{}
    }
    defer f.Close()

    var total uint64
    var available uint64

    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        line := scanner.Text()
        if strings.HasPrefix(line, "MemTotal:") {
            fields := strings.Fields(line)
            if len(fields) >= 2 {
                v, _ := strconv.ParseUint(fields[1], 10, 64)
                total = v * 1024
            }
        }
        if strings.HasPrefix(line, "MemAvailable:") {
            fields := strings.Fields(line)
            if len(fields) >= 2 {
                v, _ := strconv.ParseUint(fields[1], 10, 64)
                available = v * 1024
            }
        }
    }

    used := uint64(0)
    if total > available {
        used = total - available
    }

    percent := 0.0
    if total > 0 {
        percent = float64(used) / float64(total) * 100
        percent = float64(int(percent*100)) / 100
    }

    return memStats{Total: total, Used: used, Free: available, UsagePercent: percent}
}

func readCPUPercent() float64 {
    if runtime.GOOS == "windows" {
        return 0
    }

    b, err := os.ReadFile("/proc/stat")
    if err != nil {
        return 0
    }

    firstLine := strings.SplitN(string(b), "\n", 2)[0]
    firstLine = strings.TrimSpace(firstLine)
    if !strings.HasPrefix(firstLine, "cpu ") {
        return 0
    }

    parts := strings.Fields(firstLine)
    if len(parts) < 5 {
        return 0
    }

    var values []uint64
    for _, s := range parts[1:] {
        v, err := strconv.ParseUint(s, 10, 64)
        if err != nil {
            return 0
        }
        values = append(values, v)
    }

    total := uint64(0)
    for _, v := range values {
        total += v
    }

    idle := values[3]
    if len(values) > 4 {
        idle += values[4]
    }

    cpuMu.Lock()
    defer cpuMu.Unlock()

    if lastCPUTotal == 0 || lastCPUIdle == 0 {
        lastCPUTotal = total
        lastCPUIdle = idle
        return 0
    }

    totalDiff := total - lastCPUTotal
    idleDiff := idle - lastCPUIdle
    lastCPUTotal = total
    lastCPUIdle = idle

    if totalDiff == 0 {
        return 0
    }

    usage := (1 - float64(idleDiff)/float64(totalDiff)) * 100
    if usage < 0 {
        usage = 0
    }
    if usage > 100 {
        usage = 100
    }
    usage = float64(int(usage*100)) / 100
    return usage
}

func readDisk() diskStats {
    root := "/"
    if runtime.GOOS == "windows" {
        root = filepath.VolumeName(os.Args[0]) + "\\"
        if root == "\\" || root == "" {
            root = "C:\\"
        }
    }

    // Use os.Statfs via syscall when available.
    total, free, ok := statFS(root)
    if !ok || total == 0 {
        return diskStats{}
    }

    used := total - free
    percent := float64(used) / float64(total) * 100
    percent = float64(int(percent*100)) / 100

    return diskStats{Total: total, Used: used, Free: free, UsagePercent: percent}
}
