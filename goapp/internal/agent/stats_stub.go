//go:build !linux

package agent

type SystemStats struct {
	CPU      float64 `json:"cpu"`
	MemPct   float64 `json:"mem_pct"`
	MemUsed  string  `json:"mem_used"`
	DiskPct  float64 `json:"disk_pct"`
	DiskUsed string  `json:"disk_used"`
	NetIn    uint64  `json:"net_in"`
	NetOut   uint64  `json:"net_out"`
	Uptime   string  `json:"uptime"`
}

func CollectStats() SystemStats {
	// Stub for non-linux systems where procfs is not available
	return SystemStats{
		Uptime: "Not Supported on non-Linux",
	}
}
