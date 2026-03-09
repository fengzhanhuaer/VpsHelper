package conntrack

// Connection 表示系统中的一条网络连接
type Connection struct {
	PID        uint32 `json:"pid"`
	ProcName   string `json:"procName"`
	Protocol   string `json:"protocol"`  // "TCP" / "UDP"
	LocalAddr  string `json:"localAddr"` // "IP:Port"
	RemoteAddr string `json:"remoteAddr"`
	State      string `json:"state"` // ESTABLISHED / TIME_WAIT / LISTEN / ...
}

// Snapshot 返回当前系统所有活跃网络连接（含进程信息）
func Snapshot() ([]Connection, error) {
	return snapshot()
}
