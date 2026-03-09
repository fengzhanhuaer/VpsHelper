//go:build windows

package conntrack

import (
	"strings"
	"testing"
)

func TestSnapshot(t *testing.T) {
	conns, err := Snapshot()
	if err != nil {
		t.Fatalf("Snapshot() 返回错误: %v", err)
	}
	if len(conns) == 0 {
		t.Fatal("Snapshot() 返回空列表，Windows 上应该存在系统连接")
	}

	t.Logf("共返回 %d 条连接", len(conns))

	for _,c := range conns {
		// ProcName 不能为空
		if c.ProcName == "" {
			t.Errorf("PID=%d 的 ProcName 为空", c.PID)
		}
		// LocalAddr 需包含冒号（IP:Port 格式）
		if !strings.Contains(c.LocalAddr, ":") {
			t.Errorf("LocalAddr 格式有误: %q", c.LocalAddr)
		}
		// Protocol 必须是 TCP 或 UDP
		if c.Protocol != "TCP" && c.Protocol != "UDP" {
			t.Errorf("未知协议: %q", c.Protocol)
		}
	}

	// 打印前 5 条示例
	limit := 5
	if len(conns) < limit {
		limit = len(conns)
	}
	t.Log("── 样本连接 ──")
	for _, c := range conns[:limit] {
		t.Logf("[%s] %-30s pid=%-6d local=%-22s remote=%-22s state=%s",
			c.Protocol, c.ProcName, c.PID, c.LocalAddr, c.RemoteAddr, c.State)
	}
}
