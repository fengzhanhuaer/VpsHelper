//go:build !windows

package conntrack

// snapshot 在非 Windows 平台返回空列表（桩实现）
func snapshot() ([]Connection, error) {
	return []Connection{}, nil
}
