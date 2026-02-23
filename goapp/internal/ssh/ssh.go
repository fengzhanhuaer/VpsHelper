package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// SystemSSHConfig holds SSH settings read directly from the OS.
type SystemSSHConfig struct {
	Port           int
	ListenAddress  []string
	AllowPassword  bool
	AllowPubkey    bool
	AuthorizedKeys string // contents of ~/.ssh/authorized_keys
}

// ReadSystemConfig reads the actual sshd_config and authorized_keys from the OS.
func ReadSystemConfig() SystemSSHConfig {
	cfg := SystemSSHConfig{Port: 22, AllowPassword: true, AllowPubkey: true}

	if runtime.GOOS == "windows" {
		return cfg
	}

	b, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return cfg
	}

	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		val := strings.ToLower(fields[1])
		switch key {
		case "port":
			if p, err := strconv.Atoi(fields[1]); err == nil && p > 0 && p <= 65535 {
				cfg.Port = p
			}
		case "listenaddress":
			cfg.ListenAddress = append(cfg.ListenAddress, fields[1])
		case "passwordauthentication":
			cfg.AllowPassword = val == "yes"
		case "pubkeyauthentication":
			cfg.AllowPubkey = val == "yes"
		}
	}

	// Read authorized_keys
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		ak := filepath.Join(u.HomeDir, ".ssh", "authorized_keys")
		if data, err := os.ReadFile(ak); err == nil {
			cfg.AuthorizedKeys = strings.TrimSpace(string(data))
		}
	}

	return cfg
}

func Diagnose(port int) string {
	if port <= 0 {
		port = 22
	}
	if runtime.GOOS == "windows" {
		return "当前系统为 Windows，无法诊断 Linux SSH 服务。"
	}

	addr4 := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr4, 800*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return fmt.Sprintf("已连接到 %s（端口可达）。", addr4)
	}
	return fmt.Sprintf("连接 %s 失败：%v", addr4, err)
}

func InstallFail2ban(ctx context.Context) (bool, string) {
	if runtime.GOOS == "windows" {
		return false, "当前系统为 Windows，无法安装 Linux Fail2ban。"
	}

	if _, err := exec.LookPath("fail2ban-client"); err == nil {
		ok, msg := run(ctx, "systemctl", "enable", "--now", "fail2ban")
		if ok {
			return true, "Fail2ban 已安装并启动。"
		}
		ok, msg2 := run(ctx, "service", "fail2ban", "start")
		if ok {
			_ = msg
			return true, "Fail2ban 已安装并启动。"
		}
		return false, "Fail2ban 已安装，但启动失败：" + msg + " " + msg2
	}

	if _, err := exec.LookPath("apt-get"); err == nil {
		_, _ = run(ctx, "apt-get", "update")
		ok, msg := run(ctx, "apt-get", "install", "-y", "fail2ban")
		if !ok {
			return false, "apt 安装失败：" + msg
		}
		ok2, msg2 := run(ctx, "systemctl", "enable", "--now", "fail2ban")
		if ok2 {
			return true, "Fail2ban 已安装并启动。"
		}
		ok3, msg3 := run(ctx, "service", "fail2ban", "start")
		if ok3 {
			_ = msg2
			return true, "Fail2ban 已安装并启动。"
		}
		return false, "Fail2ban 已安装，但启动失败：" + msg2 + " " + msg3
	}

	return false, "未检测到 apt-get，暂不支持自动安装。"
}
func Fail2banStatus(ctx context.Context) string {
	if runtime.GOOS == "windows" {
		return "不支持 (Windows)"
	}
	if _, err := exec.LookPath("fail2ban-client"); err != nil {
		return "未安装"
	}
	ok, out := run(ctx, "fail2ban-client", "status", "sshd")
	if !ok {
		return "运行异常或未启动"
	}

	totalFailed := "0"
	banned := "0"
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "Total failed:") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				totalFailed = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "Currently banned:") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				banned = strings.TrimSpace(parts[1])
			}
		}
	}
	return fmt.Sprintf("运行中 (累计失败: %s, 当前封禁: %s)", totalFailed, banned)
}

func ApplySettings(ctx context.Context, port int, listenAddrs []string, allowPassword, allowKey bool, publicKey string) (bool, string) {
	if runtime.GOOS == "windows" {
		return false, "当前系统为 Windows，无法修改 Linux sshd 配置。"
	}
	if port < 1 || port > 65535 {
		return false, "端口范围必须在 1-65535。"
	}

	configPath := "/etc/ssh/sshd_config"
	b, err := os.ReadFile(configPath)
	if err != nil {
		return false, "读取 sshd_config 失败：" + err.Error()
	}

	backup := fmt.Sprintf("%s.vpshelper.bak.%s", configPath, time.Now().Format("20060102_150405"))
	_ = os.WriteFile(backup, b, 0o600)

	content := string(b)
	
	// Strip all existing ListenAddress lines
	lines := strings.Split(content, "\n")
	var newLines []string
	for _, ln := range lines {
		trim := strings.TrimSpace(ln)
		if strings.HasPrefix(strings.ToLower(trim), "listenaddress") {
			continue
		}
		newLines = append(newLines, ln)
	}
	content = strings.Join(newLines, "\n")

	content = setConfigOption(content, "Port", strconv.Itoa(port))
	if len(listenAddrs) > 0 {
		for _, addr := range listenAddrs {
			content += fmt.Sprintf("\nListenAddress %s", addr)
		}
		content += "\n"
	} else {
		// Open to all if empty
		content += "\nListenAddress 0.0.0.0\nListenAddress ::\n"
	}

	content = setConfigOption(content, "PasswordAuthentication", yesNo(allowPassword))
	content = setConfigOption(content, "PubkeyAuthentication", yesNo(allowKey))

	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		return false, "写入 sshd_config 失败（需要 root 权限）：" + err.Error()
	}

	if strings.TrimSpace(publicKey) != "" {
		if err := ensureAuthorizedKeys(publicKey); err != nil {
			return false, "sshd 配置已写入，但写入 authorized_keys 失败：" + err.Error()
		}
	}

	// Validate and restart best-effort.
	runNoFail(ctx, "sshd", "-t", "-f", configPath)
	runNoFail(ctx, "/usr/sbin/sshd", "-t", "-f", configPath)

	if ok, _ := restartSSH(ctx); ok {
		return true, "SSH 设置已应用到系统。"
	}
	return false, "SSH 配置已修改，但重启 ssh 服务失败（请手动重启）。"
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func setConfigOption(content, key, value string) string {
	lines := strings.Split(content, "\n")
	found := false
	for i, ln := range lines {
		trim := strings.TrimSpace(ln)
		if trim == "" {
			continue
		}
		if strings.HasPrefix(trim, "#") {
			trim = strings.TrimSpace(strings.TrimPrefix(trim, "#"))
		}
		fields := strings.Fields(trim)
		if len(fields) >= 1 && strings.EqualFold(fields[0], key) {
			lines[i] = fmt.Sprintf("%s %s", key, value)
			found = true
		}
	}
	if !found {
		lines = append(lines, fmt.Sprintf("%s %s", key, value))
	}
	return strings.Join(lines, "\n")
}

func ensureAuthorizedKeys(publicKey string) error {
	publicKey = strings.TrimSpace(publicKey)
	if publicKey == "" {
		return nil
	}

	u, err := user.Current()
	if err != nil {
		return err
	}
	home := u.HomeDir
	if home == "" {
		return errors.New("无法获取当前用户 home 目录")
	}

	sshDir := filepath.Join(home, ".ssh")
	_ = os.MkdirAll(sshDir, 0o700)
	ak := filepath.Join(sshDir, "authorized_keys")

	existing, _ := os.ReadFile(ak)
	if bytes.Contains(existing, []byte(publicKey)) {
		return nil
	}

	f, err := os.OpenFile(ak, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(publicKey + "\n"); err != nil {
		return err
	}
	return nil
}

func restartSSH(ctx context.Context) (bool, string) {
	cmds := [][]string{
		{"systemctl", "restart", "sshd"},
		{"systemctl", "restart", "ssh"},
		{"service", "sshd", "restart"},
		{"service", "ssh", "restart"},
		{"rc-service", "sshd", "restart"},
		{"/etc/init.d/sshd", "restart"},
		{"/etc/init.d/ssh", "restart"},
	}
	last := ""
	for _, c := range cmds {
		ok, msg := run(ctx, c[0], c[1:]...)
		if ok {
			return true, "ok"
		}
		if msg != "" {
			last = msg
		}
	}
	if last == "" {
		last = "未找到可用服务管理命令"
	}
	return false, last
}

func run(ctx context.Context, name string, args ...string) (bool, string) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	text := strings.TrimSpace(out.String())
	if err == nil {
		return true, text
	}
	return false, text
}

func runNoFail(ctx context.Context, name string, args ...string) {
	_, _ = run(ctx, name, args...)
}
