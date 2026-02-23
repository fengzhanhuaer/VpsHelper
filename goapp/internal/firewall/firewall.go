package firewall

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

type PortRow struct {
    Port     string
    Protocol string
    BindIPs  []string
    Procs    []string
}

type ListeningRow struct {
    Port      string
    Protocol  string
    BindIP    string
    ProcNames []string
}

func run(args ...string) (bool, string) {
    if len(args) == 0 {
        return false, "missing command"
    }

    cmd := exec.Command(args[0], args[1:]...)
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
        return false, out
    }
    return true, strings.TrimSpace(stdout.String())
}

func DetectType() string {
    if runtime.GOOS == "windows" {
        return "Windows 防火墙"
    }
    if which("ufw") {
        return "UFW"
    }
    if which("firewall-cmd") {
        return "firewalld"
    }
    if which("iptables") {
        return "iptables"
    }
    return "未知"
}

func which(name string) bool {
    _, err := exec.LookPath(name)
    return err == nil
}

func CollectListeningBindings() map[string]map[string]struct{} {
    bindings := map[string]map[string]struct{}{}

    scans := []struct {
        Proto string
        Cmd   []string
    }{
        {"tcp", []string{"ss", "-lnt"}},
        {"udp", []string{"ss", "-lnu"}},
    }

    for _, scan := range scans {
        ok, out := run(scan.Cmd...)
        if !ok {
            continue
        }
        for _, line := range strings.Split(out, "\n") {
            line = strings.TrimSpace(line)
            if line == "" || strings.HasPrefix(strings.ToLower(line), "state") {
                continue
            }
            cols := regexp.MustCompile(`\s+`).Split(line, -1)
            if len(cols) < 4 {
                continue
            }
            local := cols[3]

            ip, port := splitAddr(local)
            if port == "" {
                continue
            }
            if _, err := strconv.Atoi(port); err != nil {
                continue
            }
            if ip == "*" || ip == "::" {
                ip = "0.0.0.0/::"
            }

            key := scan.Proto + ":" + port
            if _, ok := bindings[key]; !ok {
                bindings[key] = map[string]struct{}{}
            }
            bindings[key][ip] = struct{}{}
        }
    }

    return bindings
}

func CollectPortProcesses() map[string]map[string]struct{} {
    procs := map[string]map[string]struct{}{}

    scans := []struct {
        Proto string
        Cmd   []string
    }{
        {"tcp", []string{"ss", "-lntp"}},
        {"udp", []string{"ss", "-lnup"}},
    }

    nameRe := regexp.MustCompile(`"([^"]+)"`)

    for _, scan := range scans {
        ok, out := run(scan.Cmd...)
        if !ok {
            continue
        }
        for _, line := range strings.Split(out, "\n") {
            line = strings.TrimSpace(line)
            if line == "" || strings.HasPrefix(strings.ToLower(line), "state") {
                continue
            }
            cols := regexp.MustCompile(`\s+`).Split(line, -1)
            if len(cols) < 6 {
                continue
            }
            local := cols[3]
            procCol := cols[len(cols)-1]

            _, port := splitAddr(local)
            if port == "" {
                continue
            }
            if _, err := strconv.Atoi(port); err != nil {
                continue
            }

            matches := nameRe.FindAllStringSubmatch(procCol, -1)
            if len(matches) == 0 {
                continue
            }
            key := scan.Proto + ":" + port
            if _, ok := procs[key]; !ok {
                procs[key] = map[string]struct{}{}
            }
            for _, m := range matches {
                if len(m) > 1 {
                    procs[key][m[1]] = struct{}{}
                }
            }
        }
    }

    return procs
}

func CollectListeningRows() []ListeningRow {
    rows := make([]ListeningRow, 0)
    procMap := CollectPortProcesses()

    scans := []struct {
        Proto string
        Cmd   []string
    }{
        {"tcp", []string{"ss", "-lnt"}},
        {"udp", []string{"ss", "-lnu"}},
    }

    seen := map[string]struct{}{}

    for _, scan := range scans {
        ok, out := run(scan.Cmd...)
        if !ok {
            continue
        }
        for _, line := range strings.Split(out, "\n") {
            line = strings.TrimSpace(line)
            if line == "" || strings.HasPrefix(strings.ToLower(line), "state") {
                continue
            }
            cols := regexp.MustCompile(`\s+`).Split(line, -1)
            if len(cols) < 4 {
                continue
            }
            local := cols[3]

            ip, port := splitAddr(local)
            if port == "" {
                continue
            }
            if _, err := strconv.Atoi(port); err != nil {
                continue
            }
            if ip == "*" || ip == "::" {
                ip = "0.0.0.0/::"
            }

            key := scan.Proto + ":" + port + ":" + ip
            if _, ok := seen[key]; ok {
                continue
            }
            seen[key] = struct{}{}

            procNames := keysSorted(procMap[scan.Proto+":"+port])
            if len(procNames) == 0 {
                procNames = []string{"未知"}
            }

            rows = append(rows, ListeningRow{Port: port, Protocol: scan.Proto, BindIP: ip, ProcNames: procNames})
        }
    }

    sort.Slice(rows, func(i, j int) bool {
        pi, _ := strconv.Atoi(rows[i].Port)
        pj, _ := strconv.Atoi(rows[j].Port)
        if pi != pj {
            return pi < pj
        }
        return rows[i].Protocol < rows[j].Protocol
    })

    return rows
}

func CollectOpenPortsAndStatus(firewallType string) (ports []map[string]string, status string, note string) {
    if runtime.GOOS == "windows" {
        return []map[string]string{}, "未知", "当前为 Windows 环境，暂未实现防火墙规则解析。"
    }

    if firewallType == "UFW" {
        // Use 'ufw status' first to get active state
        ok, out := run("ufw", "status")
        if !ok {
            return []map[string]string{}, "未知", "读取 UFW 状态失败：" + out
        }

        st := "未知"
        firstLine := ""
        for _, l := range strings.Split(out, "\n") {
            l = strings.TrimSpace(l)
            if l != "" {
                firstLine = strings.ToLower(l)
                break
            }
        }
        if strings.Contains(firstLine, "active") {
            st = "已启用"
        } else if strings.Contains(firstLine, "inactive") || strings.Contains(firstLine, "disabled") {
            st = "未启用"
        }

        noteStr := ""
        if st != "已启用" {
            noteStr = "UFW 当前未启用。"
        }

        // Use 'ufw status numbered' for reliable rule parsing
        // Falls back to basic parsing if numbered fails
        okN, outN := run("ufw", "status", "numbered")
        if !okN {
            outN = out
        }

        // Match lines like:
        //   [ 1] 80/tcp                     ALLOW IN    Anywhere
        //   [ 2] 443/tcp                    ALLOW IN    1.2.3.4
        //   [ 3] 22                         ALLOW IN    Anywhere
        // Numbered format: `[ N] <to>   ALLOW IN   <from>`
        // Non-numbered:    `<to>         ALLOW IN   <from>`
        portRe := regexp.MustCompile(`(\d+)(?:/(tcp|udp))?`)

        // key = "port/proto:source" to allow multiple sources per port
        type ufwEntry struct {
            port     string
            protocol string
            source   string
        }
        var entries []ufwEntry
        seenEntry := map[string]struct{}{}
        for _, line := range strings.Split(outN, "\n") {
            // Must be an ALLOW IN rule (inbound), skip ALLOW OUT / ALLOW FWD
            if !strings.Contains(line, "ALLOW IN") && !strings.Contains(line, "ALLOW") {
                continue
            }
            // Skip IPv6 duplicates (marked with "(v6)")
            if strings.Contains(line, "(v6)") {
                continue
            }
            // Strip leading numbering "[ N] "
            clean := regexp.MustCompile(`^\[\s*\d+\]\s*`).ReplaceAllString(strings.TrimSpace(line), "")
            // Split on 2+ spaces to get columns
            cols := regexp.MustCompile(`\s{2,}`).Split(clean, -1)
            if len(cols) == 0 {
                continue
            }
            toField := strings.TrimSpace(cols[0])
            m := portRe.FindStringSubmatch(toField)
            if len(m) < 2 {
                continue
            }
            portNum := m[1]
            proto := "tcp"
            if len(m) == 3 && m[2] != "" {
                proto = strings.ToLower(m[2])
            }
            // Extract source (from field, last column)
            source := ""
            if len(cols) >= 3 {
                src := strings.TrimSpace(cols[len(cols)-1])
                lsrc := strings.ToLower(src)
                if lsrc != "anywhere" && lsrc != "any" && src != "" {
                    source = src
                }
            }
            entryKey := portNum + "/" + proto + ":" + source
            if _, exists := seenEntry[entryKey]; exists {
                continue
            }
            seenEntry[entryKey] = struct{}{}
            entries = append(entries, ufwEntry{port: portNum, protocol: proto, source: source})
        }

        sort.Slice(entries, func(i, j int) bool {
            pi, _ := strconv.Atoi(entries[i].port)
            pj, _ := strconv.Atoi(entries[j].port)
            if pi != pj {
                return pi < pj
            }
            if entries[i].protocol != entries[j].protocol {
                return entries[i].protocol < entries[j].protocol
            }
            return entries[i].source < entries[j].source
        })
        items := make([]map[string]string, 0, len(entries))
        for _, e := range entries {
            items = append(items, map[string]string{"port": e.port, "protocol": e.protocol, "source": e.source})
        }
        return items, st, noteStr
    }

    if firewallType == "firewalld" {
        okState, state := run("firewall-cmd", "--state")
        if okState && strings.TrimSpace(state) == "running" {
            okPorts, portsText := run("firewall-cmd", "--list-ports")
            if !okPorts {
                return []map[string]string{}, "已启用", "无法读取 firewalld 端口规则。"
            }

            portRe := regexp.MustCompile(`(\d+)/(tcp|udp)`)
            var items []map[string]string
            seen := map[string]struct{}{}

            // Global open ports (no source restriction)
            for _, item := range strings.Fields(portsText) {
                m := portRe.FindStringSubmatch(item)
                if len(m) == 3 {
                    proto := strings.ToLower(m[2])
                    entryKey := m[1] + "/" + proto + ":"
                    if _, exists := seen[entryKey]; !exists {
                        seen[entryKey] = struct{}{}
                        items = append(items, map[string]string{"port": m[1], "protocol": proto, "source": ""})
                    }
                }
            }

            // Rich rules (source-restricted ports)
            _, richText := run("firewall-cmd", "--list-rich-rules")
            richPortRe := regexp.MustCompile(`port port="(\d+)" protocol="(tcp|udp)"`)
            richSrcRe := regexp.MustCompile(`source address="([^"]+)"`)
            for _, rline := range strings.Split(richText, "\n") {
                rline = strings.TrimSpace(rline)
                if rline == "" || !strings.Contains(rline, "accept") {
                    continue
                }
                pm := richPortRe.FindStringSubmatch(rline)
                if len(pm) != 3 {
                    continue
                }
                src := ""
                if sm := richSrcRe.FindStringSubmatch(rline); len(sm) == 2 {
                    src = sm[1]
                }
                proto := strings.ToLower(pm[2])
                entryKey := pm[1] + "/" + proto + ":" + src
                if _, exists := seen[entryKey]; !exists {
                    seen[entryKey] = struct{}{}
                    items = append(items, map[string]string{"port": pm[1], "protocol": proto, "source": src})
                }
            }

            sort.Slice(items, func(i, j int) bool {
                pi, _ := strconv.Atoi(items[i]["port"])
                pj, _ := strconv.Atoi(items[j]["port"])
                if pi != pj {
                    return pi < pj
                }
                if items[i]["protocol"] != items[j]["protocol"] {
                    return items[i]["protocol"] < items[j]["protocol"]
                }
                return items[i]["source"] < items[j]["source"]
            })

            return items, "已启用", ""
        }

        return []map[string]string{}, "未启用", "firewalld 未运行。"
    }

    if firewallType == "iptables" {
        ok, out := run("iptables", "-S", "INPUT")
        if !ok {
            return []map[string]string{}, "未知", "读取 iptables 失败：" + out
        }

        portRe := regexp.MustCompile(`--dport\s+(\d+)`)
        protoRe := regexp.MustCompile(`-p\s+(tcp|udp)`)
        srcRe := regexp.MustCompile(`-s\s+(\S+)`)

        seen := map[string]struct{}{}
        var items []map[string]string
        for _, line := range strings.Split(out, "\n") {
            if !strings.Contains(line, " --dport ") || !strings.Contains(line, " -j ACCEPT") {
                continue
            }
            pm := portRe.FindStringSubmatch(line)
            if len(pm) != 2 {
                continue
            }
            proto := "tcp"
            if pr := protoRe.FindStringSubmatch(line); len(pr) == 2 {
                proto = strings.ToLower(pr[1])
            }
            src := ""
            if sr := srcRe.FindStringSubmatch(line); len(sr) == 2 {
                // ignore wildcard
                if sr[1] != "0.0.0.0/0" && sr[1] != "::/0" {
                    src = sr[1]
                }
            }
            entryKey := pm[1] + "/" + proto + ":" + src
            if _, exists := seen[entryKey]; exists {
                continue
            }
            seen[entryKey] = struct{}{}
            items = append(items, map[string]string{"port": pm[1], "protocol": proto, "source": src})
        }

        sort.Slice(items, func(i, j int) bool {
            pi, _ := strconv.Atoi(items[i]["port"])
            pj, _ := strconv.Atoi(items[j]["port"])
            if pi != pj {
                return pi < pj
            }
            if items[i]["protocol"] != items[j]["protocol"] {
                return items[i]["protocol"] < items[j]["protocol"]
            }
            return items[i]["source"] < items[j]["source"]
        })

        return items, "已加载", ""
    }

    return []map[string]string{}, "未知", "未检测到可识别的防火墙工具（ufw/firewalld/iptables）。"
}

func Enable(firewallType string) (bool, string) {
	if firewallType == "未知" || firewallType == "" {
		if runtime.GOOS == "windows" {
			return false, "当前为 Windows 环境，暂不自动安装防火墙。"
		}
		installLog := ""
		// 尝试自动安装防火墙
		if which("apt-get") {
			run("apt-get", "update")
			ok, out := run("apt-get", "install", "-y", "ufw")
			if !ok {
				installLog = " apt 安装 UFW 失败：" + out
			}
		} else if which("yum") {
			ok, out := run("yum", "install", "-y", "firewalld")
			if !ok {
				installLog = " yum 安装 firewalld 失败：" + out
			}
		} else if which("dnf") {
			ok, out := run("dnf", "install", "-y", "firewalld")
			if !ok {
				installLog = " dnf 安装 firewalld 失败：" + out
			}
		}

		firewallType = DetectType()
		if firewallType == "未知" {
			return false, "系统中未检测到可启用的防火墙工具，自动尝试安装由于以下原因失败：" + installLog + "。请自行使用命令行手动安装 ufw 或 firewalld。"
		}
	}

	if firewallType == "UFW" {
		// Step 1: Set default policies BEFORE enabling to avoid traffic interruption
		run("ufw", "default", "deny", "incoming")
		run("ufw", "default", "allow", "outgoing")

		// Step 2: Ensure SSH port is allowed BEFORE enabling (prevents lockout).
		// Detect current SSH port from sshd_config; fall back to 22.
		sshPort := detectSSHPort()
		run("ufw", "allow", fmt.Sprintf("%s/tcp", sshPort))

		// Step 3: Enable firewall (non-interactive)
		ok, out := run("ufw", "--force", "enable")
		if ok {
			msg := fmt.Sprintf("UFW 防火墙已启用（默认拒绝入站）。SSH 端口 %s/tcp 已自动放行，请确认可正常登录后再调整规则。", sshPort)
			return true, msg
		}
		return false, "尝试启用 UFW 失败：" + out
	}

	if firewallType == "firewalld" {
		ok, out := run("systemctl", "enable", "--now", "firewalld")
		if ok {
			return true, "firewalld 防火墙已成功安装、启用并启动。"
		}
		ok2, out2 := run("service", "firewalld", "start")
		if ok2 {
			return true, "firewalld 已启动。"
		}
		if out == "" {
			out = out2
		}
		return false, "启用 firewalld 失败：" + out
	}

	if firewallType == "iptables" {
		return true, "iptables 无独立启用步骤，规则即时生效。"
	}

	return false, "当前已安装防识别墙由于不可预见的错误无法启用 (" + firewallType + ")。"
}

func Disable(firewallType string) (bool, string) {
	if runtime.GOOS == "windows" {
		return false, "当前为 Windows 环境，暂不支持自动关闭防火墙。"
	}

	if firewallType == "UFW" {
		ok, out := run("ufw", "--force", "disable")
		if ok {
			return true, "UFW 防火墙已关闭（入站流量将不再受限）。"
		}
		return false, "关闭 UFW 失败：" + out
	}

	if firewallType == "firewalld" {
		ok, out := run("systemctl", "stop", "firewalld")
		if !ok {
			return false, "停止 firewalld 失败：" + out
		}
		run("systemctl", "disable", "firewalld")
		return true, "firewalld 防火墙已停止并禁用自启。"
	}

	if firewallType == "iptables" {
		// 先将默认策略改回 ACCEPT，再 flush 规则，确保关闭后流量不被阻断
		run("iptables", "-P", "INPUT", "ACCEPT")
		run("iptables", "-P", "FORWARD", "ACCEPT")
		run("iptables", "-P", "OUTPUT", "ACCEPT")
		run("iptables", "-F")
		persistIptables()
		return true, "iptables 规则已清空，默认策略已改为全部放行。如需彻底禁用请手动卸载 iptables 服务。"
	}

	return false, "未检测到可用防火墙工具（" + firewallType + "）。"
}


func OpenPort(firewallType string, port int, protocol string, sourceIP string) (bool, string) {
	if port < 1 || port > 65535 {
		return false, "端口范围必须在 1-65535。"
	}
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol != "tcp" && protocol != "udp" {
		return false, "端口类型仅支持 tcp 或 udp。"
	}

	if firewallType == "UFW" {
		if sourceIP != "" {
			ok, out := run("ufw", "allow", "from", sourceIP, "to", "any", "port", strconv.Itoa(port), "proto", protocol)
			if ok {
				return true, fmt.Sprintf("UFW 仅为 IP %s 限制开放了 %d/%s。", sourceIP, port, protocol)
			}
			return false, "UFW 限制端口开放失败：" + out
		}
		
		ok, out := run("ufw", "allow", fmt.Sprintf("%d/%s", port, protocol))
		if ok {
			return true, fmt.Sprintf("UFW 已全局开放 %d/%s。", port, protocol)
		}
		return false, "UFW 开放端口失败：" + out
	}

	if firewallType == "firewalld" {
		if sourceIP != "" {
			rule := fmt.Sprintf("rule family=\"ipv4\" source address=\"%s\" port port=\"%d\" protocol=\"%s\" accept", sourceIP, port, protocol)
			okAdd, outAdd := run("firewall-cmd", "--permanent", "--add-rich-rule", rule)
			if !okAdd {
				return false, "firewalld 添加限源规则失败：" + outAdd
			}
			run("firewall-cmd", "--reload")
			return true, fmt.Sprintf("firewalld 仅为 IP %s 限制开放了 %d/%s。", sourceIP, port, protocol)
		}

		okAdd, outAdd := run("firewall-cmd", "--permanent", fmt.Sprintf("--add-port=%d/%s", port, protocol))
		if !okAdd {
			return false, "firewalld 添加端口失败：" + outAdd
		}
		run("firewall-cmd", "--reload")
		return true, fmt.Sprintf("firewalld 已全局开放 %d/%s。", port, protocol)
	}

	if firewallType == "iptables" {
		if sourceIP != "" {
			okAdd, outAdd := run("iptables", "-I", "INPUT", "-p", protocol, "-s", sourceIP, "--dport", strconv.Itoa(port), "-j", "ACCEPT")
			if !okAdd {
				return false, "iptables 限制源 IP 开放端口失败：" + outAdd
			}
			persistIptables()
			return true, fmt.Sprintf("iptables 仅为 IP %s 限制开放了 %d/%s。", sourceIP, port, protocol)
		}

		// Check existing rule.
		okCheck, _ := run("iptables", "-C", "INPUT", "-p", protocol, "--dport", strconv.Itoa(port), "-j", "ACCEPT")
		if !okCheck {
			okAdd, outAdd := run("iptables", "-I", "INPUT", "-p", protocol, "--dport", strconv.Itoa(port), "-j", "ACCEPT")
			if !okAdd {
				return false, "iptables 开放端口失败：" + outAdd
			}
		}
		okPersist, persistMsg := persistIptables()
		if !okPersist {
			return false, persistMsg
		}
		return true, fmt.Sprintf("iptables 已开全局放 %d/%s。%s", port, protocol, persistMsg)
	}

	return false, "未检测到可用防火墙工具。"
}

func DeletePort(firewallType string, port int, protocol string, sourceIP string) (bool, string) {
	if port < 1 || port > 65535 {
		return false, "端口范围必须在 1-65535。"
	}
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol != "tcp" && protocol != "udp" {
		return false, "端口类型仅支持 tcp 或 udp。"
	}

	if firewallType == "UFW" {
		if sourceIP != "" {
			ok, out := run("ufw", "delete", "allow", "from", sourceIP, "to", "any", "port", strconv.Itoa(port), "proto", protocol)
			if ok {
				return true, fmt.Sprintf("UFW 删除了源 IP %s 对 %d/%s 的限制放行规则。", sourceIP, port, protocol)
			}
			return false, "UFW 删除规则失败：" + out
		}
		
		ok, out := run("ufw", "delete", "allow", fmt.Sprintf("%d/%s", port, protocol))
		if ok {
			return true, fmt.Sprintf("UFW 已删除全局 %d/%s 放行规则。", port, protocol)
		}
		return false, "UFW 删除规则失败：" + out
	}

	if firewallType == "firewalld" {
		if sourceIP != "" {
			rule := fmt.Sprintf("rule family=\"ipv4\" source address=\"%s\" port port=\"%d\" protocol=\"%s\" accept", sourceIP, port, protocol)
			okRm, outRm := run("firewall-cmd", "--permanent", "--remove-rich-rule", rule)
			if !okRm {
				return false, "firewalld 删除限源规则失败：" + outRm
			}
			run("firewall-cmd", "--reload")
			return true, fmt.Sprintf("firewalld 已删除供源 IP %s 放行的 %d/%s。", sourceIP, port, protocol)
		}

		okRm, outRm := run("firewall-cmd", "--permanent", fmt.Sprintf("--remove-port=%d/%s", port, protocol))
		if !okRm {
			return false, "firewalld 删除端口失败：" + outRm
		}
		run("firewall-cmd", "--reload")
		return true, fmt.Sprintf("firewalld 已关闭 %d/%s。", port, protocol)
	}

	if firewallType == "iptables" {
		if sourceIP != "" {
			okRm, outRm := run("iptables", "-D", "INPUT", "-p", protocol, "-s", sourceIP, "--dport", strconv.Itoa(port), "-j", "ACCEPT")
			if !okRm {
				return false, "iptables 删除限源规则失败：" + outRm
			}
			persistIptables()
			return true, fmt.Sprintf("iptables 已删除源 IP %s 放行的 %d/%s。", sourceIP, port, protocol)
		}

		// Delete global rule
		okRm, outRm := run("iptables", "-D", "INPUT", "-p", protocol, "--dport", strconv.Itoa(port), "-j", "ACCEPT")
		if !okRm {
			return false, "iptables 删除端口失败：" + outRm
		}
		okPersist, persistMsg := persistIptables()
		if !okPersist {
			return false, persistMsg
		}
		return true, fmt.Sprintf("iptables 已删除全局 %d/%s。%s", port, protocol, persistMsg)
	}

	return false, "未检测到可用防火墙工具。"
}

func persistIptables() (bool, string) {
    if which("netfilter-persistent") {
        ok, _ := run("netfilter-persistent", "save")
        if ok {
            return true, "iptables 规则已持久化(netfilter-persistent)"
        }
    }

    okService, _ := run("service", "iptables", "save")
    if okService {
        return true, "iptables 规则已持久化(service iptables save)"
    }

    if which("iptables-save") {
        targets := []string{"/etc/iptables/rules.v4", "/etc/sysconfig/iptables", "/etc/iptables/iptables.rules"}
        for _, target := range targets {
            if err := os.MkdirAll(filepathDir(target), 0o755); err != nil {
                continue
            }
            cmd := exec.Command("iptables-save")
            var stdout bytes.Buffer
            cmd.Stdout = &stdout
            if err := cmd.Run(); err != nil {
                continue
            }
            if err := os.WriteFile(target, stdout.Bytes(), 0o644); err == nil {
                return true, "iptables 规则已保存到 " + target
            }
        }
    }

    return false, "iptables 持久化失败：未检测到可用持久化工具。"
}

func filepathDir(p string) string {
    idx := strings.LastIndex(p, string(os.PathSeparator))
    if idx <= 0 {
        return "."
    }
    return p[:idx]
}

func splitAddr(local string) (ip string, port string) {
    local = strings.TrimSpace(local)
    if local == "" {
        return "", ""
    }

    if strings.HasPrefix(local, "[") && strings.Contains(local, "]:") {
        parts := strings.SplitN(local, "]:", 2)
        ip = strings.TrimPrefix(parts[0], "[")
        port = parts[1]
        return ip, port
    }

    if strings.Count(local, ":") >= 1 {
        // Take last colon as port separator.
        idx := strings.LastIndex(local, ":")
        if idx > 0 {
            ip = local[:idx]
            port = local[idx+1:]
            return ip, port
        }
    }

    return "", ""
}

func keysSorted(m map[string]struct{}) []string {
    if len(m) == 0 {
        return []string{}
    }
    out := make([]string, 0, len(m))
    for k := range m {
        out = append(out, k)
    }
    sort.Strings(out)
    return out
}

// detectSSHPort reads the SSH daemon port from /etc/ssh/sshd_config.
// Returns "22" if the file cannot be read or no Port directive is found.
func detectSSHPort() string {
    data, err := os.ReadFile("/etc/ssh/sshd_config")
    if err != nil {
        return "22"
    }
    portRe := regexp.MustCompile(`(?im)^\s*Port\s+(\d+)`)
    m := portRe.FindSubmatch(data)
    if len(m) == 2 {
        p := strings.TrimSpace(string(m[1]))
        if p != "" {
            return p
        }
    }
    return "22"
}
