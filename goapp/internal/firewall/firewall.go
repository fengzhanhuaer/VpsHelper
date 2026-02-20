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
        ok, out := run("ufw", "status")
        if !ok {
            return []map[string]string{}, "未知", "读取 UFW 状态失败：" + out
        }

        lines := strings.Split(out, "\n")
        st := "未知"
        if len(lines) > 0 && strings.HasPrefix(strings.ToLower(strings.TrimSpace(lines[0])), "status") {
            if strings.Contains(strings.ToLower(lines[0]), "active") {
                st = "已启用"
            } else {
                st = "未启用"
            }
        }

        portRe := regexp.MustCompile(`(\d+)/(tcp|udp)`)
        unique := map[string]map[string]string{}
        for _, line := range lines {
            if !strings.Contains(line, "ALLOW") {
                continue
            }
            cols := regexp.MustCompile(`\s{2,}`).Split(strings.TrimSpace(line), -1)
            if len(cols) == 0 {
                continue
            }
            m := portRe.FindStringSubmatch(cols[0])
            if len(m) == 3 {
                key := m[1] + "/" + strings.ToLower(m[2])
                unique[key] = map[string]string{"port": m[1], "protocol": strings.ToLower(m[2])}
            }
        }

        note := ""
        if st != "已启用" {
            note = "UFW 当前未启用。"
        }

        items := make([]map[string]string, 0, len(unique))
        for _, v := range unique {
            items = append(items, v)
        }
        sort.Slice(items, func(i, j int) bool {
            pi, _ := strconv.Atoi(items[i]["port"])
            pj, _ := strconv.Atoi(items[j]["port"])
            if pi != pj {
                return pi < pj
            }
            return items[i]["protocol"] < items[j]["protocol"]
        })
        return items, st, note
    }

    if firewallType == "firewalld" {
        okState, state := run("firewall-cmd", "--state")
        if okState && strings.TrimSpace(state) == "running" {
            okPorts, portsText := run("firewall-cmd", "--list-ports")
            if !okPorts {
                return []map[string]string{}, "已启用", "无法读取 firewalld 端口规则。"
            }

            portRe := regexp.MustCompile(`(\d+)/(tcp|udp)`)
            unique := map[string]map[string]string{}
            for _, item := range strings.Fields(portsText) {
                m := portRe.FindStringSubmatch(item)
                if len(m) == 3 {
                    key := m[1] + "/" + strings.ToLower(m[2])
                    unique[key] = map[string]string{"port": m[1], "protocol": strings.ToLower(m[2])}
                }
            }

            items := make([]map[string]string, 0, len(unique))
            for _, v := range unique {
                items = append(items, v)
            }
            sort.Slice(items, func(i, j int) bool {
                pi, _ := strconv.Atoi(items[i]["port"])
                pj, _ := strconv.Atoi(items[j]["port"])
                if pi != pj {
                    return pi < pj
                }
                return items[i]["protocol"] < items[j]["protocol"]
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

        unique := map[string]map[string]string{}
        portRe := regexp.MustCompile(`--dport\s+(\d+)`)
        protoRe := regexp.MustCompile(`-p\s+(tcp|udp)`)

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
            key := pm[1] + "/" + proto
            unique[key] = map[string]string{"port": pm[1], "protocol": proto}
        }

        items := make([]map[string]string, 0, len(unique))
        for _, v := range unique {
            items = append(items, v)
        }
        sort.Slice(items, func(i, j int) bool {
            pi, _ := strconv.Atoi(items[i]["port"])
            pj, _ := strconv.Atoi(items[j]["port"])
            if pi != pj {
                return pi < pj
            }
            return items[i]["protocol"] < items[j]["protocol"]
        })

        return items, "已加载", ""
    }

    return []map[string]string{}, "未知", "未检测到可识别的防火墙工具（ufw/firewalld/iptables）。"
}

func Enable(firewallType string) (bool, string) {
    if firewallType == "UFW" {
        ok, out := run("ufw", "--force", "enable")
        if ok {
            return true, "UFW 已启用。"
        }
        return false, "启用 UFW 失败：" + out
    }

    if firewallType == "firewalld" {
        ok, out := run("systemctl", "enable", "--now", "firewalld")
        if ok {
            return true, "firewalld 已启用并启动。"
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

    return false, "未检测到可启用的防火墙工具。"
}

func OpenPort(firewallType string, port int, protocol string) (bool, string) {
    if port < 1 || port > 65535 {
        return false, "端口范围必须在 1-65535。"
    }
    protocol = strings.ToLower(strings.TrimSpace(protocol))
    if protocol != "tcp" && protocol != "udp" {
        return false, "端口类型仅支持 tcp 或 udp。"
    }

    if firewallType == "UFW" {
        ok, out := run("ufw", "allow", fmt.Sprintf("%d/%s", port, protocol))
        if ok {
            return true, fmt.Sprintf("UFW 已开放 %d/%s。", port, protocol)
        }
        return false, "UFW 开放端口失败：" + out
    }

    if firewallType == "firewalld" {
        okAdd, outAdd := run("firewall-cmd", "--permanent", fmt.Sprintf("--add-port=%d/%s", port, protocol))
        if !okAdd {
            return false, "firewalld 添加端口失败：" + outAdd
        }
        okReload, outReload := run("firewall-cmd", "--reload")
        if !okReload {
            return false, "firewalld 重载失败：" + outReload
        }
        return true, fmt.Sprintf("firewalld 已开放 %d/%s。", port, protocol)
    }

    if firewallType == "iptables" {
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
        return true, fmt.Sprintf("iptables 已开放 %d/%s。%s", port, protocol, persistMsg)
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
