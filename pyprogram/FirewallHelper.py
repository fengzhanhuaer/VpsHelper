import os
import re
import shutil
import subprocess
from pathlib import Path

from flask import redirect, render_template, request, url_for

APP = None


def setup(app, _base_dir: Path) -> None:
    global APP
    APP = app


def _require_setup() -> None:
    if APP is None:
        raise RuntimeError("FirewallHelper 未初始化，请先调用 setup(app, base_dir)")


def _run_command(args: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return False, "command not found"
    except Exception as exc:
        return False, str(exc)

    if result.returncode == 0:
        return True, (result.stdout or "").strip()

    detail = (result.stderr or result.stdout or "").strip()
    return False, detail or f"exit code {result.returncode}"


def _persist_iptables_rules() -> tuple[bool, str]:
    if shutil.which("netfilter-persistent"):
        ok, msg = _run_command(["netfilter-persistent", "save"])
        if ok:
            return True, "iptables 规则已持久化(netfilter-persistent)"

    ok_service, msg_service = _run_command(["service", "iptables", "save"])
    if ok_service:
        return True, "iptables 规则已持久化(service iptables save)"

    if shutil.which("iptables-save"):
        save_targets = [
            Path("/etc/iptables/rules.v4"),
            Path("/etc/sysconfig/iptables"),
            Path("/etc/iptables/iptables.rules"),
        ]
        for target in save_targets:
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("w", encoding="utf-8") as file:
                    result = subprocess.run(["iptables-save"], stdout=file, stderr=subprocess.PIPE, text=True, check=False)
                if result.returncode == 0:
                    return True, f"iptables 规则已保存到 {target}"
            except Exception:
                continue

    return False, "iptables 持久化失败：未检测到可用持久化工具。"


def _detect_firewall_type() -> str:
    if os.name == "nt":
        return "Windows 防火墙"
    if shutil.which("ufw"):
        return "UFW"
    if shutil.which("firewall-cmd"):
        return "firewalld"
    if shutil.which("iptables"):
        return "iptables"
    return "未知"


def _collect_listening_bindings() -> dict[str, set[str]]:
    bindings: dict[str, set[str]] = {}

    scans = [
        ("tcp", ["ss", "-lnt"]),
        ("udp", ["ss", "-lnu"]),
    ]

    for protocol, command in scans:
        ok, output = _run_command(command)
        if not ok:
            continue

        for line in output.splitlines():
            line = line.strip()
            if not line or line.lower().startswith("state"):
                continue

            cols = re.split(r"\s+", line)
            if len(cols) < 4:
                continue
            local = cols[3]

            if local.startswith("[") and "]:" in local:
                ip, port = local.rsplit(":", 1)
                ip = ip.strip("[]")
            elif ":" in local:
                ip, port = local.rsplit(":", 1)
            else:
                continue

            port = port.strip()
            if not port.isdigit():
                continue

            ip = ip.strip()
            if ip in ("*", "::"):
                ip = "0.0.0.0/::"

            key = f"{protocol}:{port}"
            bindings.setdefault(key, set()).add(ip)

    return bindings


def _collect_port_processes() -> dict[str, set[str]]:
    processes: dict[str, set[str]] = {}
    scans = [
        ("tcp", ["ss", "-lntp"]),
        ("udp", ["ss", "-lnup"]),
    ]

    for protocol, command in scans:
        ok, output = _run_command(command)
        if not ok:
            continue

        for line in output.splitlines():
            line = line.strip()
            if not line or line.lower().startswith("state"):
                continue

            cols = re.split(r"\s+", line)
            if len(cols) < 6:
                continue
            local = cols[3]
            process_col = cols[-1]

            if local.startswith("[") and "]:" in local:
                _, port = local.rsplit(":", 1)
            elif ":" in local:
                _, port = local.rsplit(":", 1)
            else:
                continue

            if not port.isdigit():
                continue

            names = re.findall(r'"([^"]+)"', process_col)
            if names:
                key = f"{protocol}:{port}"
                processes.setdefault(key, set()).update(names)

    return processes


def _collect_listening_rows() -> list[dict]:
    rows = []
    process_map = _collect_port_processes()

    scans = [
        ("tcp", ["ss", "-lnt"]),
        ("udp", ["ss", "-lnu"]),
    ]

    seen = set()
    for protocol, command in scans:
        ok, output = _run_command(command)
        if not ok:
            continue

        for line in output.splitlines():
            line = line.strip()
            if not line or line.lower().startswith("state"):
                continue

            cols = re.split(r"\s+", line)
            if len(cols) < 4:
                continue
            local = cols[3]

            if local.startswith("[") and "]:" in local:
                bind_ip, port = local.rsplit(":", 1)
                bind_ip = bind_ip.strip("[]")
            elif ":" in local:
                bind_ip, port = local.rsplit(":", 1)
            else:
                continue

            if not port.isdigit():
                continue

            bind_ip = bind_ip.strip()
            if bind_ip in ("*", "::"):
                bind_ip = "0.0.0.0/::"

            key = (protocol, port, bind_ip)
            if key in seen:
                continue
            seen.add(key)

            process_names = sorted(process_map.get(f"{protocol}:{port}", []))
            rows.append(
                {
                    "port": port,
                    "protocol": protocol,
                    "bind_ip": bind_ip,
                    "process_names": process_names if process_names else ["未知"],
                }
            )

    rows.sort(key=lambda item: (int(item["port"]), item["protocol"]))
    return rows


def _collect_open_ports_and_status(firewall_type: str) -> tuple[list[dict], str, str | None]:
    if os.name == "nt":
        return [], "未知", "当前为 Windows 环境，暂未实现防火墙规则解析。"

    if firewall_type == "UFW":
        ok, out = _run_command(["ufw", "status"])
        if ok:
            lines = out.splitlines()
            status = "未知"
            if lines and lines[0].lower().startswith("status"):
                status = "已启用" if "active" in lines[0].lower() else "未启用"

            ports = []
            for line in lines:
                if re.search(r"\bALLOW\b", line):
                    target = re.split(r"\s{2,}", line.strip())[0]
                    match = re.search(r"(\d+)/(tcp|udp)", target, re.IGNORECASE)
                    if match:
                        ports.append({"port": match.group(1), "protocol": match.group(2).lower()})
            note = None if status == "已启用" else "UFW 当前未启用。"
            unique_ports = {(item["port"], item["protocol"]) for item in ports}
            result = [{"port": p, "protocol": proto} for p, proto in sorted(unique_ports, key=lambda x: (int(x[0]), x[1]))]
            return result, status, note
        return [], "未知", f"读取 UFW 状态失败：{out}"

    if firewall_type == "firewalld":
        ok_state, state = _run_command(["firewall-cmd", "--state"])
        if ok_state and state.strip() == "running":
            ok_ports, ports_text = _run_command(["firewall-cmd", "--list-ports"])
            if ok_ports:
                ports = []
                for item in ports_text.split():
                    match = re.match(r"(\d+)/(tcp|udp)", item, re.IGNORECASE)
                    if match:
                        ports.append({"port": match.group(1), "protocol": match.group(2).lower()})
                unique_ports = {(item["port"], item["protocol"]) for item in ports}
                result = [{"port": p, "protocol": proto} for p, proto in sorted(unique_ports, key=lambda x: (int(x[0]), x[1]))]
                return result, "已启用", None
            return [], "已启用", "无法读取 firewalld 端口规则。"
        return [], "未启用", "firewalld 未运行。"

    if firewall_type == "iptables":
        ok, out = _run_command(["iptables", "-S", "INPUT"])
        if ok:
            ports = []
            for line in out.splitlines():
                if " --dport " in line and " -j ACCEPT" in line:
                    match = re.search(r"--dport\s+(\d+)", line)
                    if match:
                        proto_match = re.search(r"-p\s+(tcp|udp)", line)
                        protocol = proto_match.group(1).lower() if proto_match else "tcp"
                        ports.append({"port": match.group(1), "protocol": protocol})
            unique_ports = {(item["port"], item["protocol"]) for item in ports}
            result = [{"port": p, "protocol": proto} for p, proto in sorted(unique_ports, key=lambda x: (int(x[0]), x[1]))]
            return result, "已加载", None
        return [], "未知", f"读取 iptables 失败：{out}"

    return [], "未知", "未检测到可识别的防火墙工具（ufw/firewalld/iptables）。"


def _enable_firewall(firewall_type: str) -> tuple[bool, str]:
    if firewall_type == "UFW":
        ok, out = _run_command(["ufw", "--force", "enable"])
        return (True, "UFW 已启用。") if ok else (False, f"启用 UFW 失败：{out}")

    if firewall_type == "firewalld":
        ok_enable, out_enable = _run_command(["systemctl", "enable", "--now", "firewalld"])
        if ok_enable:
            return True, "firewalld 已启用并启动。"
        ok_start, out_start = _run_command(["service", "firewalld", "start"])
        if ok_start:
            return True, "firewalld 已启动。"
        return False, f"启用 firewalld 失败：{out_enable or out_start}"

    if firewall_type == "iptables":
        return True, "iptables 无独立启用步骤，规则即时生效。"

    return False, "未检测到可启用的防火墙工具。"


def _open_firewall_port(firewall_type: str, port: int, protocol: str) -> tuple[bool, str]:
    if port < 1 or port > 65535:
        return False, "端口范围必须在 1-65535。"
    if protocol not in {"tcp", "udp"}:
        return False, "端口类型仅支持 tcp 或 udp。"

    if firewall_type == "UFW":
        ok, out = _run_command(["ufw", "allow", f"{port}/{protocol}"])
        return (True, f"UFW 已开放 {port}/{protocol}。") if ok else (False, f"UFW 开放端口失败：{out}")

    if firewall_type == "firewalld":
        ok_add, out_add = _run_command(["firewall-cmd", "--permanent", f"--add-port={port}/{protocol}"])
        if not ok_add:
            return False, f"firewalld 添加端口失败：{out_add}"
        ok_reload, out_reload = _run_command(["firewall-cmd", "--reload"])
        if not ok_reload:
            return False, f"firewalld 重载失败：{out_reload}"
        return True, f"firewalld 已开放 {port}/{protocol}。"

    if firewall_type == "iptables":
        ok_check, _ = _run_command(["iptables", "-C", "INPUT", "-p", protocol, "--dport", str(port), "-j", "ACCEPT"])
        if not ok_check:
            ok_add, out_add = _run_command(["iptables", "-I", "INPUT", "-p", protocol, "--dport", str(port), "-j", "ACCEPT"])
            if not ok_add:
                return False, f"iptables 开放端口失败：{out_add}"

        ok_persist, persist_msg = _persist_iptables_rules()
        if not ok_persist:
            return False, persist_msg
        return True, f"iptables 已开放 {port}/{protocol}。{persist_msg}"

    return False, "未检测到可用防火墙工具。"


def register_routes(require_login) -> None:
    _require_setup()

    @APP.route("/firewall", methods=["GET", "POST"])
    def firewall():
        token = request.args.get("token") or request.form.get("token")
        username = require_login()
        if not username:
            return redirect(url_for("login"))

        message = None
        firewall_type = _detect_firewall_type()

        if request.method == "POST":
            action = request.form.get("action", "")
            if action == "enable_firewall":
                ok, msg = _enable_firewall(firewall_type)
                message = msg if ok else f"操作失败：{msg}"
            elif action == "open_port":
                port_text = (request.form.get("port") or "").strip()
                protocol = (request.form.get("protocol") or "tcp").strip().lower()
                if not port_text.isdigit():
                    message = "端口必须是数字。"
                else:
                    ok, msg = _open_firewall_port(firewall_type, int(port_text), protocol)
                    message = msg if ok else f"操作失败：{msg}"

        open_ports, firewall_status, note = _collect_open_ports_and_status(firewall_type)
        bindings = _collect_listening_bindings()
        process_map = _collect_port_processes()
        listening_rows = _collect_listening_rows()

        port_rows = []
        for item in open_ports:
            port = item["port"]
            protocol = item["protocol"]
            key = f"{protocol}:{port}"
            bind_ips = sorted(bindings.get(key, []))
            process_names = sorted(process_map.get(key, []))
            port_rows.append(
                {
                    "port": port,
                    "protocol": protocol,
                    "bind_ips": bind_ips if bind_ips else ["未监听"],
                    "process_names": process_names if process_names else ["未知"],
                }
            )

        return render_template(
            "firewall.html",
            username=username,
            token=token,
            message=message,
            firewall_type=firewall_type,
            firewall_status=firewall_status,
            port_rows=port_rows,
            listening_rows=listening_rows,
            note=note,
        )
