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


def _collect_listening_bindings() -> dict[str, set[str]]:
    bindings: dict[str, set[str]] = {}

    ok, output = _run_command(["ss", "-lnt"])
    if not ok:
        return bindings

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

        bindings.setdefault(port, set()).add(ip)

    return bindings


def _collect_open_ports_and_type() -> tuple[str, list[str], str | None]:
    if os.name == "nt":
        return "Windows 防火墙", [], "当前为 Windows 环境，暂未实现防火墙规则解析。"

    if shutil.which("ufw"):
        ok, out = _run_command(["ufw", "status"])
        if ok:
            lines = out.splitlines()
            if lines and "inactive" in lines[0].lower():
                return "UFW", [], "UFW 当前未启用。"

            ports = []
            for line in lines:
                if re.search(r"\bALLOW\b", line):
                    target = re.split(r"\s{2,}", line.strip())[0]
                    match = re.search(r"(\d+)", target)
                    if match:
                        ports.append(match.group(1))
            return "UFW", sorted(set(ports), key=int), None

    if shutil.which("firewall-cmd"):
        ok_state, state = _run_command(["firewall-cmd", "--state"])
        if ok_state and state.strip() == "running":
            ok_ports, ports_text = _run_command(["firewall-cmd", "--list-ports"])
            if ok_ports:
                ports = []
                for item in ports_text.split():
                    if "/" in item:
                        p = item.split("/", 1)[0]
                        if p.isdigit():
                            ports.append(p)
                return "firewalld", sorted(set(ports), key=int), None
            return "firewalld", [], "无法读取 firewalld 端口规则。"

    if shutil.which("iptables"):
        ok, out = _run_command(["iptables", "-S", "INPUT"])
        if ok:
            ports = []
            for line in out.splitlines():
                if " --dport " in line and " -j ACCEPT" in line:
                    match = re.search(r"--dport\s+(\d+)", line)
                    if match:
                        ports.append(match.group(1))
            return "iptables", sorted(set(ports), key=int), None

    return "未知", [], "未检测到可识别的防火墙工具（ufw/firewalld/iptables）。"


def register_routes(require_login) -> None:
    _require_setup()

    @APP.route("/firewall")
    def firewall():
        token = request.args.get("token")
        username = require_login()
        if not username:
            return redirect(url_for("login"))

        firewall_type, open_ports, note = _collect_open_ports_and_type()
        bindings = _collect_listening_bindings()

        port_rows = []
        for port in open_ports:
            bind_ips = sorted(bindings.get(port, []))
            port_rows.append(
                {
                    "port": port,
                    "bind_ips": bind_ips if bind_ips else ["未监听"],
                }
            )

        return render_template(
            "firewall.html",
            username=username,
            token=token,
            firewall_type=firewall_type,
            port_rows=port_rows,
            note=note,
        )
