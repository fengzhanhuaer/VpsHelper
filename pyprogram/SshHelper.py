import os
import re
import socket
import shutil
import subprocess
import time
from pathlib import Path

from flask import redirect, render_template, request, url_for

APP = None


def setup(app, _base_dir: Path) -> None:
    global APP
    APP = app


def _require_setup() -> None:
    if APP is None:
        raise RuntimeError("SshHelper 未初始化，请先调用 setup(app, base_dir)")


def _set_config_option(content: str, key: str, value: str) -> str:
    pattern = re.compile(rf"(?im)^\s*#?\s*{re.escape(key)}\s+.*$")
    replacement = f"{key} {value}"
    if pattern.search(content):
        return pattern.sub(replacement, content)

    if content and not content.endswith("\n"):
        content += "\n"
    return content + replacement + "\n"


def _extract_ssh_port(content: str) -> int:
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.match(r"(?i)^Port\s+(\d+)$", stripped)
        if match:
            try:
                port = int(match.group(1))
                if 1 <= port <= 65535:
                    return port
            except ValueError:
                pass
    return 22


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


def _ensure_sshd_runtime_dir() -> tuple[bool, str]:
    runtime_dir = Path("/run/sshd")
    try:
        runtime_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(runtime_dir, 0o755)
        return True, "/run/sshd 已就绪"
    except PermissionError:
        return False, "权限不足，无法创建 /run/sshd"
    except Exception as exc:
        return False, f"创建 /run/sshd 失败：{exc}"


def _persist_iptables_rules() -> tuple[bool, str]:
    if shutil.which("netfilter-persistent"):
        ok_save, msg_save = _run_command(["netfilter-persistent", "save"])
        if ok_save:
            return True, "iptables 规则已通过 netfilter-persistent 持久化"

    ok_service, msg_service = _run_command(["service", "iptables", "save"])
    if ok_service:
        return True, "iptables 规则已通过 service iptables save 持久化"

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

    details = []
    if "msg_save" in locals() and msg_save:
        details.append(f"netfilter-persistent: {msg_save}")
    if msg_service:
        details.append(f"service iptables save: {msg_service}")
    if not details:
        details.append("未找到可用持久化方式")
    return False, "；".join(details)


def _detect_ssh_socket_unit() -> str | None:
    if not shutil.which("systemctl"):
        return None

    for unit in ("ssh.socket", "sshd.socket"):
        ok_cat, _ = _run_command(["systemctl", "cat", unit])
        if not ok_cat:
            continue

        ok_active, out_active = _run_command(["systemctl", "is-active", unit])
        ok_enabled, out_enabled = _run_command(["systemctl", "is-enabled", unit])

        is_active = ok_active and (out_active.strip() == "active")
        enabled_state = out_enabled.strip() if ok_enabled else ""
        is_enabled = enabled_state in {"enabled", "static", "indirect"}
        if is_active or is_enabled:
            return unit
    return None


def _set_ssh_socket_port(socket_unit: str, port: int) -> tuple[bool, str]:
    dropin_dir = Path(f"/etc/systemd/system/{socket_unit}.d")
    dropin_file = dropin_dir / "vpshelper.conf"

    content = "[Socket]\nListenStream=\nListenStream=0.0.0.0:{port}\nListenStream=[::]:{port}\nBindIPv6Only=both\n".format(port=port)
    try:
        dropin_dir.mkdir(parents=True, exist_ok=True)
        dropin_file.write_text(content, encoding="utf-8")
    except Exception as exc:
        return False, f"写入 {dropin_file} 失败：{exc}"

    ok_reload, msg_reload = _run_command(["systemctl", "daemon-reload"])
    if not ok_reload:
        return False, f"systemd 重载失败：{msg_reload}"

    ok_restart, msg_restart = _run_command(["systemctl", "restart", socket_unit])
    if not ok_restart:
        return False, f"重启 {socket_unit} 失败：{msg_restart}"

    if socket_unit == "ssh.socket":
        _run_command(["systemctl", "restart", "ssh"])
    elif socket_unit == "sshd.socket":
        _run_command(["systemctl", "restart", "sshd"])

    if not _is_port_listening_ipv4(port):
        return False, f"{socket_unit} 已重启，但未检测到 IPv4 监听 {port} 端口。"

    return True, f"已更新 {socket_unit} 监听端口为 {port}。"


def _is_port_listening_ipv4(port: int) -> bool:
    proc_path = Path("/proc/net/tcp")
    if not proc_path.exists():
        return False

    target_hex = f"{port:04X}"
    try:
        content = proc_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False

    for line in content.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[1]
        state = parts[3]
        if ":" not in local:
            continue
        local_ip_hex, local_port_hex = local.split(":", 1)
        if local_port_hex.upper() != target_hex:
            continue
        if state != "0A":
            continue
        if local_ip_hex.upper() == "00000000":
            return True
        return True

    return False


def _apply_firewall_port_change(new_port: int, old_port: int) -> tuple[bool, str]:
    notes = []

    if shutil.which("ufw"):
        ok_status, status_text = _run_command(["ufw", "status"])
        if ok_status and "inactive" not in (status_text or "").lower():
            ok_allow, msg_allow = _run_command(["ufw", "allow", f"{new_port}/tcp"])
            if not ok_allow:
                return False, f"UFW 放行新端口失败：{msg_allow}"
            notes.append(f"UFW 已放行 {new_port}/tcp")

            if old_port != new_port:
                ok_deny, msg_deny = _run_command(["ufw", "deny", f"{old_port}/tcp"])
                if not ok_deny:
                    return False, f"UFW 关闭旧端口失败：{msg_deny}"
                notes.append(f"UFW 已关闭 {old_port}/tcp")

            return True, "；".join(notes)

    if shutil.which("iptables"):
        ok_check_new, _ = _run_command(["iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(new_port), "-j", "ACCEPT"])
        if not ok_check_new:
            ok_add_new, msg_add_new = _run_command(["iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(new_port), "-j", "ACCEPT"])
            if not ok_add_new:
                return False, f"iptables 放行新端口失败：{msg_add_new}"
        notes.append(f"iptables 已放行 {new_port}/tcp")

        if old_port != new_port:
            while True:
                ok_has_old_accept, _ = _run_command(["iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(old_port), "-j", "ACCEPT"])
                if not ok_has_old_accept:
                    break
                ok_del_old_accept, msg_del_old_accept = _run_command(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(old_port), "-j", "ACCEPT"])
                if not ok_del_old_accept:
                    return False, f"iptables 删除旧端口放行规则失败：{msg_del_old_accept}"

            ok_has_old_drop, _ = _run_command(["iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(old_port), "-j", "DROP"])
            if not ok_has_old_drop:
                ok_add_old_drop, msg_add_old_drop = _run_command(["iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(old_port), "-j", "DROP"])
                if not ok_add_old_drop:
                    return False, f"iptables 关闭旧端口失败：{msg_add_old_drop}"
            notes.append(f"iptables 已关闭 {old_port}/tcp")

        ok_persist, persist_message = _persist_iptables_rules()
        if not ok_persist:
            return False, f"iptables 持久化失败：{persist_message}"
        notes.append(persist_message)

        return True, "；".join(notes)

    return False, "未检测到可用防火墙（ufw 或 iptables）。"


def _restart_ssh_service() -> tuple[bool, str]:
    ok_runtime, msg_runtime = _ensure_sshd_runtime_dir()
    if not ok_runtime:
        return False, msg_runtime

    commands = [
        ["systemctl", "restart", "sshd"],
        ["systemctl", "restart", "ssh"],
        ["systemctl", "start", "sshd"],
        ["systemctl", "start", "ssh"],
        ["service", "sshd", "restart"],
        ["service", "ssh", "restart"],
        ["service", "sshd", "start"],
        ["service", "ssh", "start"],
        ["rc-service", "sshd", "restart"],
        ["rc-service", "sshd", "start"],
        ["/etc/init.d/sshd", "restart"],
        ["/etc/init.d/sshd", "start"],
        ["/etc/init.d/ssh", "restart"],
        ["/etc/init.d/ssh", "start"],
    ]

    last_error = ""
    for cmd in commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            continue
        except Exception as exc:
            last_error = str(exc)
            continue

        if result.returncode == 0:
            return True, "已重启 SSH 服务。"

        detail = (result.stderr or result.stdout or "").strip()
        if detail:
            last_error = detail

    direct_commands = [
        ["sshd", "-f", "/etc/ssh/sshd_config"],
        ["/usr/sbin/sshd", "-f", "/etc/ssh/sshd_config"],
    ]
    for cmd in direct_commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            continue
        except Exception as exc:
            last_error = str(exc)
            continue

        if result.returncode == 0:
            return True, "已直接启动 sshd 进程。"

        detail = (result.stderr or result.stdout or "").strip()
        if detail:
            last_error = detail

    return False, f"重启 SSH 服务失败：{last_error or '未找到可用的服务管理命令。'}"


def _test_sshd_config(config_path: Path) -> tuple[bool, str]:
    ok_runtime, msg_runtime = _ensure_sshd_runtime_dir()
    if not ok_runtime:
        return False, msg_runtime

    commands = [
        ["sshd", "-t", "-f", str(config_path)],
        ["/usr/sbin/sshd", "-t", "-f", str(config_path)],
    ]

    last_error = ""
    for cmd in commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            continue
        except Exception as exc:
            last_error = str(exc)
            continue

        if result.returncode == 0:
            return True, "SSH 配置语法检查通过。"

        detail = (result.stderr or result.stdout or "").strip()
        if detail:
            last_error = detail

    return False, f"SSH 配置语法检查失败：{last_error or '未找到 sshd 命令。'}"


def _read_port_lines(config_path: Path) -> list[str]:
    lines = []
    if not config_path.exists():
        return lines

    try:
        content = config_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return lines

    for raw in content.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"(?i)^Port\s+\d+", stripped):
            lines.append(f"{config_path}: {stripped}")
    return lines


def _collect_port_sources(main_config: Path) -> list[str]:
    sources = []
    sources.extend(_read_port_lines(main_config))

    include_dir = Path("/etc/ssh/sshd_config.d")
    if include_dir.exists() and include_dir.is_dir():
        for conf in sorted(include_dir.glob("*.conf")):
            sources.extend(_read_port_lines(conf))
    return sources


def _get_effective_sshd_settings(config_path: Path) -> tuple[bool, dict[str, str], str]:
    ok_runtime, msg_runtime = _ensure_sshd_runtime_dir()
    if not ok_runtime:
        return False, {}, msg_runtime

    commands = [
        ["sshd", "-T", "-f", str(config_path)],
        ["/usr/sbin/sshd", "-T", "-f", str(config_path)],
    ]

    last_error = ""
    for cmd in commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            continue
        except Exception as exc:
            last_error = str(exc)
            continue

        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            if detail:
                last_error = detail
            continue

        settings = {}
        for line in (result.stdout or "").splitlines():
            if " " not in line:
                continue
            key, value = line.split(" ", 1)
            settings[key.strip().lower()] = value.strip()
        return True, settings, "ok"

    return False, {}, last_error or "未找到 sshd 命令。"


def _rollback_sshd_config(config_path: Path, backup_path: Path) -> tuple[bool, str]:
    if not backup_path.exists():
        return False, "未找到备份文件，无法回滚。"

    try:
        shutil.copy2(backup_path, config_path)
        return True, "已回滚到修改前配置。"
    except Exception as exc:
        return False, f"回滚失败：{exc}"


def _is_ssh_port_listening(port: int) -> tuple[bool, str]:
    def _check_by_socket() -> bool:
        for host in ("127.0.0.1", "::1"):
            try:
                with socket.create_connection((host, port), timeout=0.8):
                    return True
            except Exception:
                continue
        return False

    def _check_by_proc_net() -> bool:
        target_hex = f"{port:04X}"
        for proc_path in ("/proc/net/tcp", "/proc/net/tcp6"):
            if not Path(proc_path).exists():
                continue
            try:
                content = Path(proc_path).read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for line in content.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                local = parts[1]
                state = parts[3]
                if ":" not in local:
                    continue
                local_port = local.split(":")[-1].upper()
                if local_port == target_hex and state == "0A":
                    return True
        return False

    def _check_by_cmd() -> tuple[bool, str]:
        commands = [
            ["ss", "-lnt"],
            ["netstat", "-lnt"],
        ]

        target = f":{port}"
        last_error = ""
        for cmd in commands:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            except FileNotFoundError:
                continue
            except Exception as exc:
                last_error = str(exc)
                continue

            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "").strip()
                if detail:
                    last_error = detail
                continue

            output = result.stdout or ""
            for line in output.splitlines():
                if target in line:
                    return True, ""

        return False, last_error

    last_error = ""
    for _ in range(8):
        cmd_ok, cmd_error = _check_by_cmd()
        if cmd_ok or _check_by_proc_net() or _check_by_socket():
            return True, f"已监听端口 {port}。"
        if cmd_error:
            last_error = cmd_error
        time.sleep(1)

    return False, f"未检测到 SSH 监听端口 {port}。{(' ' + last_error) if last_error else ''}"


def _enable_and_start_fail2ban() -> tuple[bool, str]:
    if shutil.which("systemctl"):
        ok_enable, msg_enable = _run_command(["systemctl", "enable", "--now", "fail2ban"])
        if ok_enable:
            return True, "Fail2ban 已安装并启动。"
        return False, f"Fail2ban 安装后启动失败：{msg_enable}"

    ok_start, msg_start = _run_command(["service", "fail2ban", "start"])
    if ok_start:
        return True, "Fail2ban 已安装并启动。"
    return False, f"Fail2ban 安装后启动失败：{msg_start}"


def install_fail2ban() -> tuple[bool, str]:
    if os.name == "nt":
        return False, "当前系统是 Windows，无法安装 Linux Fail2ban。"

    if shutil.which("fail2ban-client"):
        ok_start, msg_start = _enable_and_start_fail2ban()
        if ok_start:
            return True, "Fail2ban 已安装。"
        return False, msg_start

    if shutil.which("apt-get"):
        ok_update, msg_update = _run_command(["apt-get", "update"])
        if not ok_update:
            return False, f"apt-get update 失败：{msg_update}"
        ok_install, msg_install = _run_command(["apt-get", "install", "-y", "fail2ban"])
        if not ok_install:
            return False, f"apt 安装失败：{msg_install}"
    elif shutil.which("dnf"):
        ok_install, msg_install = _run_command(["dnf", "install", "-y", "fail2ban"])
        if not ok_install:
            return False, f"dnf 安装失败：{msg_install}"
    elif shutil.which("yum"):
        ok_install, msg_install = _run_command(["yum", "install", "-y", "fail2ban"])
        if not ok_install:
            return False, f"yum 安装失败：{msg_install}"
    elif shutil.which("zypper"):
        ok_install, msg_install = _run_command(["zypper", "--non-interactive", "install", "fail2ban"])
        if not ok_install:
            return False, f"zypper 安装失败：{msg_install}"
    elif shutil.which("apk"):
        ok_install, msg_install = _run_command(["apk", "add", "fail2ban"])
        if not ok_install:
            return False, f"apk 安装失败：{msg_install}"
    else:
        return False, "未检测到支持的包管理器（apt/dnf/yum/zypper/apk）。"

    return _enable_and_start_fail2ban()


def diagnose_ssh_status(target_port: int | None = None) -> str:
    if os.name == "nt":
        return "当前系统是 Windows，无法诊断 Linux SSH 服务。"

    lines = []
    config_path = Path("/etc/ssh/sshd_config")
    lines.append("=== SSH 诊断结果 ===")
    lines.append(f"配置文件: {config_path}")
    lines.append(f"目标端口: {target_port if target_port else '未指定'}")
    lines.append(
        "服务管理器: "
        f"systemctl={'有' if shutil.which('systemctl') else '无'}, "
        f"service={'有' if shutil.which('service') else '无'}, "
        f"rc-service={'有' if shutil.which('rc-service') else '无'}"
    )
    lines.append(
        "sshd 二进制: "
        f"sshd={'有' if shutil.which('sshd') else '无'}, "
        f"/usr/sbin/sshd={'有' if Path('/usr/sbin/sshd').exists() else '无'}"
    )

    ok_runtime, runtime_message = _ensure_sshd_runtime_dir()
    lines.append(f"运行时目录: {runtime_message}")

    effective_ok, effective_settings, effective_message = _get_effective_sshd_settings(config_path)
    if effective_ok:
        lines.append(f"sshd -T 生效端口: {effective_settings.get('port', '未知')}")
        lines.append(f"PasswordAuthentication: {effective_settings.get('passwordauthentication', '未知')}")
        lines.append(f"PubkeyAuthentication: {effective_settings.get('pubkeyauthentication', '未知')}")
    else:
        lines.append(f"sshd -T 读取失败: {effective_message}")

    source_lines = _collect_port_sources(config_path)
    if source_lines:
        lines.append("Port 来源:")
        for item in source_lines:
            lines.append(f"- {item}")
    else:
        lines.append("Port 来源: 未发现显式 Port 行")

    for unit in ("ssh", "sshd", "ssh.socket", "sshd.socket"):
        ok_active, active_out = _run_command(["systemctl", "is-active", unit])
        state = active_out.strip() if ok_active else "inactive/not-found"
        lines.append(f"{unit} 状态: {state}")

    ok_listen, listen_out = _run_command(["ss", "-lnt"])
    if ok_listen:
        listen_lines = []
        for row in (listen_out or "").splitlines():
            if ":22" in row:
                listen_lines.append(row)
            if target_port and f":{target_port}" in row:
                listen_lines.append(row)
        lines.append("监听端口摘要:")
        if listen_lines:
            for row in listen_lines[:10]:
                lines.append(f"- {row}")
        else:
            lines.append("- 未在 ss -lnt 中发现 22 或目标端口")
    else:
        lines.append(f"监听检测失败(ss -lnt): {listen_out}")

    if shutil.which("ufw"):
        ok_ufw, ufw_out = _run_command(["ufw", "status"])
        if ok_ufw:
            lines.append("UFW 规则摘要:")
            for row in (ufw_out or "").splitlines()[:20]:
                lines.append(f"- {row}")
        else:
            lines.append(f"UFW 状态读取失败: {ufw_out}")

    if shutil.which("iptables"):
        ok_ip, ip_out = _run_command(["iptables", "-S", "INPUT"])
        if ok_ip:
            wanted = []
            for row in (ip_out or "").splitlines():
                if "--dport 22" in row:
                    wanted.append(row)
                if target_port and f"--dport {target_port}" in row:
                    wanted.append(row)
            lines.append("iptables INPUT 规则摘要:")
            if wanted:
                for row in wanted[:20]:
                    lines.append(f"- {row}")
            else:
                lines.append("- 未发现 22 或目标端口规则")
        else:
            lines.append(f"iptables 规则读取失败: {ip_out}")

    lines.append("提示: 如在云服务器上，请同时检查安全组/防火墙放行目标端口。")
    return "\n".join(lines)


def apply_ssh_system_settings(
    ssh_port: int,
    allow_password_login: bool,
    allow_key_login: bool,
    ssh_public_key: str,
) -> tuple[bool, str]:
    if os.name == "nt":
        return False, "当前系统是 Windows，无法自动修改 Linux SSH 服务配置。"

    config_path = Path("/etc/ssh/sshd_config")
    if not config_path.exists():
        return False, "未找到 /etc/ssh/sshd_config。"

    try:
        content = config_path.read_text(encoding="utf-8")
        old_port = _extract_ssh_port(content)
        socket_unit = _detect_ssh_socket_unit()
        updated = _set_config_option(content, "Port", str(ssh_port))
        updated = _set_config_option(updated, "PasswordAuthentication", "yes" if allow_password_login else "no")
        updated = _set_config_option(updated, "PubkeyAuthentication", "yes" if allow_key_login else "no")

        backup_path = config_path.with_suffix(config_path.suffix + ".vpshelper.bak")
        shutil.copy2(config_path, backup_path)
        config_path.write_text(updated, encoding="utf-8")

        checked, check_message = _test_sshd_config(config_path)
        if not checked:
            rolled_back, rollback_message = _rollback_sshd_config(config_path, backup_path)
            return False, f"{check_message}，{rollback_message if rolled_back else rollback_message}"

        effective_ok, effective_settings, effective_message = _get_effective_sshd_settings(config_path)
        if not effective_ok:
            rolled_back, rollback_message = _rollback_sshd_config(config_path, backup_path)
            return False, f"读取 SSH 生效配置失败：{effective_message}；{rollback_message}"

        effective_port_text = effective_settings.get("port", "")
        try:
            effective_port = int(effective_port_text)
        except ValueError:
            effective_port = 0

        if effective_port != ssh_port:
            sources = _collect_port_sources(config_path)
            source_text = "；".join(sources) if sources else "未发现显式 Port 配置行"
            rolled_back, rollback_message = _rollback_sshd_config(config_path, backup_path)
            return False, (
                f"sshd 生效端口为 {effective_port or '未知'}，不是目标端口 {ssh_port}，"
                f"可能被 Include 配置覆盖。端口来源：{source_text}；{rollback_message}"
            )

        socket_note = ""
        if socket_unit:
            ok_socket, msg_socket = _set_ssh_socket_port(socket_unit, ssh_port)
            if not ok_socket:
                socket_note = f"SSH socket 端口更新失败，已降级为服务模式继续：{msg_socket}"
                _run_command(["systemctl", "disable", "--now", socket_unit])
            else:
                socket_note = msg_socket

        if ssh_public_key.strip():
            ssh_dir = Path.home() / ".ssh"
            ssh_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(ssh_dir, 0o700)

            auth_file = ssh_dir / "authorized_keys"
            existing = auth_file.read_text(encoding="utf-8") if auth_file.exists() else ""
            key = ssh_public_key.strip()
            existing_lines = {line.strip() for line in existing.splitlines() if line.strip()}
            if key not in existing_lines:
                with auth_file.open("a", encoding="utf-8") as file:
                    if existing and not existing.endswith("\n"):
                        file.write("\n")
                    file.write(key + "\n")
            os.chmod(auth_file, 0o600)

        restarted, restart_message = _restart_ssh_service()
        if not restarted:
            rolled_back, rollback_message = _rollback_sshd_config(config_path, backup_path)
            if socket_unit:
                _set_ssh_socket_port(socket_unit, old_port)
            if rolled_back:
                _restart_ssh_service()
            return False, f"{restart_message}；{rollback_message}"

        listening, listening_message = _is_ssh_port_listening(ssh_port)
        if not listening:
            rolled_back, rollback_message = _rollback_sshd_config(config_path, backup_path)
            if socket_unit:
                _set_ssh_socket_port(socket_unit, old_port)
            if rolled_back:
                _restart_ssh_service()
            return False, f"{listening_message}；{rollback_message}"

        firewall_ok, firewall_message = _apply_firewall_port_change(ssh_port, old_port)
        if not firewall_ok:
            return False, f"SSH 已监听新端口，但防火墙处理失败：{firewall_message}"

        extra = f"；{socket_note}" if socket_note else ""
        return True, f"SSH 配置已应用到系统。{listening_message}{extra}；{firewall_message}"
    except PermissionError:
        return False, "权限不足，无法修改 SSH 配置。请使用 root 权限运行。"
    except Exception as exc:
        return False, f"应用 SSH 配置失败：{exc}"


def register_routes(require_login, get_db) -> None:
    _require_setup()

    @APP.route("/settings/ssh", methods=["GET", "POST"])
    def ssh_settings():
        username = require_login()
        if not username:
            return redirect(url_for("login"))

        db = get_db()
        message = None

        if request.method == "POST":
            action = request.form.get("action", "save")
            if action == "install_fail2ban":
                installed, install_message = install_fail2ban()
                message = install_message if installed else f"安装失败：{install_message}"

            if action == "diagnose_ssh":
                port_text = request.form.get("ssh_port", "").strip()
                diag_port = int(port_text) if port_text.isdigit() else None
                message = diagnose_ssh_status(diag_port)

            ssh_port = request.form.get("ssh_port", "").strip()
            ssh_public_key = request.form.get("ssh_public_key", "").strip()
            allow_password_login = request.form.get("allow_password_login") == "on"
            allow_key_login = request.form.get("allow_key_login") == "on"

            if action not in {"install_fail2ban", "diagnose_ssh"}:
                if not ssh_port.isdigit():
                    message = "SSH 端口必须是数字。"
                else:
                    port = int(ssh_port)
                    if port < 1 or port > 65535:
                        message = "SSH 端口范围必须在 1-65535。"
                    else:
                        applied, apply_message = apply_ssh_system_settings(
                            ssh_port=port,
                            allow_password_login=allow_password_login,
                            allow_key_login=allow_key_login,
                            ssh_public_key=ssh_public_key,
                        )

                        db.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('ssh_port', ?)", (str(port),))
                        db.execute(
                            "INSERT OR REPLACE INTO app_settings (key, value) VALUES ('ssh_allow_password_login', ?)",
                            ("1" if allow_password_login else "0",),
                        )
                        db.execute(
                            "INSERT OR REPLACE INTO app_settings (key, value) VALUES ('ssh_allow_key_login', ?)",
                            ("1" if allow_key_login else "0",),
                        )
                        db.execute(
                            "INSERT OR REPLACE INTO app_settings (key, value) VALUES ('ssh_public_key', ?)",
                            (ssh_public_key,),
                        )
                        db.commit()

                        if applied:
                            message = "SSH 设置已保存，并已自动应用到系统。"
                        else:
                            message = f"SSH 设置已保存，但系统应用失败：{apply_message}"

        rows = db.execute(
            "SELECT key, value FROM app_settings WHERE key IN ('ssh_port', 'ssh_allow_password_login', 'ssh_allow_key_login', 'ssh_public_key')"
        ).fetchall()
        data = {row["key"]: row["value"] for row in rows}

        return render_template(
            "ssh_settings.html",
            username=username,
            message=message,
            ssh_port=data.get("ssh_port") or "22",
            ssh_public_key=data.get("ssh_public_key") or "",
            allow_password_login=(data.get("ssh_allow_password_login", "1") == "1"),
            allow_key_login=(data.get("ssh_allow_key_login", "1") == "1"),
        )
