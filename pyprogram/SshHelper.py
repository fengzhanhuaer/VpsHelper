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
        raise RuntimeError("SshHelper 未初始化，请先调用 setup(app, base_dir)")


def _set_config_option(content: str, key: str, value: str) -> str:
    pattern = re.compile(rf"(?im)^\s*#?\s*{re.escape(key)}\s+.*$")
    replacement = f"{key} {value}"
    if pattern.search(content):
        return pattern.sub(replacement, content)

    if content and not content.endswith("\n"):
        content += "\n"
    return content + replacement + "\n"


def _restart_ssh_service() -> tuple[bool, str]:
    commands = [
        ["systemctl", "restart", "sshd"],
        ["systemctl", "restart", "ssh"],
        ["service", "sshd", "restart"],
        ["service", "ssh", "restart"],
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

    return False, f"重启 SSH 服务失败：{last_error or '未找到可用的服务管理命令。'}"


def _test_sshd_config(config_path: Path) -> tuple[bool, str]:
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
        updated = _set_config_option(content, "Port", str(ssh_port))
        updated = _set_config_option(updated, "PasswordAuthentication", "yes" if allow_password_login else "no")
        updated = _set_config_option(updated, "PubkeyAuthentication", "yes" if allow_key_login else "no")

        backup_path = config_path.with_suffix(config_path.suffix + ".vpshelper.bak")
        shutil.copy2(config_path, backup_path)
        config_path.write_text(updated, encoding="utf-8")

        checked, check_message = _test_sshd_config(config_path)
        if not checked:
            shutil.copy2(backup_path, config_path)
            return False, f"{check_message}，已自动回滚配置。"

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
            return False, restart_message

        return True, "SSH 配置已应用到系统。"
    except PermissionError:
        return False, "权限不足，无法修改 SSH 配置。请使用 root 权限运行。"
    except Exception as exc:
        return False, f"应用 SSH 配置失败：{exc}"


def register_routes(require_login, get_db) -> None:
    _require_setup()

    @APP.route("/settings/ssh", methods=["GET", "POST"])
    def ssh_settings():
        token = request.args.get("token") or request.form.get("token")
        username = require_login()
        if not username:
            return redirect(url_for("login"))

        db = get_db()
        message = None

        if request.method == "POST":
            ssh_port = request.form.get("ssh_port", "").strip()
            ssh_public_key = request.form.get("ssh_public_key", "").strip()
            allow_password_login = request.form.get("allow_password_login") == "on"
            allow_key_login = request.form.get("allow_key_login") == "on"

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
            token=token,
            message=message,
            ssh_port=data.get("ssh_port") or "22",
            ssh_public_key=data.get("ssh_public_key") or "",
            allow_password_login=(data.get("ssh_allow_password_login", "1") == "1"),
            allow_key_login=(data.get("ssh_allow_key_login", "1") == "1"),
        )
