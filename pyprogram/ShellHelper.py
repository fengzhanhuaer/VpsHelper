import subprocess
from pathlib import Path

from flask import jsonify, redirect, render_template, request, session, url_for

APP = None


def setup(app, _base_dir: Path) -> None:
    global APP
    APP = app


def _require_setup() -> None:
    if APP is None:
        raise RuntimeError("ShellHelper 未初始化，请先调用 setup(app, base_dir)")


def register_routes(require_login) -> None:
    _require_setup()

    @APP.route("/shell")
    def shell_console():
        token = request.args.get("token")
        username = require_login()
        if not username:
            return redirect(url_for("login"))

        cwd = session.get("shell_cwd") or str(Path.home())
        if not Path(cwd).exists():
            cwd = str(Path.home())
            session["shell_cwd"] = cwd

        return render_template("shell_console.html", username=username, token=token, cwd=cwd)

    @APP.route("/shell/exec", methods=["POST"])
    def shell_exec():
        username = require_login()
        if not username:
            return jsonify({"ok": False, "output": "未登录或会话已过期。", "cwd": ""}), 401

        command = (request.form.get("command") or "").strip()
        if not command:
            return jsonify({"ok": False, "output": "命令不能为空。", "cwd": session.get("shell_cwd") or str(Path.home())}), 400

        if any(x in command for x in ["reboot", "shutdown", "poweroff", "halt", "init 0", "init 6"]):
            return jsonify({"ok": False, "output": "该命令已禁用，请在系统控制台执行。", "cwd": session.get("shell_cwd") or str(Path.home())}), 400

        cwd = session.get("shell_cwd") or str(Path.home())
        current_path = Path(cwd)
        if not current_path.exists():
            current_path = Path.home()

        if command == "cd" or command.startswith("cd "):
            target = command[2:].strip() if command.startswith("cd ") else "~"
            if not target:
                target = "~"
            target_path = Path(target).expanduser()
            if not target_path.is_absolute():
                target_path = (current_path / target_path).resolve()
            if not target_path.exists() or not target_path.is_dir():
                return jsonify({"ok": False, "output": f"目录不存在：{target_path}", "cwd": str(current_path)}), 400
            session["shell_cwd"] = str(target_path)
            return jsonify({"ok": True, "output": str(target_path), "cwd": str(target_path)})

        try:
            result = subprocess.run(
                command,
                shell=True,
                cwd=str(current_path),
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            output = (result.stdout or "") + (result.stderr or "")
            output = output.strip() or "(无输出)"
            ok = result.returncode == 0
            session["shell_cwd"] = str(current_path)
            return jsonify({"ok": ok, "output": output, "cwd": str(current_path)})
        except subprocess.TimeoutExpired:
            return jsonify({"ok": False, "output": "命令执行超时（30秒）。", "cwd": str(current_path)}), 408
        except Exception as exc:
            return jsonify({"ok": False, "output": f"执行失败：{exc}", "cwd": str(current_path)}), 500
