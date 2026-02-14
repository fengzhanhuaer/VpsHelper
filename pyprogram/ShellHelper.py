import json
import re
import subprocess
from datetime import datetime
from pathlib import Path

from flask import jsonify, redirect, render_template, request, session, url_for

from pyprogram import TimeHelper

APP = None
USERDATA_DIR: Path | None = None
HISTORY_LIMIT = 2048


def setup(app, _base_dir: Path) -> None:
    global APP, USERDATA_DIR
    APP = app
    USERDATA_DIR = _base_dir / "userdata"
    USERDATA_DIR.mkdir(parents=True, exist_ok=True)


def _require_setup() -> None:
    if APP is None or USERDATA_DIR is None:
        raise RuntimeError("ShellHelper 未初始化，请先调用 setup(app, base_dir)")


def _ensure_shell_tables(db) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS shell_shortcuts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            name TEXT NOT NULL,
            command TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    db.commit()


def _history_file_path(owner: str) -> Path:
    safe_owner = re.sub(r"[^a-zA-Z0-9_.-]", "_", owner)
    return USERDATA_DIR / f"shell_history_{safe_owner}.json"


def _load_history(owner: str) -> list[str]:
    path = _history_file_path(owner)
    if not path.exists():
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return [str(item) for item in data][-HISTORY_LIMIT:]
    except Exception:
        pass
    return []


def _save_history(owner: str, commands: list[str]) -> None:
    path = _history_file_path(owner)
    path.write_text(json.dumps(commands[-HISTORY_LIMIT:], ensure_ascii=False), encoding="utf-8")


def _append_history(owner: str, command: str) -> None:
    history = _load_history(owner)
    history.append(command)
    _save_history(owner, history)


def register_routes(require_login, get_db) -> None:
    _require_setup()

    @APP.route("/shell")
    def shell_console():
        username = require_login()
        if not username:
            return redirect(url_for("login"))

        cwd = session.get("shell_cwd") or str(Path.home())
        if not Path(cwd).exists():
            cwd = str(Path.home())
            session["shell_cwd"] = cwd

        db = get_db()
        _ensure_shell_tables(db)

        history_commands = _load_history(username)

        shortcut_rows = db.execute(
            "SELECT id, name, command FROM shell_shortcuts WHERE owner = ? ORDER BY id ASC",
            (username,),
        ).fetchall()
        shortcuts = [
            {"id": row["id"], "name": row["name"], "command": row["command"]}
            for row in shortcut_rows
        ]

        return render_template(
            "shell_console.html",
            username=username,
            cwd=cwd,
            history_commands=history_commands,
            shortcuts=shortcuts,
        )

    @APP.route("/shell/shortcuts/add", methods=["POST"])
    def shell_shortcuts_add():
        username = require_login()
        if not username:
            return jsonify({"ok": False, "message": "未登录或会话已过期。"}), 401

        name = (request.form.get("name") or "").strip()
        command = (request.form.get("command") or "").strip()
        if not name or not command:
            return jsonify({"ok": False, "message": "名称和命令不能为空。"}), 400

        db = get_db()
        _ensure_shell_tables(db)
        db.execute(
            "INSERT INTO shell_shortcuts (owner, name, command, created_at) VALUES (?, ?, ?, ?)",
            (username, name, command, TimeHelper.now_iso()),
        )
        db.commit()

        row = db.execute("SELECT last_insert_rowid() AS id").fetchone()
        return jsonify({"ok": True, "item": {"id": row["id"], "name": name, "command": command}})

    @APP.route("/shell/shortcuts/delete/<int:shortcut_id>", methods=["POST"])
    def shell_shortcuts_delete(shortcut_id: int):
        username = require_login()
        if not username:
            return jsonify({"ok": False, "message": "未登录或会话已过期。"}), 401

        db = get_db()
        _ensure_shell_tables(db)
        db.execute("DELETE FROM shell_shortcuts WHERE id = ? AND owner = ?", (shortcut_id, username))
        db.commit()
        return jsonify({"ok": True})

    @APP.route("/shell/shortcuts/clear", methods=["POST"])
    def shell_shortcuts_clear():
        username = require_login()
        if not username:
            return jsonify({"ok": False, "message": "未登录或会话已过期。"}), 401

        db = get_db()
        _ensure_shell_tables(db)
        db.execute("DELETE FROM shell_shortcuts WHERE owner = ?", (username,))
        db.commit()
        return jsonify({"ok": True})

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

        _append_history(username, command)

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
