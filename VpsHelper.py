import os
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from secrets import token_urlsafe
from flask import Flask, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from pyprogram import TgHelper

BASE_DIR = Path(__file__).resolve().parent
USERDATA_DIR = BASE_DIR / "userdata"
USERDATA_DIR.mkdir(parents=True, exist_ok=True)
MAIN_DB_PATH = USERDATA_DIR / "VpsHelper.db"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-me")
app.config["APP_NAME"] = "VpsHelper"
TgHelper.setup(app, BASE_DIR)

SCHEDULER = BackgroundScheduler(timezone="Asia/Shanghai")


def run_git_command(args: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return False, "未检测到 git 命令，请先安装 Git。"
    except Exception as exc:
        return False, f"执行 Git 命令失败：{exc}"

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        return False, detail or "Git 命令执行失败。"

    return True, (result.stdout or "").strip()


def get_update_status() -> dict:
    status = {
        "repo_ok": False,
        "branch": "-",
        "current_version": "-",
        "current_commit": "-",
        "latest_version": "-",
        "latest_commit": "-",
        "behind_count": "-",
        "remote": "origin",
        "note": "",
    }

    ok, out = run_git_command(["rev-parse", "--is-inside-work-tree"])
    if not ok or out.lower() != "true":
        status["note"] = "当前目录不是 Git 仓库。"
        return status
    status["repo_ok"] = True

    ok_branch, branch = run_git_command(["rev-parse", "--abbrev-ref", "HEAD"])
    if ok_branch and branch:
        status["branch"] = branch

    ok_cur_ver, cur_ver = run_git_command(["describe", "--tags", "--always"])
    if ok_cur_ver and cur_ver:
        status["current_version"] = cur_ver

    ok_cur_sha, cur_sha = run_git_command(["rev-parse", "HEAD"])
    if ok_cur_sha and cur_sha:
        status["current_commit"] = cur_sha[:7]

    ok_fetch, fetch_msg = run_git_command(["fetch", "origin"])
    if not ok_fetch:
        status["note"] = f"获取远端信息失败：{fetch_msg}"
        return status

    branch = status["branch"]
    if branch and branch != "-":
        ok_latest_sha, latest_sha = run_git_command(["rev-parse", f"origin/{branch}"])
        if ok_latest_sha and latest_sha:
            status["latest_commit"] = latest_sha[:7]
            ok_latest_ver, latest_ver = run_git_command(["describe", "--tags", "--always", latest_sha.strip()])
            status["latest_version"] = latest_ver if ok_latest_ver and latest_ver else latest_sha[:7]
            ok_behind, behind = run_git_command(["rev-list", "--count", f"HEAD..origin/{branch}"])
            if ok_behind and behind.isdigit():
                status["behind_count"] = behind
            return status

    ok_remote_head, remote_head = run_git_command(["ls-remote", "origin", "HEAD"])
    if ok_remote_head and remote_head:
        remote_sha = remote_head.split()[0]
        status["latest_commit"] = remote_sha[:7]
        ok_latest_ver, latest_ver = run_git_command(["describe", "--tags", "--always", remote_sha])
        status["latest_version"] = latest_ver if ok_latest_ver and latest_ver else remote_sha[:7]

    return status


def restart_current_process_delayed(delay_seconds: float = 1.0) -> None:
    def _restart():
        time.sleep(delay_seconds)
        os.execv(sys.executable, [sys.executable, *sys.argv])

    threading.Thread(target=_restart, daemon=True).start()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(MAIN_DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()
    tg_db = g.pop("tg_db", None)
    if tg_db is not None:
        tg_db.close()


def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    db.commit()
    TgHelper.init_tg_db()


def has_users() -> bool:
    db = get_db()
    cur = db.execute("SELECT COUNT(1) AS cnt FROM users")
    row = cur.fetchone()
    return row["cnt"] > 0


def create_session_token(username: str) -> str:
    token = token_urlsafe(32)
    db = get_db()
    db.execute(
        "INSERT INTO sessions (token, username, created_at) VALUES (?, ?, ?)",
        (token, username, datetime.utcnow().isoformat()),
    )
    db.commit()
    return token


def get_username_by_token(token: str) -> str | None:
    db = get_db()
    cur = db.execute("SELECT username FROM sessions WHERE token = ?", (token,))
    row = cur.fetchone()
    return row["username"] if row else None


def delete_session_token(token: str) -> None:
    db = get_db()
    db.execute("DELETE FROM sessions WHERE token = ?", (token,))
    db.commit()


def require_login():
    if "user" in session:
        return session["user"]
    token = request.args.get("token") or request.form.get("token")
    if token:
        username = get_username_by_token(token)
        if username:
            session["user"] = username
            return username
    return None


def configure_scheduler_jobs():
    TgHelper.configure_scheduler_jobs(SCHEDULER)


TgHelper.register_routes(require_login, configure_scheduler_jobs)


@app.before_request
def ensure_db_initialized():
    init_db()
    TgHelper.load_api_config()


@app.context_processor
def inject_app_name():
    return {"app_name": app.config.get("APP_NAME", "VpsHelper")}


@app.route("/")
def index():
    if "user" in session:
        return redirect(url_for("home"))
    if not has_users():
        return redirect(url_for("register"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if has_users() and "user" in session:
        return redirect(url_for("home"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        confirm = request.form.get("confirm", "").strip()

        if not username or not password:
            error = "用户名和密码不能为空。"
        elif password != confirm:
            error = "两次输入的密码不一致。"
        else:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
                session["user"] = username
                token = create_session_token(username)
                return redirect(url_for("home", token=token))
            except sqlite3.IntegrityError:
                error = "用户名已存在。"

    return render_template("register.html", error=error, has_users=has_users())


@app.route("/login", methods=["GET", "POST"])
def login():
    if not has_users():
        return redirect(url_for("register"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        db = get_db()
        cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["user"] = username
            token = create_session_token(username)
            return redirect(url_for("home", token=token))
        error = "用户名或密码错误。"

    return render_template("login.html", error=error)


@app.route("/home")
def home():
    token = request.args.get("token")
    username = require_login()
    if not username:
        return redirect(url_for("login"))
    return render_template("home.html", username=username, token=token)


@app.route("/system/update", methods=["GET", "POST"])
def system_update():
    token = request.args.get("token") or request.form.get("token")
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    message = None
    if request.method == "POST":
        action = request.form.get("action", "check")
        if action == "update":
            ok_branch, branch = run_git_command(["rev-parse", "--abbrev-ref", "HEAD"])
            if not ok_branch or not branch:
                message = f"更新失败：{branch or '无法识别当前分支。'}"
            else:
                ok_pull, pull_out = run_git_command(["pull", "--ff-only", "origin", branch])
                message = f"更新成功：{pull_out}" if ok_pull else f"更新失败：{pull_out}"
        elif action == "restart":
            message = "服务将在 1 秒后自动重启，请稍后刷新页面。"
            restart_current_process_delayed(1.0)
        else:
            message = "已刷新最新版本信息。"

    status = get_update_status()
    return render_template(
        "update_manager.html",
        token=token,
        username=username,
        message=message,
        status=status,
    )


@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    token = request.args.get("token") or request.form.get("token")
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    message = None
    if request.method == "POST":
        old_password = request.form.get("old_password", "").strip()
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if not old_password or not new_password or not confirm_password:
            message = "请完整填写旧密码、新密码和确认密码。"
        elif new_password != confirm_password:
            message = "两次输入的新密码不一致。"
        else:
            db = get_db()
            user = db.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()
            if not user or not check_password_hash(user["password_hash"], old_password):
                message = "旧密码错误。"
            else:
                db.execute(
                    "UPDATE users SET password_hash = ? WHERE username = ?",
                    (generate_password_hash(new_password), username),
                )
                db.commit()
                message = "密码已修改。"

    return render_template("change_password.html", token=token, username=username, message=message)


@app.route("/firewall")
def firewall():
    token = request.args.get("token")
    username = require_login()
    if not username:
        return redirect(url_for("login"))
    return render_template("firewall.html", username=username, token=token)


@app.route("/logout")
def logout():
    token = request.args.get("token")
    if token:
        delete_session_token(token)
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    is_dev = os.environ.get("TGHELPER_DEV", "1") == "1"
    if not is_dev or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        with app.app_context():
            init_db()
            TgHelper.load_api_config()
            configure_scheduler_jobs()
        if not SCHEDULER.running:
            SCHEDULER.start()

    app.run(host="127.0.0.1", port=15018, debug=is_dev, use_reloader=is_dev)
