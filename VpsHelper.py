import os
import sqlite3
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
    is_dev = os.environ.get("TGHELPER_DEV") == "1"
    if not is_dev or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        with app.app_context():
            init_db()
            TgHelper.load_api_config()
            configure_scheduler_jobs()
        if not SCHEDULER.running:
            SCHEDULER.start()

    app.run(host="0.0.0.0", port=15018, debug=is_dev, use_reloader=is_dev)
