import os
import sqlite3
import asyncio
import random
import json
from urllib import request as urlrequest
from urllib import error as urlerror
from datetime import datetime, timedelta, timezone
from pathlib import Path
from secrets import token_urlsafe
from flask import Flask, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
import socks
from telethon import TelegramClient
from telethon.errors import PhoneCodeInvalidError, SessionPasswordNeededError
from telethon.sessions import StringSession

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "VpsHelper.db"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-me")
app.config["APP_NAME"] = "VpsHelper"
app.config["TELEGRAM_API_ID"] = os.environ.get("TELEGRAM_API_ID")
app.config["TELEGRAM_API_HASH"] = os.environ.get("TELEGRAM_API_HASH")

SCHEDULER = BackgroundScheduler(timezone="Asia/Shanghai")
AUTO_SEND_JOB_ID = "auto_send_tick"
AUTO_BACKUP_JOB_ID = "auto_backup_daily"

APP_TABLES = [
    "users",
    "sessions",
    "tg_accounts",
    "tg_dialogs",
    "tg_sign_tasks",
    "tg_auto_send_tasks",
    "tg_login_flows",
    "app_settings",
]

UTC_PLUS_8 = timezone(timedelta(hours=8))


def utc8_now() -> datetime:
    return datetime.now(timezone.utc).astimezone(UTC_PLUS_8)


def utc8_now_text() -> str:
    return utc8_now().strftime("%Y-%m-%d %H:%M:%S UTC+8")


def format_datetime_utc8(dt_value: datetime | None) -> str:
    if not dt_value:
        return utc8_now_text()
    if dt_value.tzinfo is None:
        dt_value = dt_value.replace(tzinfo=timezone.utc)
    return dt_value.astimezone(UTC_PLUS_8).strftime("%Y-%m-%d %H:%M:%S UTC+8")


def append_utc8_timestamp(message: str) -> str:
    return f"{message}\n\n[{utc8_now_text()}]"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


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
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS tg_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            account_name TEXT NOT NULL,
            session_text TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS tg_dialogs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            dialog_id TEXT NOT NULL,
            title TEXT,
            username TEXT,
            updated_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS tg_sign_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            account_id INTEGER NOT NULL,
            dialog_id TEXT NOT NULL,
            message TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(owner, account_id)
        )
        """
    )
    ensure_auto_send_table(db)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS tg_login_flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            phone TEXT NOT NULL,
            account_name TEXT,
            session_text TEXT NOT NULL,
            phone_code_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
    db.commit()


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


def ensure_auto_send_table(db: sqlite3.Connection) -> None:
    columns = db.execute("PRAGMA table_info(tg_auto_send_tasks)").fetchall()
    if not columns:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS tg_auto_send_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner TEXT NOT NULL,
                account_id INTEGER NOT NULL,
                dialog_id TEXT NOT NULL,
                message TEXT NOT NULL,
                interval_seconds INTEGER NOT NULL,
                jitter_seconds INTEGER NOT NULL,
                schedule_type TEXT NOT NULL,
                time_of_day TEXT,
                enabled INTEGER NOT NULL,
                next_run_at TEXT NOT NULL,
                last_run_at TEXT,
                last_result TEXT,
                last_reply TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        return

    column_names = {col[1] for col in columns}
    if "last_reply" in column_names and "created_at" in column_names:
        return

    db.execute("ALTER TABLE tg_auto_send_tasks RENAME TO tg_auto_send_tasks_old")
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS tg_auto_send_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            account_id INTEGER NOT NULL,
            dialog_id TEXT NOT NULL,
            message TEXT NOT NULL,
            interval_seconds INTEGER NOT NULL,
            jitter_seconds INTEGER NOT NULL,
            schedule_type TEXT NOT NULL,
            time_of_day TEXT,
            enabled INTEGER NOT NULL,
            next_run_at TEXT NOT NULL,
            last_run_at TEXT,
            last_result TEXT,
            last_reply TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        INSERT INTO tg_auto_send_tasks (owner, account_id, dialog_id, message, interval_seconds, jitter_seconds, schedule_type, time_of_day, enabled, next_run_at, created_at, updated_at)
        SELECT owner, account_id, dialog_id, message, interval_seconds, jitter_seconds,
               COALESCE(schedule_type, 'interval') AS schedule_type,
               time_of_day,
               enabled, next_run_at,
               COALESCE(updated_at, next_run_at) AS created_at,
               COALESCE(updated_at, next_run_at) AS updated_at
        FROM tg_auto_send_tasks_old
        """
    )
    db.execute("DROP TABLE tg_auto_send_tasks_old")


async def send_tg_login_code(phone: str) -> tuple[bool, str | None, str | None, str | None]:
    api_id = app.config.get("TELEGRAM_API_ID")
    api_hash = app.config.get("TELEGRAM_API_HASH")
    if not api_id or not api_hash:
        return False, "未配置 TELEGRAM_API_ID/TELEGRAM_API_HASH。", None, None

    try:
        session = StringSession()
        client = TelegramClient(
            session,
            int(api_id),
            api_hash,
            proxy=get_configured_proxy(),
            connection_retries=1,
            retry_delay=1,
        )
        await client.connect()
        result = await client.send_code_request(phone)
        session_text = client.session.save()
        await client.disconnect()
        return True, None, session_text, result.phone_code_hash
    except TimeoutError:
        return False, "连接超时，请检查代理或网络。", None, None
    except Exception as exc:
        detail = f"{exc.__class__.__name__}: {exc}" if str(exc) else exc.__class__.__name__
        return False, f"发送验证码失败：{detail}", None, None


async def complete_tg_login(phone: str, session_text: str, phone_code_hash: str, code: str, password: str | None) -> tuple[bool, str | None, str | None, str | None]:
    api_id = app.config.get("TELEGRAM_API_ID")
    api_hash = app.config.get("TELEGRAM_API_HASH")
    if not api_id or not api_hash:
        return False, "未配置 TELEGRAM_API_ID/TELEGRAM_API_HASH。", None, None

    try:
        client = TelegramClient(
            StringSession(session_text),
            int(api_id),
            api_hash,
            proxy=get_configured_proxy(),
            connection_retries=1,
            retry_delay=1,
        )
        await client.connect()
        try:
            await client.sign_in(phone=phone, code=code, phone_code_hash=phone_code_hash)
        except SessionPasswordNeededError:
            if not password:
                await client.disconnect()
                return False, "需要两步验证密码。", None, None
            await client.sign_in(password=password)
        me = await client.get_me()
        final_session = client.session.save()
        await client.disconnect()
        display_name = me.username or (me.phone if hasattr(me, "phone") else None)
        return True, None, display_name, final_session
    except PhoneCodeInvalidError:
        return False, "验证码错误。", None, None
    except TimeoutError:
        return False, "连接超时，请检查代理或网络。", None, None
    except Exception as exc:
        detail = f"{exc.__class__.__name__}: {exc}" if str(exc) else exc.__class__.__name__
        return False, f"登录失败：{detail}", None, None


async def fetch_recent_dialogs(session_text: str, limit: int = 30) -> list[dict]:
    api_id = app.config.get("TELEGRAM_API_ID")
    api_hash = app.config.get("TELEGRAM_API_HASH")
    if not api_id or not api_hash:
        return []

    client = TelegramClient(
        StringSession(session_text),
        int(api_id),
        api_hash,
        proxy=get_configured_proxy(),
        connection_retries=1,
        retry_delay=1,
    )
    dialogs = []
    try:
        await client.connect()
        async for dialog in client.iter_dialogs(limit=limit):
            entity = dialog.entity
            dialogs.append(
                {
                    "dialog_id": str(dialog.id),
                    "title": dialog.name,
                    "username": getattr(entity, "username", None),
                }
            )
    finally:
        await client.disconnect()
    return dialogs


async def send_message_to_dialog(session_text: str, dialog_id: str, message: str) -> None:
    api_id = app.config.get("TELEGRAM_API_ID")
    api_hash = app.config.get("TELEGRAM_API_HASH")
    if not api_id or not api_hash:
        raise RuntimeError("API 未配置")

    client = TelegramClient(
        StringSession(session_text),
        int(api_id),
        api_hash,
        proxy=get_configured_proxy(),
        connection_retries=1,
        retry_delay=1,
    )
    try:
        await client.connect()
        target = await resolve_dialog_target(client, dialog_id)
        await client.send_message(target, append_utc8_timestamp(message))
    finally:
        await client.disconnect()


async def send_and_fetch_reply(session_text: str, dialog_id: str, message: str) -> str | None:
    api_id = app.config.get("TELEGRAM_API_ID")
    api_hash = app.config.get("TELEGRAM_API_HASH")
    if not api_id or not api_hash:
        raise RuntimeError("API 未配置")

    client = TelegramClient(
        StringSession(session_text),
        int(api_id),
        api_hash,
        proxy=get_configured_proxy(),
        connection_retries=1,
        retry_delay=1,
    )
    try:
        await client.connect()
        target = await resolve_dialog_target(client, dialog_id)
        await client.send_message(target, append_utc8_timestamp(message))
        await asyncio.sleep(2)
        messages = await client.get_messages(target, limit=5)
        for msg in messages:
            if not msg.out:
                reply_text = msg.message or ""
                return f"[{format_datetime_utc8(msg.date)}] {reply_text}" if reply_text else f"[{format_datetime_utc8(msg.date)}]"
        return None
    finally:
        await client.disconnect()


async def resolve_dialog_target(client: TelegramClient, dialog_id: str):
    async for dialog in client.iter_dialogs(limit=200):
        if str(dialog.id) == str(dialog_id):
            return dialog.entity

    try:
        return int(dialog_id)
    except ValueError:
        return dialog_id


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


def get_configured_proxy():
    host = app.config.get("PROXY_HOST")
    port = app.config.get("PROXY_PORT")
    if not host or not port:
        return None

    try:
        port_value = int(port)
    except ValueError:
        return None

    username = app.config.get("PROXY_USERNAME")
    password = app.config.get("PROXY_PASSWORD")
    if username or password:
        return (socks.SOCKS5, host, port_value, True, username, password)
    return (socks.SOCKS5, host, port_value, True)


def test_proxy_connection() -> tuple[bool, str]:
    proxy = get_configured_proxy()
    if not proxy:
        return False, "未配置代理。"

    api_id = app.config.get("TELEGRAM_API_ID")
    api_hash = app.config.get("TELEGRAM_API_HASH")
    if api_id and api_hash:
        try:
            async def _telethon_ping():
                session = StringSession()
                client = TelegramClient(
                    session,
                    int(api_id),
                    api_hash,
                    proxy=proxy,
                    connection_retries=1,
                    retry_delay=1,
                )
                await client.connect()
                await client.disconnect()

            run_async(_telethon_ping())
            return True, "代理可用，已连通 Telegram。"
        except Exception as exc:
            detail = f"{exc.__class__.__name__}: {exc}" if str(exc) else exc.__class__.__name__
            return False, f"代理不可用：{detail}"

    try:
        sock = socks.socksocket()
        sock.set_proxy(*proxy)
        sock.settimeout(6)
        sock.connect(("api.telegram.org", 443))
        sock.close()
        return True, "代理可用。"
    except Exception as exc:
        detail = f"{exc.__class__.__name__}: {exc}" if str(exc) else exc.__class__.__name__
        return False, f"代理不可用：{detail}"


def load_api_config():
    db = get_db()
    rows = db.execute(
        "SELECT key, value FROM app_settings WHERE key IN ('telegram_api_id', 'telegram_api_hash', 'proxy_host', 'proxy_port', 'proxy_username', 'proxy_password', 'cf_api_token', 'cf_account_id', 'cf_d1_database_name', 'cf_d1_database_id', 'cf_use_d1', 'db_auto_backup_enabled', 'db_auto_backup_time', 'db_auto_backup_last_date', 'db_auto_backup_last_result')"
    ).fetchall()
    data = {row["key"]: row["value"] for row in rows}
    app.config["TELEGRAM_API_ID"] = os.environ.get("TELEGRAM_API_ID") or data.get("telegram_api_id")
    app.config["TELEGRAM_API_HASH"] = os.environ.get("TELEGRAM_API_HASH") or data.get("telegram_api_hash")
    app.config["PROXY_HOST"] = data.get("proxy_host")
    app.config["PROXY_PORT"] = data.get("proxy_port")
    app.config["PROXY_USERNAME"] = data.get("proxy_username")
    app.config["PROXY_PASSWORD"] = data.get("proxy_password")
    app.config["CF_API_TOKEN"] = data.get("cf_api_token")
    app.config["CF_ACCOUNT_ID"] = data.get("cf_account_id")
    app.config["CF_D1_DATABASE_NAME"] = data.get("cf_d1_database_name")
    app.config["CF_D1_DATABASE_ID"] = data.get("cf_d1_database_id")
    app.config["CF_USE_D1"] = data.get("cf_use_d1") == "1"
    app.config["DB_AUTO_BACKUP_ENABLED"] = data.get("db_auto_backup_enabled") == "1"
    app.config["DB_AUTO_BACKUP_TIME"] = data.get("db_auto_backup_time") or "03:30"
    app.config["DB_AUTO_BACKUP_LAST_DATE"] = data.get("db_auto_backup_last_date") or ""
    app.config["DB_AUTO_BACKUP_LAST_RESULT"] = data.get("db_auto_backup_last_result") or ""


def run_async(coro):
    try:
        return asyncio.run(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(coro)
        finally:
            loop.close()


def refresh_dialogs_for_account(account_id: int, session_text: str) -> None:
    dialogs = run_async(fetch_recent_dialogs(session_text))
    db = get_db()
    db.execute("DELETE FROM tg_dialogs WHERE account_id = ?", (account_id,))
    for item in dialogs:
        db.execute(
            "INSERT INTO tg_dialogs (account_id, dialog_id, title, username, updated_at) VALUES (?, ?, ?, ?, ?)",
            (account_id, item["dialog_id"], item["title"], item["username"], datetime.utcnow().isoformat()),
        )
    db.commit()


def schedule_next_run(interval_seconds: int, jitter_seconds: int, schedule_type: str, time_of_day: str | None) -> str:
    jitter = random.randint(0, max(jitter_seconds, 0))
    now = datetime.now()

    if schedule_type == "daily" and time_of_day:
        try:
            hour, minute = time_of_day.split(":")
            target = now.replace(hour=int(hour), minute=int(minute), second=0, microsecond=0)
            if target <= now:
                target = target + timedelta(days=1)
            return (target + timedelta(seconds=jitter)).isoformat()
        except ValueError:
            pass

    return (now + timedelta(seconds=interval_seconds + jitter)).isoformat()


def process_auto_send_due_tasks() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        now = datetime.now().isoformat()
        tasks = conn.execute(
            """
            SELECT t.id, t.owner, t.account_id, t.dialog_id, t.message, t.interval_seconds, t.jitter_seconds,
                   t.schedule_type, t.time_of_day, t.next_run_at, a.session_text
            FROM tg_auto_send_tasks t
            JOIN tg_accounts a ON a.id = t.account_id
            WHERE t.enabled = 1 AND t.next_run_at <= ?
            """,
            (now,),
        ).fetchall()

        for task in tasks:
            try:
                reply = run_async(send_and_fetch_reply(task["session_text"], task["dialog_id"], task["message"]))
                next_run = schedule_next_run(
                    task["interval_seconds"],
                    task["jitter_seconds"],
                    task["schedule_type"],
                    task["time_of_day"],
                )
                conn.execute(
                    "UPDATE tg_auto_send_tasks SET next_run_at = ?, last_run_at = ?, last_result = ?, last_reply = ?, updated_at = ? WHERE id = ?",
                    (
                        next_run,
                        datetime.now().isoformat(),
                        f"sent [{utc8_now_text()}]",
                        reply,
                        datetime.now().isoformat(),
                        task["id"],
                    ),
                )
                conn.commit()
            except Exception as exc:
                next_run = schedule_next_run(
                    task["interval_seconds"],
                    task["jitter_seconds"],
                    task["schedule_type"],
                    task["time_of_day"],
                )
                detail = f"{exc.__class__.__name__}: {exc}" if str(exc) else exc.__class__.__name__
                conn.execute(
                    "UPDATE tg_auto_send_tasks SET next_run_at = ?, last_run_at = ?, last_result = ?, updated_at = ? WHERE id = ?",
                    (
                        next_run,
                        datetime.now().isoformat(),
                        f"failed [{utc8_now_text()}]: {detail}",
                        datetime.now().isoformat(),
                        task["id"],
                    ),
                )
                conn.commit()
    finally:
        conn.close()


def run_auto_send_job():
    try:
        process_auto_send_due_tasks()
    except Exception:
        pass


def configure_scheduler_jobs():
    if SCHEDULER.get_job(AUTO_SEND_JOB_ID) is None:
        SCHEDULER.add_job(run_auto_send_job, CronTrigger(second="*/5"), id=AUTO_SEND_JOB_ID, replace_existing=True)


@app.before_request
def ensure_db_initialized():
    init_db()
    load_api_config()


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


@app.route("/logout")
def logout():
    token = request.args.get("token")
    if token:
        delete_session_token(token)
    session.clear()
    return redirect(url_for("login"))


@app.route("/tg-helper")
def tg_helper():
    token = request.args.get("token")
    username = require_login()
    if not username:
        return redirect(url_for("login"))
    return render_template("tg_helper.html", username=username, token=token)


@app.route("/firewall")
def firewall():
    token = request.args.get("token")
    username = require_login()
    if not username:
        return redirect(url_for("login"))
    return render_template("firewall.html", username=username, token=token)


@app.route("/tg/accounts/delete/<int:account_id>", methods=["POST"])
def delete_account(account_id: int):
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    token = request.form.get("token")
    db = get_db()
    db.execute("DELETE FROM tg_accounts WHERE id = ? AND owner = ?", (account_id, username))
    db.commit()
    return redirect(url_for("tg_accounts", token=token) if token else url_for("tg_accounts"))


@app.route("/tg/accounts")
def tg_accounts():
    token = request.args.get("token")
    error = request.args.get("error")
    selected_account_id = request.args.get("account_id")
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    db = get_db()
    accounts_list = db.execute(
        "SELECT id, account_name, session_text, created_at FROM tg_accounts WHERE owner = ? ORDER BY id DESC",
        (username,),
    ).fetchall()

    if not selected_account_id and accounts_list:
        selected_account_id = str(accounts_list[0]["id"])

    dialogs = []
    sign_task = None
    if selected_account_id:
        dialogs = db.execute(
            "SELECT dialog_id, title, username FROM tg_dialogs WHERE account_id = ? ORDER BY id DESC",
            (selected_account_id,),
        ).fetchall()
        sign_task = db.execute(
            "SELECT dialog_id, message FROM tg_sign_tasks WHERE owner = ? AND account_id = ?",
            (username, selected_account_id),
        ).fetchone()

    return render_template(
        "tg_accounts.html",
        username=username,
        token=token,
        accounts=accounts_list,
        error=error,
        selected_account_id=selected_account_id,
        dialogs=dialogs,
        sign_task=sign_task,
    )


if __name__ == "__main__":
    configure_scheduler_jobs()
    SCHEDULER.start()
    app.run(host="0.0.0.0", port=15018, debug=False)
