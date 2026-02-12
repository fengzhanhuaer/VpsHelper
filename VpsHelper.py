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
AUTO_SEND_JOB_ID = "auto_send_tick"
AUTO_BACKUP_JOB_ID = "auto_backup_daily"


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


get_tg_db = TgHelper.get_tg_db
ensure_auto_send_table = TgHelper.ensure_auto_send_table
utc8_now = TgHelper.utc8_now
utc8_now_text = TgHelper.utc8_now_text
format_datetime_utc8 = TgHelper.format_datetime_utc8
append_utc8_timestamp = TgHelper.append_utc8_timestamp
run_async = TgHelper.run_async
get_configured_proxy = TgHelper.get_configured_proxy
send_tg_login_code = TgHelper.send_tg_login_code
complete_tg_login = TgHelper.complete_tg_login
fetch_recent_dialogs = TgHelper.fetch_recent_dialogs
resolve_dialog_target = TgHelper.resolve_dialog_target
send_and_fetch_reply = TgHelper.send_and_fetch_reply
refresh_dialogs_for_account = TgHelper.refresh_dialogs_for_account
test_proxy_connection = TgHelper.test_proxy_connection
load_api_config = TgHelper.load_api_config
cloudflare_request = TgHelper.cloudflare_request
cloudflare_create_d1 = TgHelper.cloudflare_create_d1
cloudflare_get_first_account = TgHelper.cloudflare_get_first_account
cloudflare_test_token = TgHelper.cloudflare_test_token
cloudflare_find_d1_by_name = TgHelper.cloudflare_find_d1_by_name
cloudflare_d1_query = TgHelper.cloudflare_d1_query
ensure_cloud_d1_schema = TgHelper.ensure_cloud_d1_schema
backup_local_to_d1 = TgHelper.backup_local_to_d1
pull_d1_to_local = TgHelper.pull_d1_to_local
process_daily_cloud_backup = TgHelper.process_daily_cloud_backup
schedule_next_run = TgHelper.schedule_next_run
process_auto_send_due_tasks = TgHelper.process_auto_send_due_tasks
run_auto_send_job = TgHelper.run_auto_send_job
run_auto_backup_job = TgHelper.run_auto_backup_job


def configure_scheduler_jobs():
    TgHelper.configure_scheduler_jobs(SCHEDULER, AUTO_SEND_JOB_ID, AUTO_BACKUP_JOB_ID)


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


@app.route("/tg_helper")
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


@app.route("/logout")
def logout():
    token = request.args.get("token")
    if token:
        delete_session_token(token)
    session.clear()
    return redirect(url_for("login"))


@app.route("/accounts/delete/<int:account_id>", methods=["POST"])
def delete_account(account_id: int):
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    token = request.form.get("token")
    db = get_tg_db()
    db.execute("DELETE FROM tg_accounts WHERE id = ? AND owner = ?", (account_id, username))
    db.commit()
    return redirect(url_for("accounts", token=token) if token else url_for("accounts"))


@app.route("/accounts")
def accounts():
    token = request.args.get("token")
    error = request.args.get("error")
    selected_account_id = request.args.get("account_id")
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    db = get_tg_db()
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
        "accounts.html",
        username=username,
        token=token,
        accounts=accounts_list,
        error=error,
        selected_account_id=selected_account_id,
        dialogs=dialogs,
        sign_task=sign_task,
    )


@app.route("/settings/api", methods=["GET", "POST"])
def api_settings():
    token = request.args.get("token") or request.form.get("token")
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    message = None
    if request.method == "POST":
        api_id = request.form.get("api_id", "").strip()
        api_hash = request.form.get("api_hash", "").strip()
        if not api_id or not api_hash:
            message = "API ID 和 API Hash 不能为空。"
        else:
            db = get_tg_db()
            db.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('telegram_api_id', ?)", (api_id,))
            db.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('telegram_api_hash', ?)", (api_hash,))
            db.commit()
            load_api_config()
            message = "已保存。"

    return render_template(
        "api_settings.html",
        token=token,
        api_id=app.config.get("TELEGRAM_API_ID") or "",
        api_hash=app.config.get("TELEGRAM_API_HASH") or "",
        message=message,
    )


@app.route("/settings/proxy", methods=["GET", "POST"])
def proxy_settings():
    token = request.args.get("token") or request.form.get("token")
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    message = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "test":
            ok, message = test_proxy_connection()
        else:
            proxy_host = request.form.get("proxy_host", "").strip()
            proxy_port = request.form.get("proxy_port", "").strip()
            proxy_username = request.form.get("proxy_username", "").strip()
            proxy_password = request.form.get("proxy_password", "").strip()

            if (proxy_host and not proxy_port) or (proxy_port and not proxy_host):
                message = "代理地址与端口需同时填写，或同时留空。"
            else:
                db = get_tg_db()
                if proxy_host and proxy_port:
                    db.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('proxy_host', ?)", (proxy_host,))
                    db.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('proxy_port', ?)", (proxy_port,))
                    db.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('proxy_username', ?)", (proxy_username,))
                    db.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('proxy_password', ?)", (proxy_password,))
                else:
                    db.execute("DELETE FROM app_settings WHERE key IN ('proxy_host', 'proxy_port', 'proxy_username', 'proxy_password')")
                db.commit()
                load_api_config()
                message = "已保存。"

    return render_template(
        "proxy_settings.html",
        token=token,
        proxy_host=app.config.get("PROXY_HOST") or "",
        proxy_port=app.config.get("PROXY_PORT") or "",
        proxy_username=app.config.get("PROXY_USERNAME") or "",
        proxy_password=app.config.get("PROXY_PASSWORD") or "",
        message=message,
    )


@app.route("/settings/database", methods=["GET", "POST"])
def database_settings():
    token = request.args.get("token") or request.form.get("token")
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    message = None
    db = get_tg_db()
    if request.method == "POST":
        action = request.form.get("action", "save")
        api_token = request.form.get("cf_api_token", "").strip()
        account_id = app.config.get("CF_ACCOUNT_ID") or ""
        db_name = "TgHelper"
        db_id = app.config.get("CF_D1_DATABASE_ID") or ""
        use_d1 = app.config.get("CF_USE_D1") or False

        if action == "create":
            if not api_token:
                message = "请先填写 API Token。"
            else:
                ok, message, resolved_account_id = cloudflare_test_token(api_token)
                if resolved_account_id:
                    account_id = resolved_account_id
                    ok_find, _, found_db_id = cloudflare_find_d1_by_name(api_token, account_id, db_name)
                    if ok_find and found_db_id:
                        db_id = found_db_id
                        message = "已找到云端数据库 TgHelper。"
                        use_d1 = True
                    else:
                        ok_create, msg, created_id = cloudflare_create_d1(api_token, account_id, db_name)
                        message = msg
                        if ok_create and created_id:
                            db_id = created_id
                            use_d1 = True
        elif action == "backup":
            if not api_token:
                message = "请先填写 API Token。"
            else:
                ok, msg, resolved_account_id = cloudflare_test_token(api_token)
                if not ok or not resolved_account_id:
                    message = msg
                else:
                    account_id = resolved_account_id
                    ok_find, _, found_db_id = cloudflare_find_d1_by_name(api_token, account_id, db_name)
                    if not ok_find or not found_db_id:
                        message = "未找到云端数据库 TgHelper，请先创建。"
                    else:
                        db_id = found_db_id
                        ok_bak, msg_bak = backup_local_to_d1(api_token, account_id, db_id, db)
                        message = msg_bak
                        use_d1 = ok_bak
        elif action == "pull":
            if not api_token:
                message = "请先填写 API Token。"
            else:
                ok, msg, resolved_account_id = cloudflare_test_token(api_token)
                if not ok or not resolved_account_id:
                    message = msg
                else:
                    account_id = resolved_account_id
                    ok_find, _, found_db_id = cloudflare_find_d1_by_name(api_token, account_id, db_name)
                    if not ok_find or not found_db_id:
                        message = "未找到云端数据库 TgHelper，请先创建。"
                    else:
                        db_id = found_db_id
                        ok_pull, msg_pull = pull_d1_to_local(api_token, account_id, db_id, db)
                        message = msg_pull
                        use_d1 = ok_pull
        elif action == "auto_backup":
            auto_enabled = request.form.get("db_auto_backup_enabled") == "on"
            auto_time = request.form.get("db_auto_backup_time", "03:30").strip()
            if ":" not in auto_time:
                message = "自动备份时间格式不正确，应为 HH:MM。"
            else:
                db.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('db_auto_backup_enabled', ?)", ("1" if auto_enabled else "0",))
                db.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('db_auto_backup_time', ?)", (auto_time,))
                db.commit()
                load_api_config()
                if SCHEDULER.running:
                    configure_scheduler_jobs()
                message = "自动备份设置已保存。"
        else:
            if not api_token:
                message = "请先填写 API Token。"
            else:
                message = "已保存。"

        if api_token:
            db.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('cf_api_token', ?)", (api_token,))
            db.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('cf_account_id', ?)", (account_id,))
            db.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('cf_d1_database_name', ?)", (db_name,))
            db.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('cf_d1_database_id', ?)", (db_id,))
            db.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('cf_use_d1', ?)", ("1" if use_d1 else "0",))
            db.commit()
            load_api_config()

    load_api_config()

    return render_template(
        "database_settings.html",
        token=token,
        message=message,
        cf_api_token=app.config.get("CF_API_TOKEN") or "",
        cf_d1_database_name="TgHelper",
        cf_d1_database_id=app.config.get("CF_D1_DATABASE_ID") or "",
        cf_use_d1=app.config.get("CF_USE_D1") or False,
        db_auto_backup_enabled=app.config.get("DB_AUTO_BACKUP_ENABLED") or False,
        db_auto_backup_time=app.config.get("DB_AUTO_BACKUP_TIME") or "03:30",
        db_auto_backup_last_result=app.config.get("DB_AUTO_BACKUP_LAST_RESULT") or "",
    )


@app.route("/auto/send")
def auto_send():
    token = request.args.get("token")
    username = require_login()
    if not username:
        return redirect(url_for("login"))
    return render_template("auto_send.html", token=token)


@app.route("/auto/reply")
def auto_reply():
    token = request.args.get("token")
    username = require_login()
    if not username:
        return redirect(url_for("login"))
    return render_template("auto_reply.html", token=token)


@app.route("/auto/send/new")
def auto_send_new():
    token = request.args.get("token")
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    selected_account_id = request.args.get("account_id")
    db = get_tg_db()
    accounts_list = db.execute(
        "SELECT id, account_name FROM tg_accounts WHERE owner = ? ORDER BY id DESC",
        (username,),
    ).fetchall()

    if not selected_account_id and accounts_list:
        selected_account_id = str(accounts_list[0]["id"])

    dialogs = []
    if selected_account_id:
        dialogs = db.execute(
            "SELECT dialog_id, title, username FROM tg_dialogs WHERE account_id = ? ORDER BY id DESC",
            (selected_account_id,),
        ).fetchall()

    return render_template(
        "auto_send_new.html",
        token=token,
        accounts=accounts_list,
        selected_account_id=selected_account_id,
        dialogs=dialogs,
        error=request.args.get("error"),
    )


@app.route("/auto/send/manage")
def auto_send_manage():
    token = request.args.get("token")
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    selected_account_id = request.args.get("account_id")
    db = get_tg_db()
    accounts_list = db.execute(
        "SELECT id, account_name FROM tg_accounts WHERE owner = ? ORDER BY id DESC",
        (username,),
    ).fetchall()

    if not selected_account_id and accounts_list:
        selected_account_id = str(accounts_list[0]["id"])

    tasks = []
    if selected_account_id:
        tasks = db.execute(
            """
             SELECT t.id, t.dialog_id, t.message, t.interval_seconds, t.jitter_seconds, t.schedule_type, t.time_of_day,
                 t.enabled, t.last_run_at, t.last_result, t.last_reply,
                 COALESCE(d.title, d.username, t.dialog_id) AS dialog_name
             FROM tg_auto_send_tasks t
             LEFT JOIN tg_dialogs d ON d.account_id = t.account_id AND d.dialog_id = t.dialog_id
             WHERE t.owner = ? AND t.account_id = ?
                 ORDER BY t.id DESC
            """,
            (username, selected_account_id),
        ).fetchall()

    return render_template(
        "auto_send_manage.html",
        token=token,
        accounts=accounts_list,
        selected_account_id=selected_account_id,
        tasks=tasks,
        error=request.args.get("error"),
        message=request.args.get("message"),
    )


@app.route("/auto/send/refresh", methods=["POST"])
def auto_send_refresh_dialogs():
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    token = request.form.get("token")
    account_id = request.form.get("account_id")
    if not account_id:
        return redirect(url_for("auto_send_new", token=token, error="请选择账号。") if token else url_for("auto_send_new", error="请选择账号。"))

    db = get_tg_db()
    account = db.execute(
        "SELECT id, session_text FROM tg_accounts WHERE id = ? AND owner = ?",
        (account_id, username),
    ).fetchone()
    if not account:
        return redirect(url_for("auto_send_new", token=token, error="账号不存在。") if token else url_for("auto_send_new", error="账号不存在。"))

    refresh_dialogs_for_account(account["id"], account["session_text"])
    return redirect(
        url_for("auto_send_new", token=token, account_id=account_id)
        if token
        else url_for("auto_send_new", account_id=account_id)
    )


@app.route("/auto/send/save", methods=["POST"])
def auto_send_save():
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    token = request.form.get("token")
    account_id = request.form.get("account_id")
    dialog_id = request.form.get("dialog_id")
    message_text = request.form.get("message", "").strip()
    jitter_seconds = request.form.get("jitter_seconds", "0").strip()
    schedule_type = "daily"
    time_of_day = request.form.get("time_of_day", "").strip()
    enabled = request.form.get("enabled") == "on"

    if not account_id or not dialog_id or not message_text:
        return redirect(url_for("auto_send_new", token=token, error="请选择账号与会话，并填写内容。") if token else url_for("auto_send_new", error="请选择账号与会话，并填写内容。"))

    try:
        jitter_value = int(jitter_seconds) if jitter_seconds else 0
        if jitter_value < 0:
            raise ValueError
    except ValueError:
        return redirect(url_for("auto_send_new", token=token, error="随机延时填写不正确。") if token else url_for("auto_send_new", error="随机延时填写不正确。"))

    if not time_of_day or ":" not in time_of_day:
        return redirect(url_for("auto_send_new", token=token, error="请填写每天的时间点，例如 09:30。") if token else url_for("auto_send_new", error="请填写每天的时间点，例如 09:30。"))
    interval_value = 86400

    next_run = schedule_next_run(interval_value, jitter_value, schedule_type, time_of_day)
    db = get_tg_db()
    now_str = datetime.now().isoformat()
    db.execute(
        """
        INSERT INTO tg_auto_send_tasks (owner, account_id, dialog_id, message, interval_seconds, jitter_seconds, schedule_type, time_of_day, enabled, next_run_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            username,
            account_id,
            dialog_id,
            message_text,
            interval_value,
            jitter_value,
            schedule_type,
            time_of_day,
            1 if enabled else 0,
            next_run,
            now_str,
            now_str,
        ),
    )
    db.commit()

    return redirect(
        url_for("auto_send_manage", token=token, account_id=account_id, message="已保存。")
        if token
        else url_for("auto_send_manage", account_id=account_id, message="已保存。")
    )


@app.route("/auto/send/delete/<int:task_id>", methods=["POST"])
def auto_send_delete(task_id: int):
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    token = request.form.get("token")
    account_id = request.form.get("account_id")
    db = get_tg_db()
    db.execute("DELETE FROM tg_auto_send_tasks WHERE id = ? AND owner = ?", (task_id, username))
    db.commit()
    return redirect(
        url_for("auto_send_manage", token=token, account_id=account_id)
        if token
        else url_for("auto_send_manage", account_id=account_id)
    )


@app.route("/auto/send/update/<int:task_id>", methods=["POST"])
def auto_send_update(task_id: int):
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    token = request.form.get("token")
    account_id = request.form.get("account_id")
    message_text = request.form.get("message", "").strip()
    time_of_day = request.form.get("time_of_day", "").strip()
    jitter_seconds = request.form.get("jitter_seconds", "0").strip()
    if not message_text:
        return redirect(
            url_for("auto_send_manage", token=token, account_id=account_id, error="发送内容不能为空。")
            if token
            else url_for("auto_send_manage", account_id=account_id, error="发送内容不能为空。")
        )

    if not time_of_day or ":" not in time_of_day:
        return redirect(
            url_for("auto_send_manage", token=token, account_id=account_id, error="时间格式不正确，应为 HH:MM。")
            if token
            else url_for("auto_send_manage", account_id=account_id, error="时间格式不正确，应为 HH:MM。")
        )

    try:
        hh, mm = time_of_day.split(":")
        hh_value = int(hh)
        mm_value = int(mm)
        if hh_value < 0 or hh_value > 23 or mm_value < 0 or mm_value > 59:
            raise ValueError
        jitter_value = int(jitter_seconds) if jitter_seconds else 0
        if jitter_value < 0:
            raise ValueError
    except ValueError:
        return redirect(
            url_for("auto_send_manage", token=token, account_id=account_id, error="时间或随机延时填写不正确。")
            if token
            else url_for("auto_send_manage", account_id=account_id, error="时间或随机延时填写不正确。")
        )

    interval_value = 86400
    next_run = schedule_next_run(interval_value, jitter_value, "daily", time_of_day)

    db = get_tg_db()
    db.execute(
        "UPDATE tg_auto_send_tasks SET message = ?, time_of_day = ?, jitter_seconds = ?, interval_seconds = ?, schedule_type = ?, next_run_at = ?, updated_at = ? WHERE id = ? AND owner = ?",
        (message_text, time_of_day, jitter_value, interval_value, "daily", next_run, datetime.now().isoformat(), task_id, username),
    )
    db.commit()
    return redirect(
        url_for("auto_send_manage", token=token, account_id=account_id, message="任务内容与计划已更新。")
        if token
        else url_for("auto_send_manage", account_id=account_id, message="任务内容与计划已更新。")
    )


@app.route("/auto/send/run/<int:task_id>", methods=["POST"])
def auto_send_run(task_id: int):
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    token = request.form.get("token")
    account_id = request.form.get("account_id")
    db = get_tg_db()
    task = db.execute(
        """
        SELECT t.id, t.dialog_id, t.message, a.session_text
        FROM tg_auto_send_tasks t
        JOIN tg_accounts a ON a.id = t.account_id
        WHERE t.id = ? AND t.owner = ?
        """,
        (task_id, username),
    ).fetchone()

    if not task:
        return redirect(url_for("auto_send_manage", token=token, error="任务不存在。") if token else url_for("auto_send_manage", error="任务不存在。"))

    try:
        reply = run_async(send_and_fetch_reply(task["session_text"], task["dialog_id"], task["message"]))
        db.execute(
            "UPDATE tg_auto_send_tasks SET last_run_at = ?, last_result = ?, last_reply = ?, updated_at = ? WHERE id = ?",
            (datetime.now().isoformat(), f"sent [{utc8_now_text()}]", reply, datetime.now().isoformat(), task_id),
        )
        db.commit()
        msg = "已发送。"
    except Exception as exc:
        detail = f"{exc.__class__.__name__}: {exc}" if str(exc) else exc.__class__.__name__
        db.execute(
            "UPDATE tg_auto_send_tasks SET last_run_at = ?, last_result = ?, updated_at = ? WHERE id = ?",
            (datetime.now().isoformat(), f"failed [{utc8_now_text()}]: {detail}", datetime.now().isoformat(), task_id),
        )
        db.commit()
        msg = "发送失败。"

    return redirect(
        url_for("auto_send_manage", token=token, account_id=account_id, message=msg)
        if token
        else url_for("auto_send_manage", account_id=account_id, message=msg)
    )


@app.route("/tg/login/start", methods=["POST"])
def tg_login_start():
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    token = request.form.get("token")
    phone = request.form.get("phone", "").strip()
    account_name = request.form.get("account_name", "").strip()
    if not phone:
        return redirect(url_for("accounts", token=token, error="请输入手机号。") if token else url_for("accounts", error="请输入手机号。"))

    ok, error, session_text, phone_code_hash = run_async(send_tg_login_code(phone))
    if not ok:
        return redirect(url_for("accounts", token=token, error=error) if token else url_for("accounts", error=error))

    db = get_tg_db()
    cur = db.execute(
        "INSERT INTO tg_login_flows (owner, phone, account_name, session_text, phone_code_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (username, phone, account_name or None, session_text, phone_code_hash, datetime.utcnow().isoformat()),
    )
    db.commit()
    flow_id = cur.lastrowid
    return redirect(url_for("tg_login_verify", flow_id=flow_id, token=token) if token else url_for("tg_login_verify", flow_id=flow_id))


@app.route("/tg/login/verify", methods=["GET", "POST"])
def tg_login_verify():
    token = request.args.get("token") or request.form.get("token")
    flow_id = request.args.get("flow_id") or request.form.get("flow_id")
    username = require_login()
    if not username:
        return redirect(url_for("login"))
    if not flow_id:
        return redirect(url_for("accounts", token=token, error="缺少登录流程信息。") if token else url_for("accounts", error="缺少登录流程信息。"))

    db = get_tg_db()
    flow = db.execute(
        "SELECT * FROM tg_login_flows WHERE id = ? AND owner = ?",
        (flow_id, username),
    ).fetchone()
    if not flow:
        return redirect(url_for("accounts", token=token, error="登录流程已过期。") if token else url_for("accounts", error="登录流程已过期。"))

    if request.method == "GET":
        return render_template(
            "tg_login_verify.html",
            token=token,
            flow_id=flow_id,
            phone=flow["phone"],
            error=request.args.get("error"),
        )

    code = request.form.get("code", "").strip()
    password = request.form.get("password", "").strip() or None
    if not code:
        return redirect(
            url_for("tg_login_verify", flow_id=flow_id, token=token, error="请输入验证码。")
            if token
            else url_for("tg_login_verify", flow_id=flow_id, error="请输入验证码。")
        )

    ok, error, display_name, final_session = run_async(
        complete_tg_login(
            phone=flow["phone"],
            session_text=flow["session_text"],
            phone_code_hash=flow["phone_code_hash"],
            code=code,
            password=password,
        )
    )
    if not ok:
        return redirect(
            url_for("tg_login_verify", flow_id=flow_id, token=token, error=error)
            if token
            else url_for("tg_login_verify", flow_id=flow_id, error=error)
        )

    account_name = flow["account_name"] or display_name or flow["phone"]
    final_session_text = final_session or flow["session_text"]
    cur = db.execute(
        "INSERT INTO tg_accounts (owner, account_name, session_text, created_at) VALUES (?, ?, ?, ?)",
        (username, account_name, final_session_text, datetime.utcnow().isoformat()),
    )
    account_id = cur.lastrowid
    db.execute("DELETE FROM tg_login_flows WHERE id = ? AND owner = ?", (flow_id, username))
    db.commit()
    if account_id:
        refresh_dialogs_for_account(account_id, final_session_text)
    return redirect(url_for("accounts", token=token) if token else url_for("accounts"))


@app.route("/tg/dialogs/refresh", methods=["POST"])
def tg_refresh_dialogs():
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    token = request.form.get("token")
    account_id = request.form.get("account_id")
    if not account_id:
        return redirect(url_for("accounts", token=token, error="请选择账号。") if token else url_for("accounts", error="请选择账号。"))

    db = get_tg_db()
    account = db.execute(
        "SELECT id, session_text FROM tg_accounts WHERE id = ? AND owner = ?",
        (account_id, username),
    ).fetchone()
    if not account:
        return redirect(url_for("accounts", token=token, error="账号不存在。") if token else url_for("accounts", error="账号不存在。"))

    refresh_dialogs_for_account(account["id"], account["session_text"])
    return redirect(
        url_for("accounts", token=token, account_id=account_id)
        if token
        else url_for("accounts", account_id=account_id)
    )


@app.route("/tg/sign/save", methods=["POST"])
def tg_save_sign_task():
    username = require_login()
    if not username:
        return redirect(url_for("login"))

    token = request.form.get("token")
    account_id = request.form.get("account_id")
    dialog_id = request.form.get("dialog_id")
    message = request.form.get("message", "").strip()
    if not account_id or not dialog_id:
        return redirect(url_for("accounts", token=token, error="请选择账号和会话。") if token else url_for("accounts", error="请选择账号和会话。"))

    db = get_tg_db()
    db.execute(
        """
        INSERT INTO tg_sign_tasks (owner, account_id, dialog_id, message, created_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(owner, account_id)
        DO UPDATE SET dialog_id = excluded.dialog_id, message = excluded.message, created_at = excluded.created_at
        """,
        (username, account_id, dialog_id, message, datetime.utcnow().isoformat()),
    )
    db.commit()
    return redirect(
        url_for("accounts", token=token, account_id=account_id)
        if token
        else url_for("accounts", account_id=account_id)
    )


if __name__ == "__main__":
    is_dev = os.environ.get("TGHELPER_DEV") == "1"
    if not is_dev or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        with app.app_context():
            init_db()
            load_api_config()
            configure_scheduler_jobs()
        if not SCHEDULER.running:
            SCHEDULER.start()

    app.run(host="0.0.0.0", port=15018, debug=is_dev, use_reloader=is_dev)
