import asyncio
import json
import os
import random
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib import error as urlerror
from urllib import request as urlrequest

import socks
from flask import g, redirect, render_template, request, url_for
from telethon import TelegramClient
from telethon.errors import PhoneCodeInvalidError, SessionPasswordNeededError
from telethon.sessions import StringSession

APP = None
USERDATA_DIR: Path | None = None
TG_DB_PATH: Path | None = None
LEGACY_TG_DB_PATH: Path | None = None

TG_TABLES = [
    "tg_accounts",
    "tg_dialogs",
    "tg_sign_tasks",
    "tg_auto_send_tasks",
    "tg_login_flows",
    "app_settings",
]

AUTO_SEND_JOB_ID = "auto_send_tick"
AUTO_BACKUP_JOB_ID = "auto_backup_daily"

UTC_PLUS_8 = timezone(timedelta(hours=8))


def setup(app, base_dir: Path) -> None:
    global APP, USERDATA_DIR, TG_DB_PATH, LEGACY_TG_DB_PATH
    APP = app
    APP.config["TELEGRAM_API_ID"] = os.environ.get("TELEGRAM_API_ID")
    APP.config["TELEGRAM_API_HASH"] = os.environ.get("TELEGRAM_API_HASH")
    USERDATA_DIR = base_dir / "userdata"
    USERDATA_DIR.mkdir(parents=True, exist_ok=True)
    TG_DB_PATH = USERDATA_DIR / "VpsHelper.db"
    LEGACY_TG_DB_PATH = USERDATA_DIR / "TgHelper.db"


def _require_setup() -> None:
    if APP is None or TG_DB_PATH is None:
        raise RuntimeError("TgHelper 未初始化，请先调用 setup(app, base_dir)")


def utc8_now() -> datetime:
    return datetime.now(timezone.utc).astimezone(UTC_PLUS_8)


def utc8_now_naive() -> datetime:
    return utc8_now().replace(tzinfo=None)


def utc8_now_iso() -> str:
    return utc8_now_naive().isoformat()


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


def get_tg_db():
    _require_setup()
    if "db" in g:
        return g.db
    if "tg_db" not in g:
        g.tg_db = sqlite3.connect(TG_DB_PATH)
        g.tg_db.row_factory = sqlite3.Row
    return g.tg_db


def migrate_legacy_tg_db(target_db: sqlite3.Connection) -> None:
    if LEGACY_TG_DB_PATH is None or TG_DB_PATH is None:
        return
    if LEGACY_TG_DB_PATH == TG_DB_PATH:
        return
    if not LEGACY_TG_DB_PATH.exists():
        return

    source_db = sqlite3.connect(LEGACY_TG_DB_PATH)
    source_db.row_factory = sqlite3.Row
    try:
        ensure_auto_send_table(source_db)
        existing_tables = {
            row["name"]
            for row in source_db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }

        for table in TG_TABLES:
            if table not in existing_tables:
                continue

            source_columns = [
                col["name"]
                for col in source_db.execute(f"PRAGMA table_info({table})").fetchall()
            ]
            if not source_columns:
                continue

            target_columns = {
                col["name"]
                for col in target_db.execute(f"PRAGMA table_info({table})").fetchall()
            }
            columns = [name for name in source_columns if name in target_columns]
            if not columns:
                continue

            column_sql = ", ".join(columns)
            placeholders = ", ".join(["?"] * len(columns))
            rows = source_db.execute(f"SELECT {column_sql} FROM {table}").fetchall()
            if not rows:
                continue

            target_db.executemany(
                f"INSERT OR IGNORE INTO {table} ({column_sql}) VALUES ({placeholders})",
                [tuple(row[column] for column in columns) for row in rows],
            )
    finally:
        source_db.close()


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


def init_tg_db() -> None:
    db = get_tg_db()
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

    migration_flag = db.execute(
        "SELECT value FROM app_settings WHERE key = 'tg_legacy_db_migrated'"
    ).fetchone()
    if not migration_flag:
        migrate_legacy_tg_db(db)
        db.execute(
            "INSERT OR REPLACE INTO app_settings (key, value) VALUES ('tg_legacy_db_migrated', '1')"
        )
    db.commit()


def get_configured_proxy():
    _require_setup()
    if not APP.config.get("PROXY_ENABLED"):
        return None

    host = APP.config.get("PROXY_HOST")
    port = APP.config.get("PROXY_PORT")
    if not host or not port:
        return None

    try:
        port_value = int(port)
    except ValueError:
        return None

    username = APP.config.get("PROXY_USERNAME")
    password = APP.config.get("PROXY_PASSWORD")
    if username or password:
        return (socks.SOCKS5, host, port_value, True, username, password)
    return (socks.SOCKS5, host, port_value, True)


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


async def send_tg_login_code(phone: str) -> tuple[bool, str | None, str | None, str | None]:
    _require_setup()
    api_id = APP.config.get("TELEGRAM_API_ID")
    api_hash = APP.config.get("TELEGRAM_API_HASH")
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
    _require_setup()
    api_id = APP.config.get("TELEGRAM_API_ID")
    api_hash = APP.config.get("TELEGRAM_API_HASH")
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
    _require_setup()
    api_id = APP.config.get("TELEGRAM_API_ID")
    api_hash = APP.config.get("TELEGRAM_API_HASH")
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


async def resolve_dialog_target(client: TelegramClient, dialog_id: str):
    async for dialog in client.iter_dialogs(limit=200):
        if str(dialog.id) == str(dialog_id):
            return dialog.entity

    try:
        return int(dialog_id)
    except ValueError:
        return dialog_id


async def send_and_fetch_reply(session_text: str, dialog_id: str, message: str) -> str | None:
    _require_setup()
    api_id = APP.config.get("TELEGRAM_API_ID")
    api_hash = APP.config.get("TELEGRAM_API_HASH")
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


def refresh_dialogs_for_account(account_id: int, session_text: str) -> None:
    dialogs = run_async(fetch_recent_dialogs(session_text))
    db = get_tg_db()
    db.execute("DELETE FROM tg_dialogs WHERE account_id = ?", (account_id,))
    for item in dialogs:
        db.execute(
            "INSERT INTO tg_dialogs (account_id, dialog_id, title, username, updated_at) VALUES (?, ?, ?, ?, ?)",
            (account_id, item["dialog_id"], item["title"], item["username"], datetime.utcnow().isoformat()),
        )
    db.commit()


def test_proxy_connection() -> tuple[bool, str]:
    proxy = get_configured_proxy()
    if not proxy:
        return False, "未配置代理。"

    _require_setup()
    api_id = APP.config.get("TELEGRAM_API_ID")
    api_hash = APP.config.get("TELEGRAM_API_HASH")
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
    _require_setup()
    db = get_tg_db()
    rows = db.execute(
        "SELECT key, value FROM app_settings WHERE key IN ('telegram_api_id', 'telegram_api_hash', 'proxy_enabled', 'proxy_host', 'proxy_port', 'proxy_username', 'proxy_password', 'cf_api_token', 'cf_account_id', 'cf_d1_database_name', 'cf_d1_database_id', 'cf_use_d1', 'db_auto_backup_enabled', 'db_auto_backup_time', 'db_auto_backup_last_date', 'db_auto_backup_last_result')"
    ).fetchall()
    data = {row["key"]: row["value"] for row in rows}
    APP.config["TELEGRAM_API_ID"] = APP.config.get("TELEGRAM_API_ID") or data.get("telegram_api_id")
    APP.config["TELEGRAM_API_HASH"] = APP.config.get("TELEGRAM_API_HASH") or data.get("telegram_api_hash")
    APP.config["PROXY_ENABLED"] = (
        data.get("proxy_enabled") == "1"
        if data.get("proxy_enabled") is not None
        else bool(data.get("proxy_host") and data.get("proxy_port"))
    )
    APP.config["PROXY_HOST"] = data.get("proxy_host")
    APP.config["PROXY_PORT"] = data.get("proxy_port")
    APP.config["PROXY_USERNAME"] = data.get("proxy_username")
    APP.config["PROXY_PASSWORD"] = data.get("proxy_password")
    APP.config["CF_API_TOKEN"] = data.get("cf_api_token")
    APP.config["CF_ACCOUNT_ID"] = data.get("cf_account_id")
    APP.config["CF_D1_DATABASE_NAME"] = data.get("cf_d1_database_name") or APP.config.get("APP_NAME", "VpsHelper")
    APP.config["CF_D1_DATABASE_ID"] = data.get("cf_d1_database_id")
    APP.config["CF_USE_D1"] = data.get("cf_use_d1") == "1"
    APP.config["DB_AUTO_BACKUP_ENABLED"] = data.get("db_auto_backup_enabled") == "1"
    APP.config["DB_AUTO_BACKUP_TIME"] = data.get("db_auto_backup_time") or "03:30"
    APP.config["DB_AUTO_BACKUP_LAST_DATE"] = data.get("db_auto_backup_last_date") or ""
    APP.config["DB_AUTO_BACKUP_LAST_RESULT"] = data.get("db_auto_backup_last_result") or ""


def cloudflare_request(api_token: str, method: str, url: str, payload: dict | None = None) -> dict:
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urlrequest.Request(url=url, data=data, method=method, headers=headers)
    try:
        with urlrequest.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urlerror.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="ignore")
        try:
            return json.loads(raw)
        except Exception:
            return {"success": False, "errors": [{"message": raw or str(exc)}]}
    except Exception as exc:
        return {"success": False, "errors": [{"message": str(exc)}]}


def cloudflare_create_d1(api_token: str, account_id: str, db_name: str) -> tuple[bool, str, str | None]:
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/d1/database"
    result = cloudflare_request(api_token, "POST", url, {"name": db_name})
    if result.get("success") and result.get("result"):
        db_id = result["result"].get("uuid") or result["result"].get("id")
        return True, "D1 数据库创建成功。", db_id
    errors = result.get("errors") or []
    msg = errors[0].get("message") if errors else "创建失败"
    return False, f"创建失败：{msg}", None


def cloudflare_get_first_account(api_token: str) -> tuple[bool, str, str | None]:
    url = "https://api.cloudflare.com/client/v4/accounts?page=1&per_page=1"
    result = cloudflare_request(api_token, "GET", url)
    if result.get("success") and isinstance(result.get("result"), list) and result["result"]:
        account_id = result["result"][0].get("id")
        if account_id:
            return True, "已获取账号。", account_id
    errors = result.get("errors") or []
    msg = errors[0].get("message") if errors else "无法获取账号"
    return False, f"获取账号失败：{msg}", None


def cloudflare_test_token(api_token: str) -> tuple[bool, str, str | None]:
    ok, msg, account_id = cloudflare_get_first_account(api_token)
    if not ok or not account_id:
        return False, msg, None
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/d1/database"
    result = cloudflare_request(api_token, "GET", url)
    if result.get("success"):
        return True, "Cloudflare API 可用。", account_id
    errors = result.get("errors") or []
    err = errors[0].get("message") if errors else "测试失败"
    return False, f"测试失败：{err}", account_id


def cloudflare_find_d1_by_name(api_token: str, account_id: str, db_name: str) -> tuple[bool, str, str | None]:
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/d1/database"
    result = cloudflare_request(api_token, "GET", url)
    if result.get("success") and isinstance(result.get("result"), list):
        for item in result["result"]:
            if item.get("name") == db_name:
                db_id = item.get("uuid") or item.get("id")
                if db_id:
                    return True, "已找到数据库。", db_id
        return False, "未找到数据库。", None
    errors = result.get("errors") or []
    msg = errors[0].get("message") if errors else "查询失败"
    return False, f"查询失败：{msg}", None


def cloudflare_d1_query(api_token: str, account_id: str, db_id: str, sql: str, params: list | None = None) -> tuple[bool, list, str]:
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/d1/database/{db_id}/query"
    payload = {"sql": sql}
    if params is not None:
        payload["params"] = params
    result = cloudflare_request(api_token, "POST", url, payload)
    if result.get("success"):
        statements = result.get("result") or []
        rows = []
        for st in statements:
            if isinstance(st, dict) and st.get("success", True):
                rows.extend(st.get("results") or [])
            elif isinstance(st, dict):
                err = st.get("error") or st.get("errors") or "query failed"
                return False, [], str(err)
        return True, rows, "ok"
    errors = result.get("errors") or []
    msg = errors[0].get("message") if errors else "query failed"
    return False, [], msg


def ensure_cloud_d1_schema(api_token: str, account_id: str, db_id: str, local_db: sqlite3.Connection) -> tuple[bool, str]:
    for table in TG_TABLES:
        row = local_db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name = ?",
            (table,),
        ).fetchone()
        if not row or not row[0]:
            continue
        ok, _, msg = cloudflare_d1_query(api_token, account_id, db_id, row[0])
        if not ok:
            lower_msg = (msg or "").lower()
            if "already exists" in lower_msg:
                continue
            return False, f"创建云端表失败({table})：{msg}"
    return True, "ok"


def backup_local_to_d1(api_token: str, account_id: str, db_id: str, local_db: sqlite3.Connection) -> tuple[bool, str]:
    ok, msg = ensure_cloud_d1_schema(api_token, account_id, db_id, local_db)
    if not ok:
        return False, msg

    for table in TG_TABLES:
        local_rows = local_db.execute(f"SELECT * FROM {table}").fetchall()
        ok, _, emsg = cloudflare_d1_query(api_token, account_id, db_id, f"DELETE FROM {table}")
        if not ok:
            return False, f"清空云端表失败({table})：{emsg}"

        if not local_rows:
            continue

        columns = local_rows[0].keys()
        placeholders = ",".join(["?"] * len(columns))
        sql = f"INSERT INTO {table} ({','.join(columns)}) VALUES ({placeholders})"
        for row in local_rows:
            params = [row[col] for col in columns]
            ok, _, emsg = cloudflare_d1_query(api_token, account_id, db_id, sql, params)
            if not ok:
                return False, f"写入云端失败({table})：{emsg}"

    return True, "本地数据库已备份到云端 D1。"


def pull_d1_to_local(api_token: str, account_id: str, db_id: str, local_db: sqlite3.Connection) -> tuple[bool, str]:
    ok, msg = ensure_cloud_d1_schema(api_token, account_id, db_id, local_db)
    if not ok:
        return False, msg

    for table in TG_TABLES:
        ok, rows, emsg = cloudflare_d1_query(api_token, account_id, db_id, f"SELECT * FROM {table}")
        if not ok:
            return False, f"读取云端失败({table})：{emsg}"

        local_db.execute(f"DELETE FROM {table}")
        if not rows:
            continue

        columns = list(rows[0].keys())
        placeholders = ",".join(["?"] * len(columns))
        sql = f"INSERT INTO {table} ({','.join(columns)}) VALUES ({placeholders})"
        for row in rows:
            local_db.execute(sql, [row.get(col) for col in columns])

    local_db.commit()
    return True, "云端 D1 数据已拉取到本地。"


def process_daily_cloud_backup(conn: sqlite3.Connection) -> None:
    settings_rows = conn.execute(
        "SELECT key, value FROM app_settings WHERE key IN ('db_auto_backup_enabled', 'db_auto_backup_time', 'db_auto_backup_last_date', 'cf_api_token', 'cf_account_id', 'cf_d1_database_id')"
    ).fetchall()
    settings = {row["key"]: row["value"] for row in settings_rows}

    if settings.get("db_auto_backup_enabled") != "1":
        return

    backup_time = settings.get("db_auto_backup_time") or "03:30"
    if ":" not in backup_time:
        return

    now = datetime.now()
    today = now.strftime("%Y-%m-%d")
    if settings.get("db_auto_backup_last_date") == today:
        return

    try:
        hh, mm = backup_time.split(":")
        target = now.replace(hour=int(hh), minute=int(mm), second=0, microsecond=0)
    except ValueError:
        return

    if now < target:
        return

    api_token = settings.get("cf_api_token") or ""
    account_id = settings.get("cf_account_id") or ""
    db_id = settings.get("cf_d1_database_id") or ""
    if not api_token or not account_id or not db_id:
        conn.execute(
            "INSERT OR REPLACE INTO app_settings (key, value) VALUES ('db_auto_backup_last_result', ?)",
            (f"{utc8_now_text()} 自动备份失败：Cloudflare 配置不完整",),
        )
        conn.commit()
        return

    ok, message = backup_local_to_d1(api_token, account_id, db_id, conn)
    conn.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES ('db_auto_backup_last_date', ?)", (today,))
    conn.execute(
        "INSERT OR REPLACE INTO app_settings (key, value) VALUES ('db_auto_backup_last_result', ?)",
        (f"{utc8_now_text()} {message}",),
    )
    conn.commit()


def schedule_next_run(interval_seconds: int, jitter_seconds: int, schedule_type: str, time_of_day: str | None) -> str:
    jitter = random.randint(0, max(jitter_seconds, 0))
    now = utc8_now_naive()

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
    _require_setup()
    conn = sqlite3.connect(TG_DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        now = utc8_now_iso()
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
                        utc8_now_iso(),
                        f"sent [{utc8_now_text()}]",
                        reply,
                        utc8_now_iso(),
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
                        utc8_now_iso(),
                        f"failed [{utc8_now_text()}]: {detail}",
                        utc8_now_iso(),
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


def run_auto_backup_job():
    _require_setup()
    conn = sqlite3.connect(TG_DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        process_daily_cloud_backup(conn)
    finally:
        conn.close()


def configure_scheduler_jobs(scheduler) -> None:
    from apscheduler.triggers.cron import CronTrigger

    tz = getattr(scheduler, "timezone", None)
    if scheduler.get_job(AUTO_SEND_JOB_ID) is None:
        scheduler.add_job(
            run_auto_send_job,
            CronTrigger(second="*/5", timezone=tz),
            id=AUTO_SEND_JOB_ID,
            replace_existing=True,
        )

    backup_time = APP.config.get("DB_AUTO_BACKUP_TIME") or "03:30"
    hour = 3
    minute = 30
    if ":" in backup_time:
        try:
            hh, mm = backup_time.split(":")
            hour = int(hh)
            minute = int(mm)
        except ValueError:
            hour, minute = 3, 30

    if scheduler.get_job(AUTO_BACKUP_JOB_ID):
        scheduler.remove_job(AUTO_BACKUP_JOB_ID)
    scheduler.add_job(
        run_auto_backup_job,
        CronTrigger(hour=hour, minute=minute, timezone=tz),
        id=AUTO_BACKUP_JOB_ID,
        replace_existing=True,
    )


def register_routes(require_login, configure_scheduler_jobs_cb) -> None:
    _require_setup()

    def _format_countdown_text(next_run_at: str | None) -> tuple[str, str]:
        if not next_run_at:
            return "--", "未知"

        try:
            next_dt = datetime.fromisoformat(next_run_at)
        except ValueError:
            return next_run_at, "未知"

        if next_dt.tzinfo is not None:
            next_dt = next_dt.astimezone(UTC_PLUS_8).replace(tzinfo=None)
        display = next_dt.strftime("%Y-%m-%d %H:%M:%S UTC+8")
        delta_seconds = int((next_dt - utc8_now_naive()).total_seconds())
        if delta_seconds <= 0:
            return display, "即将执行"

        days, rem = divmod(delta_seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, seconds = divmod(rem, 60)

        parts = []
        if days > 0:
            parts.append(f"{days}天")
        if hours > 0:
            parts.append(f"{hours}小时")
        if minutes > 0:
            parts.append(f"{minutes}分钟")
        if not parts:
            parts.append(f"{seconds}秒")
        return display, "后执行（" + " ".join(parts) + "）"

    @APP.route("/tg_helper")
    def tg_helper():
        token = request.args.get("token")
        username = require_login()
        if not username:
            return redirect(url_for("login"))
        return render_template("tg_helper.html", username=username, token=token)

    @APP.route("/accounts/delete/<int:account_id>", methods=["POST"])
    def delete_account(account_id: int):
        username = require_login()
        if not username:
            return redirect(url_for("login"))

        token = request.form.get("token")
        db = get_tg_db()
        db.execute("DELETE FROM tg_accounts WHERE id = ? AND owner = ?", (account_id, username))
        db.commit()
        return redirect(url_for("accounts", token=token) if token else url_for("accounts"))

    @APP.route("/accounts")
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

    @APP.route("/settings/api", methods=["GET", "POST"])
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
            api_id=APP.config.get("TELEGRAM_API_ID") or "",
            api_hash=APP.config.get("TELEGRAM_API_HASH") or "",
            message=message,
        )

    @APP.route("/settings/proxy", methods=["GET", "POST"])
    def proxy_settings():
        token = request.args.get("token") or request.form.get("token")
        username = require_login()
        if not username:
            return redirect(url_for("login"))

        message = None
        if request.method == "POST":
            action = request.form.get("action")
            if action == "test":
                if not APP.config.get("PROXY_ENABLED"):
                    message = "当前未启用代理。"
                else:
                    ok, message = test_proxy_connection()
            else:
                proxy_enabled = request.form.get("proxy_enabled") == "on"
                proxy_host = request.form.get("proxy_host", "").strip()
                proxy_port = request.form.get("proxy_port", "").strip()
                proxy_username = request.form.get("proxy_username", "").strip()
                proxy_password = request.form.get("proxy_password", "").strip()

                if proxy_enabled and (not proxy_host or not proxy_port):
                    message = "启用代理时，代理地址与端口需同时填写。"
                elif (proxy_host and not proxy_port) or (proxy_port and not proxy_host):
                    message = "代理地址与端口需同时填写，或同时留空。"
                else:
                    db = get_tg_db()
                    db.execute(
                        "INSERT OR REPLACE INTO app_settings (key, value) VALUES ('proxy_enabled', ?)",
                        ("1" if proxy_enabled else "0",),
                    )
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
            proxy_enabled=APP.config.get("PROXY_ENABLED") or False,
            proxy_host=APP.config.get("PROXY_HOST") or "",
            proxy_port=APP.config.get("PROXY_PORT") or "",
            proxy_username=APP.config.get("PROXY_USERNAME") or "",
            proxy_password=APP.config.get("PROXY_PASSWORD") or "",
            message=message,
        )

    @APP.route("/settings/database", methods=["GET", "POST"])
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
            account_id = APP.config.get("CF_ACCOUNT_ID") or ""
            db_name = APP.config.get("APP_NAME", "VpsHelper")
            db_id = APP.config.get("CF_D1_DATABASE_ID") or ""
            use_d1 = APP.config.get("CF_USE_D1") or False

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
                            message = f"已找到云端数据库 {db_name}。"
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
                            message = f"未找到云端数据库 {db_name}，请先创建。"
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
                            message = f"未找到云端数据库 {db_name}，请先创建。"
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
                    if configure_scheduler_jobs_cb:
                        configure_scheduler_jobs_cb()
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
            cf_api_token=APP.config.get("CF_API_TOKEN") or "",
            cf_d1_database_name=APP.config.get("APP_NAME", "VpsHelper"),
            cf_d1_database_id=APP.config.get("CF_D1_DATABASE_ID") or "",
            cf_use_d1=APP.config.get("CF_USE_D1") or False,
            db_auto_backup_enabled=APP.config.get("DB_AUTO_BACKUP_ENABLED") or False,
            db_auto_backup_time=APP.config.get("DB_AUTO_BACKUP_TIME") or "03:30",
            db_auto_backup_last_result=APP.config.get("DB_AUTO_BACKUP_LAST_RESULT") or "",
        )

    @APP.route("/auto/send")
    def auto_send():
        token = request.args.get("token")
        username = require_login()
        if not username:
            return redirect(url_for("login"))
        return render_template("auto_send.html", token=token)

    @APP.route("/auto/reply")
    def auto_reply():
        token = request.args.get("token")
        username = require_login()
        if not username:
            return redirect(url_for("login"))
        return render_template("auto_reply.html", token=token)

    @APP.route("/auto/send/new")
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

    @APP.route("/auto/send/manage")
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
                       t.enabled, t.next_run_at, t.last_run_at, t.last_result, t.last_reply,
                       COALESCE(d.title, d.username, t.dialog_id) AS dialog_name
                FROM tg_auto_send_tasks t
                LEFT JOIN tg_dialogs d ON d.account_id = t.account_id AND d.dialog_id = t.dialog_id
                WHERE t.owner = ? AND t.account_id = ?
                ORDER BY t.id DESC
                """,
                (username, selected_account_id),
            ).fetchall()

        tasks_view = []
        for task in tasks:
            next_run_display, next_run_countdown = _format_countdown_text(task["next_run_at"])
            item = dict(task)
            item["next_run_display"] = next_run_display
            item["next_run_countdown"] = next_run_countdown
            tasks_view.append(item)

        queue_rows = db.execute(
            """
            SELECT t.id, t.account_id, t.dialog_id, t.next_run_at,
                   COALESCE(a.account_name, CAST(t.account_id AS TEXT)) AS account_name,
                   COALESCE(d.title, d.username, t.dialog_id) AS dialog_name
            FROM tg_auto_send_tasks t
            LEFT JOIN tg_accounts a ON a.id = t.account_id
            LEFT JOIN tg_dialogs d ON d.account_id = t.account_id AND d.dialog_id = t.dialog_id
            WHERE t.owner = ? AND t.enabled = 1
            ORDER BY t.next_run_at ASC
            """,
            (username,),
        ).fetchall()

        queue_tasks = []
        for row in queue_rows:
            next_run_display, next_run_countdown = _format_countdown_text(row["next_run_at"])
            item = dict(row)
            item["next_run_display"] = next_run_display
            item["next_run_countdown"] = next_run_countdown
            queue_tasks.append(item)

        return render_template(
            "auto_send_manage.html",
            token=token,
            accounts=accounts_list,
            selected_account_id=selected_account_id,
            tasks=tasks_view,
            queue_tasks=queue_tasks,
            error=request.args.get("error"),
            message=request.args.get("message"),
        )

    @APP.route("/auto/send/refresh", methods=["POST"])
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

    @APP.route("/auto/send/save", methods=["POST"])
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
        now_str = utc8_now_iso()
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

    @APP.route("/auto/send/delete/<int:task_id>", methods=["POST"])
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

    @APP.route("/auto/send/update/<int:task_id>", methods=["POST"])
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
            (message_text, time_of_day, jitter_value, interval_value, "daily", next_run, utc8_now_iso(), task_id, username),
        )
        db.commit()
        return redirect(
            url_for("auto_send_manage", token=token, account_id=account_id, message="任务内容与计划已更新。")
            if token
            else url_for("auto_send_manage", account_id=account_id, message="任务内容与计划已更新。")
        )

    @APP.route("/auto/send/run/<int:task_id>", methods=["POST"])
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
                (utc8_now_iso(), f"sent [{utc8_now_text()}]", reply, utc8_now_iso(), task_id),
            )
            db.commit()
            msg = "已发送。"
        except Exception as exc:
            detail = f"{exc.__class__.__name__}: {exc}" if str(exc) else exc.__class__.__name__
            db.execute(
                "UPDATE tg_auto_send_tasks SET last_run_at = ?, last_result = ?, updated_at = ? WHERE id = ?",
                (utc8_now_iso(), f"failed [{utc8_now_text()}]: {detail}", utc8_now_iso(), task_id),
            )
            db.commit()
            msg = "发送失败。"

        return redirect(
            url_for("auto_send_manage", token=token, account_id=account_id, message=msg)
            if token
            else url_for("auto_send_manage", account_id=account_id, message=msg)
        )

    @APP.route("/tg/login/start", methods=["POST"])
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

    @APP.route("/tg/login/verify", methods=["GET", "POST"])
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

    @APP.route("/tg/dialogs/refresh", methods=["POST"])
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

    @APP.route("/tg/sign/save", methods=["POST"])
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
