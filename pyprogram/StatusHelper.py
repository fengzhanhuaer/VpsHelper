import os
import shutil
import time
from pathlib import Path

from flask import jsonify, redirect, render_template, request, url_for

from pyprogram import TimeHelper

APP = None
_LAST_CPU_TOTAL = None
_LAST_CPU_IDLE = None
_PROCESS_START_EPOCH = time.time()


def setup(app, _base_dir: Path) -> None:
    global APP
    APP = app


def _require_setup() -> None:
    if APP is None:
        raise RuntimeError("StatusHelper 未初始化，请先调用 setup(app, base_dir)")


def _read_mem_stats() -> dict:
    mem_total = 0
    mem_available = 0
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as file:
            for line in file:
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1]) * 1024
                elif line.startswith("MemAvailable:"):
                    mem_available = int(line.split()[1]) * 1024
    except Exception:
        return {
            "total": 0,
            "used": 0,
            "free": 0,
            "usage_percent": 0,
        }

    used = max(mem_total - mem_available, 0)
    usage_percent = round((used / mem_total) * 100, 2) if mem_total else 0
    return {
        "total": mem_total,
        "used": used,
        "free": mem_available,
        "usage_percent": usage_percent,
    }


def _read_cpu_usage_percent() -> float:
    global _LAST_CPU_TOTAL, _LAST_CPU_IDLE

    try:
        with open("/proc/stat", "r", encoding="utf-8") as file:
            first = file.readline().strip()
    except Exception:
        return 0.0

    if not first.startswith("cpu "):
        return 0.0

    parts = first.split()[1:]
    if len(parts) < 4:
        return 0.0

    values = [int(x) for x in parts]
    total = sum(values)
    idle = values[3] + (values[4] if len(values) > 4 else 0)

    if _LAST_CPU_TOTAL is None or _LAST_CPU_IDLE is None:
        _LAST_CPU_TOTAL = total
        _LAST_CPU_IDLE = idle
        return 0.0

    total_diff = total - _LAST_CPU_TOTAL
    idle_diff = idle - _LAST_CPU_IDLE

    _LAST_CPU_TOTAL = total
    _LAST_CPU_IDLE = idle

    if total_diff <= 0:
        return 0.0

    usage = (1 - (idle_diff / total_diff)) * 100
    return round(max(0.0, min(usage, 100.0)), 2)


def _read_disk_stats() -> dict:
    try:
        usage = shutil.disk_usage("/")
    except Exception:
        return {
            "total": 0,
            "used": 0,
            "free": 0,
            "usage_percent": 0,
        }

    usage_percent = round((usage.used / usage.total) * 100, 2) if usage.total else 0
    return {
        "total": usage.total,
        "used": usage.used,
        "free": usage.free,
        "usage_percent": usage_percent,
    }


def _read_uptime_seconds() -> float | None:
    proc_path = Path("/proc/uptime")
    if proc_path.exists():
        try:
            raw = proc_path.read_text(encoding="utf-8").strip().split()[0]
            return float(raw)
        except Exception:
            return None
    return None


def _format_duration(seconds: float) -> str:
    total = max(int(seconds), 0)
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)

    parts: list[str] = []
    if days:
        parts.append(f"{days}天")
    if hours:
        parts.append(f"{hours}小时")
    if minutes:
        parts.append(f"{minutes}分钟")
    if not parts:
        parts.append(f"{secs}秒")
    return " ".join(parts)


def _collect_status_data() -> dict:
    tz_name = os.environ.get("VPSHELPER_TZ") or os.environ.get("TZ") or TimeHelper.DEFAULT_TZ_NAME
    now_value = TimeHelper.now()
    uptime_seconds = _read_uptime_seconds()
    if uptime_seconds is None:
        uptime_seconds = time.time() - _PROCESS_START_EPOCH
    uptime_text = _format_duration(uptime_seconds)

    return {
        "time": {
            "timezone": tz_name,
            "now": now_value.strftime("%Y-%m-%d %H:%M:%S"),
            "uptime": uptime_text,
        },
        "ram": _read_mem_stats(),
        "cpu": {
            "usage_percent": _read_cpu_usage_percent(),
        },
        "disk": _read_disk_stats(),
    }


def register_routes(require_login) -> None:
    _require_setup()

    @APP.route("/server/status")
    def server_status():
        username = require_login()
        if not username:
            return redirect(url_for("login"))

        status = _collect_status_data()
        return render_template("server_status.html", username=username, status=status)

    @APP.route("/server/status/data")
    def server_status_data():
        username = require_login()
        if not username:
            return jsonify({"ok": False, "message": "未登录或会话已过期。"}), 401

        return jsonify({"ok": True, "data": _collect_status_data()})
