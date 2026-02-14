import os
import time
from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None


DEFAULT_TZ_NAME = "Asia/Shanghai"
UTC_PLUS_8 = timezone(timedelta(hours=8))


def _looks_like_iana_name(value: str) -> bool:
    return "/" in value and " " not in value


def ensure_default_timezone() -> str:
    """Ensure process default timezone is UTC+8 when user didn't explicitly set one.

    Priority:
    - If `VPSHELPER_TZ` or `TZ` is already set: respect it.
    - Otherwise: set `TZ=Asia/Shanghai`.
    """

    if os.environ.get("VPSHELPER_TZ") or os.environ.get("TZ"):
        if hasattr(time, "tzset") and os.environ.get("TZ"):
            try:
                time.tzset()
            except Exception:
                pass
        return os.environ.get("VPSHELPER_TZ") or os.environ.get("TZ") or DEFAULT_TZ_NAME

    os.environ["TZ"] = DEFAULT_TZ_NAME
    if hasattr(time, "tzset"):
        try:
            time.tzset()
        except Exception:
            pass
    return DEFAULT_TZ_NAME


def get_apscheduler_timezone_name() -> str:
    """Timezone name for APScheduler.

    APScheduler works best with IANA names (e.g. Asia/Shanghai). If user sets a
    non-IANA `TZ` (like 'UTC+8'), fall back to default.
    """

    tz_value = os.environ.get("VPSHELPER_TZ") or os.environ.get("TZ")
    if tz_value and _looks_like_iana_name(tz_value):
        return tz_value
    return DEFAULT_TZ_NAME


def get_app_tzinfo():
    """Return tzinfo used by the app for timestamps & display.

    - If `VPSHELPER_TZ`/`TZ` is a valid IANA timezone and `zoneinfo` is available,
      use it.
    - Otherwise use fixed UTC+8.
    """

    tz_value = os.environ.get("VPSHELPER_TZ") or os.environ.get("TZ")
    if tz_value and ZoneInfo is not None and _looks_like_iana_name(tz_value):
        try:
            return ZoneInfo(tz_value)
        except Exception:
            pass
    return UTC_PLUS_8


def now() -> datetime:
    return datetime.now(get_app_tzinfo())


def now_naive() -> datetime:
    return now().replace(tzinfo=None)


def now_iso() -> str:
    return now_naive().isoformat()
