from collections.abc import Callable
from datetime import UTC, datetime
from functools import lru_cache
from zoneinfo import ZoneInfo

from sqlalchemy.orm import Session

from monitoring.models import AppSetting

DEFAULT_TIMEZONE = "Europe/Moscow"


@lru_cache(maxsize=16)
def _timezone(name: str) -> ZoneInfo:
    return ZoneInfo(name)


def in_timezone(value: datetime, timezone_name: str) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(_timezone(timezone_name))


def format_datetime(
    value: datetime,
    timezone_name: str,
    pattern: str = "%d.%m.%Y %H:%M:%S %Z",
) -> str:
    return in_timezone(value, timezone_name).strftime(pattern)


def display_timezone(session: Session) -> str:
    setting = session.get(AppSetting, "display_timezone")
    return setting.value if setting is not None else DEFAULT_TIMEZONE


def session_datetime_formatter(session: Session) -> Callable[[datetime, str], str]:
    timezone_name = display_timezone(session)

    def formatter(
        value: datetime,
        pattern: str = "%d.%m.%Y %H:%M:%S %Z",
    ) -> str:
        return format_datetime(value, timezone_name, pattern)

    return formatter
