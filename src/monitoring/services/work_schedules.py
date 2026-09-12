from datetime import UTC, datetime, time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy.orm import Session

from monitoring.models import AppSetting, WorkSchedule

DAY_FIELDS = (
    ("monday", "Понедельник"),
    ("tuesday", "Вторник"),
    ("wednesday", "Среда"),
    ("thursday", "Четверг"),
    ("friday", "Пятница"),
    ("saturday", "Суббота"),
    ("sunday", "Воскресенье"),
)

DAY_ABBREVIATIONS = {
    "monday": "пн.",
    "tuesday": "вт.",
    "wednesday": "ср.",
    "thursday": "чт.",
    "friday": "пт.",
    "saturday": "сб.",
    "sunday": "вс.",
}


def schedule_timezone(session: Session) -> str:
    setting = session.get(AppSetting, "display_timezone")
    return setting.value if setting and setting.value else "Europe/Moscow"


def _parse_clock(value: str | None) -> time | None:
    if not value:
        return None
    try:
        hour, minute = (int(part) for part in value.split(":"))
        return time(hour=hour, minute=minute)
    except (TypeError, ValueError):
        return None


def schedule_is_working(
    schedule: WorkSchedule | None,
    at: datetime | None = None,
    timezone_name: str = "Europe/Moscow",
) -> bool:
    if schedule is None or schedule.is_24x7:
        return True
    try:
        timezone = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError:
        timezone = UTC
    moment = at or datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    local = moment.astimezone(timezone)
    current_time = local.time().replace(tzinfo=None)
    day_index = local.weekday()

    day_name = DAY_FIELDS[day_index][0]
    start = _parse_clock(getattr(schedule, f"{day_name}_start"))
    end = _parse_clock(getattr(schedule, f"{day_name}_end"))
    if start is not None and end is not None:
        if start < end and start <= current_time < end:
            return True
        if start > end and current_time >= start:
            return True

    previous_name = DAY_FIELDS[(day_index - 1) % 7][0]
    previous_start = _parse_clock(getattr(schedule, f"{previous_name}_start"))
    previous_end = _parse_clock(getattr(schedule, f"{previous_name}_end"))
    return (
        previous_start is not None
        and previous_end is not None
        and previous_start > previous_end
        and current_time < previous_end
    )


def validate_schedule_values(
    name: str,
    is_24x7: bool,
    values: dict[str, tuple[bool, str, str]],
) -> tuple[str, dict[str, str | None]]:
    clean_name = name.strip()
    if not 2 <= len(clean_name) <= 120:
        raise ValueError("Название графика должно содержать от 2 до 120 символов")
    cleaned: dict[str, str | None] = {}
    active_days = 0
    for field, label in DAY_FIELDS:
        enabled, raw_start, raw_end = values[field]
        if is_24x7 or not enabled:
            cleaned[f"{field}_start"] = None
            cleaned[f"{field}_end"] = None
            continue
        start = _parse_clock(raw_start)
        end = _parse_clock(raw_end)
        if start is None or end is None:
            raise ValueError(f"{label}: укажите корректное время начала и окончания")
        if start == end:
            raise ValueError(f"{label}: начало и окончание не должны совпадать")
        cleaned[f"{field}_start"] = start.strftime("%H:%M")
        cleaned[f"{field}_end"] = end.strftime("%H:%M")
        active_days += 1
    if not is_24x7 and active_days == 0:
        raise ValueError("Выберите хотя бы один рабочий день")
    return clean_name, cleaned


def schedule_summary(schedule: WorkSchedule) -> str:
    if schedule.is_24x7:
        return "Круглосуточно"
    parts: list[str] = []
    for field, _label in DAY_FIELDS:
        start = getattr(schedule, f"{field}_start")
        end = getattr(schedule, f"{field}_end")
        if start and end:
            parts.append(f"{DAY_ABBREVIATIONS[field]} {start}–{end}")
    return " · ".join(parts) if parts else "Нет рабочих дней"
