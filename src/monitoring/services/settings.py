from dataclasses import dataclass
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy.orm import Session

from monitoring.models import AppSetting


@dataclass(frozen=True, slots=True)
class SettingRule:
    minimum: int | None = None
    maximum: int | None = None
    boolean: bool = False
    timezone: bool = False


EDITABLE_SETTINGS = {
    "default_check_interval_seconds": SettingRule(60, 86400),
    "failures_before_incident": SettingRule(1, 10),
    "history_retention_days": SettingRule(7, 3650),
    "target_history_max_results": SettingRule(100, 100000),
    "audit_retention_days": SettingRule(1, 3650),
    "notification_retention_days": SettingRule(1, 3650),
    "notifications_enabled": SettingRule(boolean=True),
    "min_password_length": SettingRule(3, 64),
    "display_timezone": SettingRule(timezone=True),
    "portal_metric_interval_seconds": SettingRule(60, 3600),
    "portal_metric_retention_hours": SettingRule(24, 8760),
    "snmp_sample_retention_days": SettingRule(7, 365),
    "snmp_sample_max_per_target": SettingRule(100, 100000),
    "https_enabled": SettingRule(boolean=True),
    "https_redirect_http": SettingRule(boolean=True),
    "tls_expiry_warning_enabled": SettingRule(boolean=True),
    "tls_expiry_warning_days": SettingRule(1, 365),
    "availability_warning_threshold_percent": SettingRule(0, 100),
    "availability_good_threshold_percent": SettingRule(0, 100),
}


def validate_setting(key: str, value: str) -> str:
    try:
        rule = EDITABLE_SETTINGS[key]
    except KeyError as exc:
        raise ValueError("Эту настройку нельзя изменять через веб-интерфейс") from exc
    normalized = value.strip().casefold()
    if rule.boolean:
        if normalized not in {"true", "false"}:
            raise ValueError("Ожидается значение true или false")
        return normalized
    if rule.timezone:
        timezone_name = value.strip()
        try:
            ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("Неизвестный часовой пояс IANA") from exc
        return timezone_name
    try:
        number = int(normalized)
    except ValueError as exc:
        raise ValueError("Ожидается целое число") from exc
    if rule.minimum is not None and number < rule.minimum:
        raise ValueError(f"Минимальное значение: {rule.minimum}")
    if rule.maximum is not None and number > rule.maximum:
        raise ValueError(f"Максимальное значение: {rule.maximum}")
    return str(number)


def update_setting(session: Session, key: str, value: str) -> AppSetting:
    normalized = validate_setting(key, value)
    setting = session.get(AppSetting, key)
    if setting is None:
        raise ValueError("Настройка не найдена")
    setting.value = normalized
    return setting
