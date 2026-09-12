from __future__ import annotations

import hashlib

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from monitoring.checks.registry import CheckerRegistry
from monitoring.models import MonitorTarget, TargetCheck
from monitoring.services.directory_monitoring import DIRECTORY_CHECKER_TYPE
from monitoring.services.dns_monitoring import DNS_CHECKER_TYPE

MAX_CHECKS_PER_TARGET = 16
PRIMARY_CHECK_NAME = "Основная доступность"


def primary_checker_names(registry: CheckerRegistry) -> tuple[str, ...]:
    """DNS is an optional service and is deliberately never a target primary check."""
    return tuple(name for name in registry.names if name != DNS_CHECKER_TYPE)


def secondary_checker_names(registry: CheckerRegistry) -> tuple[str, ...]:
    return tuple((*registry.names, DIRECTORY_CHECKER_TYPE))


def normalize_check_fields(
    registry: CheckerRegistry,
    *,
    name: str,
    checker_type: str,
    address_override: str | None,
    port: int | None,
    path: str | None,
    timeout_seconds: float | None,
    retries: int,
) -> tuple[str, str, str | None, int, str, float | None, int]:
    clean_name = name.strip()
    if not 2 <= len(clean_name) <= 160:
        raise ValueError("Название проверки должно содержать от 2 до 160 символов")
    if checker_type not in secondary_checker_names(registry):
        raise ValueError("Неизвестный тип проверки")

    clean_address = (address_override or "").strip() or None
    if clean_address is not None and (
        len(clean_address) > 255 or any(char.isspace() for char in clean_address)
    ):
        raise ValueError("Адрес проверки должен быть IP/DNS без пробелов")

    if checker_type == DIRECTORY_CHECKER_TYPE:
        clean_address = None
        clean_port = 1
    elif checker_type == DNS_CHECKER_TYPE:
        clean_address = None
        clean_port = 53
    elif checker_type == "icmp":
        clean_port = 1
    elif port is None and checker_type == "http":
        clean_port = 80
    elif port is None and checker_type == "https":
        clean_port = 443
    elif port is None and checker_type == "rtsp":
        clean_port = 554
    elif port is None:
        raise ValueError("Укажите порт для выбранной проверки")
    else:
        clean_port = int(port)
    if not 1 <= clean_port <= 65535:
        raise ValueError("Порт должен быть в диапазоне 1–65535")

    clean_path = (path or "/").strip() or "/"
    if len(clean_path) > 500:
        raise ValueError("Путь проверки не должен превышать 500 символов")
    if checker_type in {"http", "https"} and not clean_path.startswith("/"):
        clean_path = f"/{clean_path}"
    elif checker_type not in {"http", "https"}:
        clean_path = "/"

    clean_timeout = None if timeout_seconds is None else float(timeout_seconds)
    if clean_timeout is not None and not 0.5 <= clean_timeout <= 60:
        raise ValueError("Timeout должен быть в диапазоне 0.5–60 секунд")
    clean_retries = int(retries)
    if not 0 <= clean_retries <= 10:
        raise ValueError("Количество повторов должно быть в диапазоне 0–10")
    return (
        clean_name,
        checker_type,
        clean_address,
        clean_port,
        clean_path,
        clean_timeout,
        clean_retries,
    )


def normalize_http_deep_fields(
    *,
    checker_type: str,
    expected_status: int | None,
    content_contains: str | None,
    content_not_contains: str | None,
    max_response_ms: float | None,
) -> tuple[int | None, str | None, str | None, float | None]:
    """Normalize optional HTTP/HTTPS criteria and clear them for other checks."""
    if checker_type not in {"http", "https"}:
        return None, None, None, None
    if expected_status is not None and not 100 <= expected_status <= 599:
        raise ValueError("Ожидаемый HTTP-код должен быть в диапазоне 100–599")
    clean_contains = (content_contains or "").strip() or None
    clean_not_contains = (content_not_contains or "").strip() or None
    if clean_contains is not None and len(clean_contains) > 500:
        raise ValueError("Строка «Должно содержать» не должна превышать 500 символов")
    if clean_not_contains is not None and len(clean_not_contains) > 500:
        raise ValueError("Строка «Не должно содержать» не должна превышать 500 символов")
    if max_response_ms is not None and max_response_ms <= 0:
        raise ValueError("Максимальное время ответа должно быть больше 0 мс")
    return expected_status, clean_contains, clean_not_contains, max_response_ms


def normalize_tls_monitoring(
    *,
    checker_type: str,
    enabled: bool,
    warning_days: int | None,
    critical_days: int | None,
) -> tuple[bool, int | None, int | None]:
    """Normalize optional HTTPS certificate-expiry monitoring settings."""
    if checker_type != "https" or not enabled:
        return False, None, None
    warning = 30 if warning_days is None else int(warning_days)
    critical = 7 if critical_days is None else int(critical_days)
    if warning <= 0:
        raise ValueError("Warning-порог TLS должен быть больше 0 дней")
    if critical < 0:
        raise ValueError("Critical-порог TLS не может быть отрицательным")
    if warning <= critical:
        raise ValueError("Warning-порог TLS должен быть больше Critical-порога")
    return True, warning, critical


def ensure_primary_check(session: Session, target: MonitorTarget) -> TargetCheck:
    primary = session.scalar(
        select(TargetCheck).where(
            TargetCheck.target_id == target.id,
            TargetCheck.is_primary.is_(True),
        )
    )
    if primary is None:
        primary = TargetCheck(
            target_id=target.id,
            name=PRIMARY_CHECK_NAME,
            checker_type=target.checker_type,
            address_override=None,
            port=target.port,
            path="/",
            timeout_seconds=None,
            retries=0,
            enabled=True,
            is_primary=True,
            display_order=0,
        )
        session.add(primary)
        session.flush()
        return primary
    sync_primary_check(primary, target)
    return primary


def sync_primary_check(primary: TargetCheck, target: MonitorTarget) -> None:
    primary.name = PRIMARY_CHECK_NAME
    primary.checker_type = target.checker_type
    primary.address_override = None
    primary.port = target.port
    primary.path = "/"
    primary.timeout_seconds = None
    primary.retries = 0
    primary.enabled = True
    primary.is_primary = True
    primary.display_order = 0


def sync_target_primary_check(session: Session, target: MonitorTarget) -> TargetCheck:
    return ensure_primary_check(session, target)


def next_check_display_order(session: Session, target_id: int) -> int:
    current = session.scalar(
        select(func.max(TargetCheck.display_order)).where(TargetCheck.target_id == target_id)
    )
    return max(0, int(current or 0)) + 1


def ensure_check_capacity(session: Session, target_id: int) -> None:
    count = session.scalar(
        select(func.count(TargetCheck.id)).where(TargetCheck.target_id == target_id)
    ) or 0
    if count >= MAX_CHECKS_PER_TARGET:
        raise ValueError(f"На один объект можно добавить не более {MAX_CHECKS_PER_TARGET} проверок")


def duplicate_check_name_exists(
    session: Session,
    *,
    target_id: int,
    name: str,
    exclude_check_id: int | None = None,
) -> bool:
    query = select(TargetCheck.id).where(
        TargetCheck.target_id == target_id,
        func.lower(TargetCheck.name) == name.casefold(),
    )
    if exclude_check_id is not None:
        query = query.where(TargetCheck.id != exclude_check_id)
    return session.scalar(query.limit(1)) is not None


def check_execution_signature(check: TargetCheck) -> tuple[object, ...]:
    """Fields that define what endpoint/how a secondary check executes."""
    return (
        check.checker_type,
        check.address_override,
        check.port,
        check.path or "/",
        check.timeout_seconds,
        check.retries,
        check.http_expected_status,
        check.http_content_contains,
        check.http_content_not_contains,
        check.http_max_response_ms,
        check.tls_monitor_enabled,
        check.tls_warning_days,
        check.tls_critical_days,
        check.dns_name,
        check.dns_record_type,
        check.dns_expected_address,
        check.dns_max_response_ms,
        check.directory_path,
        check.directory_pattern,
        check.directory_period_hours,
        check.directory_show_last,
        check.directory_username,
        hashlib.sha256((check.directory_password_encrypted or "").encode()).hexdigest(),
    )
