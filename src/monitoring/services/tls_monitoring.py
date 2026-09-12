from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum


class TlsHealth(StrEnum):
    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class TlsEvaluation:
    health: TlsHealth
    days_remaining: float
    not_after: datetime


def evaluate_tls_certificate(
    *,
    not_after: datetime,
    warning_days: int,
    critical_days: int,
    now: datetime | None = None,
) -> TlsEvaluation:
    if warning_days <= 0:
        raise ValueError("Warning-порог TLS должен быть больше 0 дней")
    if critical_days < 0:
        raise ValueError("Critical-порог TLS не может быть отрицательным")
    if warning_days <= critical_days:
        raise ValueError("Warning-порог TLS должен быть больше Critical-порога")
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=UTC)
    seconds_remaining = (not_after - current).total_seconds()
    if seconds_remaining <= critical_days * 86400:
        health = TlsHealth.CRITICAL
    elif seconds_remaining <= warning_days * 86400:
        health = TlsHealth.WARNING
    else:
        health = TlsHealth.OK
    return TlsEvaluation(
        health=health,
        days_remaining=seconds_remaining / 86400.0,
        not_after=not_after,
    )


def tls_reason(evaluation: TlsEvaluation) -> str:
    if evaluation.days_remaining < 0:
        return f"TLS: сертификат просрочен на {max(1, int(abs(evaluation.days_remaining)))} дн."
    days = max(0, int(evaluation.days_remaining))
    if evaluation.health is TlsHealth.OK:
        return f"TLS: сертификат действителен ещё {days} дн."
    return f"TLS: сертификат истекает через {days} дн."
