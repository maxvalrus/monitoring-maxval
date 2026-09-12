from datetime import UTC, datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.orm import Session

from monitoring.models import (
    AppSetting,
    AuditLog,
    CheckResult,
    SnmpInterfaceSample,
    SnmpSample,
    SnmpUpsEvent,
    SnmpUpsSample,
    TargetCheckResult,
    UserNotification,
)
from monitoring.services.system_metrics import cleanup_portal_metrics


def _setting_int(
    session: Session,
    key: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    setting = session.get(AppSetting, key)
    try:
        value = int(setting.value) if setting is not None else default
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


def cleanup_check_history(
    session: Session,
    *,
    now: datetime | None = None,
) -> int:
    retention_days = _setting_int(session, "history_retention_days", 90, 7, 3650)
    threshold = (now or datetime.now(UTC)) - timedelta(days=retention_days)
    result = session.execute(delete(CheckResult).where(CheckResult.checked_at < threshold))
    target_check_result = session.execute(
        delete(TargetCheckResult).where(TargetCheckResult.checked_at < threshold)
    )
    session.commit()
    return (result.rowcount or 0) + (target_check_result.rowcount or 0)


def cleanup_audit_log(
    session: Session,
    *,
    now: datetime | None = None,
) -> int:
    retention_days = _setting_int(session, "audit_retention_days", 7, 1, 3650)
    threshold = (now or datetime.now(UTC)) - timedelta(days=retention_days)
    result = session.execute(delete(AuditLog).where(AuditLog.created_at < threshold))
    session.commit()
    return result.rowcount or 0



def cleanup_user_notifications(
    session: Session,
    *,
    now: datetime | None = None,
) -> int:
    retention_days = _setting_int(session, "notification_retention_days", 30, 1, 3650)
    threshold = (now or datetime.now(UTC)) - timedelta(days=retention_days)
    result = session.execute(delete(UserNotification).where(UserNotification.created_at < threshold))
    session.commit()
    return result.rowcount or 0


def cleanup_snmp_samples(
    session: Session,
    *,
    now: datetime | None = None,
) -> int:
    retention_days = _setting_int(session, "snmp_sample_retention_days", 30, 7, 365)
    threshold = (now or datetime.now(UTC)) - timedelta(days=retention_days)
    metric_result = session.execute(delete(SnmpSample).where(SnmpSample.collected_at < threshold))
    interface_result = session.execute(
        delete(SnmpInterfaceSample).where(SnmpInterfaceSample.collected_at < threshold)
    )
    ups_result = session.execute(
        delete(SnmpUpsSample).where(SnmpUpsSample.collected_at < threshold)
    )
    ups_events_result = session.execute(
        delete(SnmpUpsEvent).where(SnmpUpsEvent.collected_at < threshold)
    )
    session.commit()
    return (
        (metric_result.rowcount or 0)
        + (interface_result.rowcount or 0)
        + (ups_result.rowcount or 0)
        + (ups_events_result.rowcount or 0)
    )


def cleanup_all_history(
    session: Session,
    *,
    now: datetime | None = None,
) -> tuple[int, int, int, int, int]:
    checks = cleanup_check_history(session, now=now)
    metrics = cleanup_portal_metrics(session, now=now)
    audit = cleanup_audit_log(session, now=now)
    notifications = cleanup_user_notifications(session, now=now)
    snmp_samples = cleanup_snmp_samples(session, now=now)
    return checks, metrics, audit, notifications, snmp_samples
