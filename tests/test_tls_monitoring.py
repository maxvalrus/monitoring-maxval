from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from monitoring.checks.base import CheckOutcome
from monitoring.checks.registry import CheckerRegistry
from monitoring.db import Base
from monitoring.models import (
    AppSetting,
    CheckStatus,
    Incident,
    IncidentSeverity,
    IncidentSourceKind,
    IncidentStatus,
    MonitorTarget,
    Site,
    TargetCheck,
)
from monitoring.services.monitoring import MonitoringService
from monitoring.services.target_checks import normalize_tls_monitoring
from monitoring.services.target_health import TargetHealthState, get_targets_health
from monitoring.services.tls_monitoring import TlsHealth, evaluate_tls_certificate

NOW = datetime(2026, 9, 1, 10, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("days", "expected"),
    [
        (31, TlsHealth.OK),
        (30, TlsHealth.WARNING),
        (8, TlsHealth.WARNING),
        (7, TlsHealth.CRITICAL),
        (0, TlsHealth.CRITICAL),
        (-1, TlsHealth.CRITICAL),
    ],
)
def test_tls_evaluation_uses_exact_expiry_thresholds(days: int, expected: TlsHealth) -> None:
    result = evaluate_tls_certificate(
        not_after=NOW + timedelta(days=days),
        warning_days=30,
        critical_days=7,
        now=NOW,
    )
    assert result.health is expected


def test_tls_evaluation_does_not_round_before_comparison() -> None:
    result = evaluate_tls_certificate(
        not_after=NOW + timedelta(days=7, seconds=1),
        warning_days=30,
        critical_days=7,
        now=NOW,
    )
    assert result.health is TlsHealth.WARNING


@pytest.mark.parametrize(
    ("warning", "critical"), [(0, 0), (7, 7), (6, 7), (30, -1)]
)
def test_tls_validation_rejects_invalid_thresholds(warning: int, critical: int) -> None:
    with pytest.raises(ValueError):
        normalize_tls_monitoring(
            checker_type="https",
            enabled=True,
            warning_days=warning,
            critical_days=critical,
        )


def _service() -> MonitoringService:
    return MonitoringService(CheckerRegistry(), timeout_seconds=5, max_parallel_checks=2)


def test_tls_expiry_lifecycle_keeps_https_up_and_updates_same_incident() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        target = MonitorTarget(
            site=Site(name="Web"),
            name="Portal",
            checker_type="tcp",
            address="example.test",
            port=443,
            interval_seconds=300,
        )
        check = TargetCheck(
            target=target,
            name="HTTPS",
            checker_type="https",
            port=443,
            enabled=True,
            is_primary=False,
            tls_monitor_enabled=True,
            tls_warning_days=30,
            tls_critical_days=7,
        )
        session.add_all([target, check, AppSetting(key="failures_before_incident", value="2")])
        session.commit()

        warning = _service().save_target_check_result(
            session,
            target.id,
            check.id,
            CheckOutcome(
                CheckStatus.UP,
                15.0,
                "HTTPS 200",
                datetime.now(UTC) + timedelta(days=20),
            ),
        )
        incident = session.scalar(
            select(Incident).where(
                Incident.source_kind == IncidentSourceKind.CHECK_TLS
            )
        )
        assert incident is not None
        assert incident.status == IncidentStatus.OPEN
        assert incident.severity == IncidentSeverity.WARNING
        assert len(warning) == 1

        critical = _service().save_target_check_result(
            session,
            target.id,
            check.id,
            CheckOutcome(
                CheckStatus.UP,
                15.0,
                "HTTPS 200",
                datetime.now(UTC) + timedelta(days=5),
            ),
        )
        session.refresh(incident)
        assert incident.severity == IncidentSeverity.CRITICAL
        assert len(critical) == 1
        assert session.query(Incident).count() == 1
        health = get_targets_health(session, {target.id: "up"})[target.id]
        assert health.state == TargetHealthState.CRITICAL
        assert health.reason_kind == "tls"

        downgraded = _service().save_target_check_result(
            session,
            target.id,
            check.id,
            CheckOutcome(
                CheckStatus.UP,
                15.0,
                "HTTPS 200",
                datetime.now(UTC) + timedelta(days=20),
            ),
        )
        session.refresh(incident)
        assert incident.severity == IncidentSeverity.WARNING
        assert downgraded == []
        assert session.query(Incident).count() == 1

        recovered = _service().save_target_check_result(
            session,
            target.id,
            check.id,
            CheckOutcome(
                CheckStatus.UP,
                15.0,
                "HTTPS 200",
                datetime.now(UTC) + timedelta(days=90),
            ),
        )
        session.refresh(incident)
        assert incident.status == IncidentStatus.RESOLVED
        assert len(recovered) == 1


def test_https_down_without_fresh_certificate_metadata_keeps_tls_incident_open() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        target = MonitorTarget(
            site=Site(name="Web"),
            name="Portal",
            checker_type="tcp",
            address="example.test",
            port=443,
        )
        check = TargetCheck(
            target=target,
            name="HTTPS",
            checker_type="https",
            port=443,
            enabled=True,
            is_primary=False,
            tls_monitor_enabled=True,
            tls_warning_days=30,
            tls_critical_days=7,
        )
        session.add_all([target, check])
        session.commit()
        service = _service()
        service.save_target_check_result(
            session,
            target.id,
            check.id,
            CheckOutcome(
                CheckStatus.UP,
                tls_not_after=datetime.now(UTC) + timedelta(days=5),
            ),
        )
        service.save_target_check_result(
            session,
            target.id,
            check.id,
            CheckOutcome(CheckStatus.DOWN, message="TLS verify failed"),
        )
        incident = session.scalar(
            select(Incident).where(
                Incident.source_kind == IncidentSourceKind.CHECK_TLS
            )
        )
        assert incident is not None
        assert incident.status == IncidentStatus.OPEN
