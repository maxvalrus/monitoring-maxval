from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from monitoring.db import Base
from monitoring.models import (
    CheckResult,
    Incident,
    MonitorTarget,
    Site,
    SnmpConfig,
    TargetCheck,
    TargetCheckResult,
)
from monitoring.models.mixins import utc_now
from monitoring.services.target_health import get_targets_health


def _engine():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine


def _target(session: Session):
    site = Site(name="Health")
    target = MonitorTarget(
        site=site,
        name="Server-01",
        address="192.0.2.10",
        port=22,
        checker_type="tcp",
    )
    session.add(target)
    session.flush()
    primary = TargetCheck(
        target_id=target.id,
        name="Основная доступность",
        checker_type="tcp",
        port=22,
        enabled=True,
        is_primary=True,
        display_order=0,
        config_version=1,
    )
    service = TargetCheck(
        target_id=target.id,
        name="1С",
        checker_type="tcp",
        port=1541,
        enabled=True,
        is_primary=False,
        display_order=1,
        config_version=1,
    )
    session.add_all((primary, service))
    session.flush()
    return target, primary, service


def _up_results(session: Session, target, service) -> None:
    session.add(
        CheckResult(
            target_id=target.id,
            status="up",
            latency_ms=2.0,
            message="ok",
        )
    )
    session.add(
        TargetCheckResult(
            check_id=service.id,
            config_version=service.config_version,
            status="up",
            latency_ms=3.0,
            message="ok",
        )
    )
    session.flush()


def test_health_is_ok_when_primary_and_service_are_healthy() -> None:
    engine = _engine()
    with Session(engine) as session:
        target, _primary, service = _target(session)
        _up_results(session, target, service)

        health = get_targets_health(session, {target.id: "up"})[target.id]

        assert health.state == "ok"
        assert health.reason is None
        assert health.services_ok == 1
        assert health.services_total == 1
        assert [item.status for item in health.services] == ["up", "up"]


def test_unstable_marker_is_runtime_only_and_hidden_while_primary_is_down() -> None:
    engine = _engine()
    with Session(engine) as session:
        target, _primary, service = _target(session)
        _up_results(session, target, service)
        target.unstable_until = utc_now().replace(year=utc_now().year + 1)
        service.unstable_until = target.unstable_until
        session.flush()

        healthy = get_targets_health(session, {target.id: "up"})[target.id]
        offline = get_targets_health(session, {target.id: "down"})[target.id]

        assert healthy.state == "ok"
        assert healthy.unstable is True
        assert healthy.services[1].unstable is True
        assert offline.state == "offline"
        assert offline.unstable is False
        assert offline.services[1].unstable is False


def test_open_service_incident_makes_online_target_critical() -> None:
    engine = _engine()
    with Session(engine) as session:
        target, _primary, service = _target(session)
        _up_results(session, target, service)
        session.add(
            Incident(
                target_id=target.id,
                check_id=service.id,
                status="open",
                source_kind="check",
                severity="critical",
                failure_count=2,
                last_message="1С: соединение не установлено",
            )
        )
        session.flush()

        health = get_targets_health(session, {target.id: "up"})[target.id]

        assert health.state == "critical"
        assert health.reason == "1С недоступен"
        assert health.reason_kind == "check"
        assert health.additional_problem_count == 0
        assert health.services_ok == 0
        assert health.services[1].status == "down"


def test_critical_problem_wins_and_additional_count_is_stable() -> None:
    engine = _engine()
    with Session(engine) as session:
        target, _primary, service = _target(session)
        _up_results(session, target, service)
        session.add_all(
            (
                Incident(
                    target_id=target.id,
                    status="open",
                    source_kind="snmp",
                    severity="warning",
                    failure_count=1,
                    last_message="Температура выше warning",
                ),
                Incident(
                    target_id=target.id,
                    check_id=service.id,
                    status="open",
                    source_kind="check",
                    severity="critical",
                    failure_count=2,
                    last_message="1С down",
                ),
            )
        )
        session.flush()

        health = get_targets_health(session, {target.id: "up"})[target.id]

        assert health.state == "critical"
        assert health.reason == "1С недоступен"
        assert health.additional_problem_count == 1


def test_offline_primary_overrides_stale_critical_problem() -> None:
    engine = _engine()
    with Session(engine) as session:
        target, _primary, service = _target(session)
        _up_results(session, target, service)
        session.add(
            Incident(
                target_id=target.id,
                check_id=service.id,
                status="open",
                source_kind="check",
                severity="critical",
                failure_count=2,
                last_message="1С down",
            )
        )
        session.flush()

        health = get_targets_health(session, {target.id: "down"})[target.id]

        assert health.state == "offline"
        assert health.reason_kind == "availability"
        assert health.additional_problem_count == 0
        assert health.services_ok is None
        assert health.services[1].status == "waiting_primary"


def test_snmp_warning_incident_makes_target_warning() -> None:
    engine = _engine()
    with Session(engine) as session:
        target, _primary, service = _target(session)
        _up_results(session, target, service)
        session.add(
            Incident(
                target_id=target.id,
                status="open",
                source_kind="snmp",
                severity="warning",
                failure_count=1,
                last_message="Black Toner: 18%",
            )
        )
        session.flush()

        health = get_targets_health(session, {target.id: "up"})[target.id]

        assert health.state == "warning"
        assert health.reason == "Black Toner: 18%"
        assert health.reason_kind == "snmp"


def test_disabled_and_unknown_are_not_overridden_by_old_incidents() -> None:
    engine = _engine()
    with Session(engine) as session:
        target, _primary, service = _target(session)
        _up_results(session, target, service)
        session.add(
            Incident(
                target_id=target.id,
                check_id=service.id,
                status="open",
                source_kind="check",
                severity="critical",
                failure_count=2,
                last_message="old",
            )
        )
        session.flush()

        unknown = get_targets_health(session, {target.id: "unknown"})[target.id]
        assert unknown.state == "unknown"
        assert unknown.reason is None

        target.enabled = False
        session.flush()
        disabled = get_targets_health(session, {target.id: "up"})[target.id]
        assert disabled.state == "disabled"
        assert disabled.reason is None


def test_old_secondary_result_after_config_change_is_not_current() -> None:
    engine = _engine()
    with Session(engine) as session:
        target, _primary, service = _target(session)
        session.add(CheckResult(target_id=target.id, status="up", message="ok"))
        session.add(
            TargetCheckResult(
                check_id=service.id,
                config_version=1,
                status="up",
                message="old config",
            )
        )
        service.config_version = 2
        session.flush()

        health = get_targets_health(session, {target.id: "up"})[target.id]

        assert health.state == "ok"
        assert health.services_ok == 0
        assert health.services_total == 1
        assert health.services[1].status == "unknown"
        assert health.services[1].checked_at is None


def test_disabled_service_stale_incident_does_not_make_target_critical() -> None:
    engine = _engine()
    with Session(engine) as session:
        target, _primary, service = _target(session)
        _up_results(session, target, service)
        service.enabled = False
        session.add(
            Incident(
                target_id=target.id,
                check_id=service.id,
                status="open",
                source_kind="check",
                severity="critical",
                failure_count=2,
                last_message="stale after administrative disable",
            )
        )
        session.flush()

        health = get_targets_health(session, {target.id: "up"})[target.id]

        assert health.state == "ok"
        assert health.reason is None
        assert health.services_total == 0
        assert health.services_ok == 0
        assert health.services[1].status == "disabled"


def test_off_hours_and_current_snmp_transport_error_are_distinct() -> None:
    engine = _engine()
    with Session(engine) as session:
        target, _primary, service = _target(session)
        _up_results(session, target, service)
        session.add(
            SnmpConfig(
                target_id=target.id,
                enabled=True,
                last_status="error",
                last_error="timeout",
            )
        )
        session.flush()

        warning = get_targets_health(session, {target.id: "up"})[target.id]
        assert warning.state == "warning"
        assert warning.reason == "SNMP недоступен"

        off_hours = get_targets_health(session, {target.id: "off_hours"})[target.id]
        assert off_hours.state == "off_hours"
        assert off_hours.reason is None


def test_batch_health_for_255_targets_has_no_per_target_queries() -> None:
    engine = _engine()
    with Session(engine) as session:
        site = Site(name="Batch health")
        targets = [
            MonitorTarget(
                site=site,
                name=f"Target-{index}",
                address=f"192.0.2.{index % 255 + 1}",
                port=22,
                checker_type="tcp",
            )
            for index in range(255)
        ]
        session.add_all(targets)
        session.flush()
        statements: list[str] = []

        def count_sql(_conn, _cursor, statement, _parameters, _context, _executemany):
            statements.append(statement)

        event.listen(engine, "before_cursor_execute", count_sql)
        try:
            health = get_targets_health(session, {target.id: "up" for target in targets})
        finally:
            event.remove(engine, "before_cursor_execute", count_sql)

        assert len(health) == 255
        # Site-entry gates add one batched query; query count remains constant at scale.
        assert len(statements) <= 7
