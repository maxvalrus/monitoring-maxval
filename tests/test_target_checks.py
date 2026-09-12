import asyncio

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from monitoring.checks.base import CheckOutcome
from monitoring.checks.registry import CheckerRegistry
from monitoring.db import Base
from monitoring.models import (
    AppSetting,
    CheckResult,
    CheckStatus,
    Incident,
    IncidentSourceKind,
    IncidentStatus,
    MonitorTarget,
    Site,
    TargetCheck,
    TargetCheckResult,
)
from monitoring.services.incidents import IncidentEventKind
from monitoring.services.monitoring import MonitoringService
from monitoring.services.target_checks import (
    check_execution_signature,
    ensure_primary_check,
    normalize_http_deep_fields,
)


class SequenceChecker:
    name = "sequence"

    def __init__(self, outcomes: list[CheckOutcome]) -> None:
        self.outcomes = outcomes
        self.targets = []

    async def check(self, target, timeout_seconds: float) -> CheckOutcome:
        self.targets.append((target, timeout_seconds))
        return self.outcomes.pop(0)


def _service(registry: CheckerRegistry | None = None) -> MonitoringService:
    return MonitoringService(
        registry or CheckerRegistry(), timeout_seconds=5, max_parallel_checks=4
    )


def _target(session: Session) -> MonitorTarget:
    target = MonitorTarget(
        site=Site(name="Центральный офис"),
        name="Server-01",
        checker_type="tcp",
        address="192.0.2.10",
        port=22,
        interval_seconds=300,
    )
    session.add_all(
        [
            target,
            AppSetting(
                key="failures_before_incident", value="2", description="Порог"
            ),
        ]
    )
    session.flush()
    ensure_primary_check(session, target)
    session.commit()
    return target


def test_primary_check_is_mirrored_without_changing_legacy_availability_history() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        target = _target(session)
        events = _service().save_result(
            session, target.id, CheckOutcome(CheckStatus.UP, 4.2, "TCP OK")
        )

        primary = session.query(TargetCheck).one()
        legacy_result = session.query(CheckResult).one()

        assert events == []
        assert primary.is_primary is True
        assert primary.name == "Основная доступность"
        assert primary.checker_type == target.checker_type
        assert primary.port == target.port
        assert session.query(TargetCheckResult).count() == 0
        assert legacy_result.target_id == target.id
        assert legacy_result.status == CheckStatus.UP


def test_secondary_check_has_independent_history_and_incident_lifecycle() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        target = _target(session)
        ensure_primary_check(session, target)
        check = TargetCheck(
            target_id=target.id,
            name="1С",
            checker_type="tcp",
            port=1541,
            enabled=True,
            is_primary=False,
            display_order=1,
        )
        session.add(check)
        session.commit()
        service = _service()

        first = service.save_target_check_result(
            session,
            target.id,
            check.id,
            CheckOutcome(CheckStatus.DOWN, message="connection refused"),
        )
        opened = service.save_target_check_result(
            session,
            target.id,
            check.id,
            CheckOutcome(CheckStatus.DOWN, message="connection refused"),
        )

        incident = session.query(Incident).one()
        assert first == []
        assert [event.kind for event in opened] == [IncidentEventKind.OPENED]
        assert incident.source_kind == IncidentSourceKind.CHECK
        assert incident.check_id == check.id
        assert incident.status == IncidentStatus.OPEN
        assert incident.severity == "critical"
        assert "1С" in (incident.last_message or "")
        assert session.query(CheckResult).count() == 0
        assert session.query(TargetCheckResult).count() == 2

        recovered = service.save_target_check_result(
            session,
            target.id,
            check.id,
            CheckOutcome(CheckStatus.UP, 8.0, "connected"),
        )
        session.refresh(incident)
        assert [event.kind for event in recovered] == [IncidentEventKind.RECOVERED]
        assert incident.status == IncidentStatus.RESOLVED


def test_secondary_check_retries_and_uses_override_path_and_timeout() -> None:
    checker = SequenceChecker(
        [
            CheckOutcome(CheckStatus.DOWN, message="timeout"),
            CheckOutcome(CheckStatus.UP, latency_ms=12.0, message="HTTP 200"),
        ]
    )
    registry = CheckerRegistry()
    registry.register(checker)
    service = _service(registry)
    target = MonitorTarget(
        site_id=1,
        name="Server-01",
        address="192.0.2.10",
        port=22,
    )
    check = TargetCheck(
        target_id=1,
        name="Web",
        checker_type="sequence",
        address_override="service.example.test",
        port=8443,
        path="/health",
        timeout_seconds=2.5,
        retries=1,
        enabled=True,
        is_primary=False,
    )

    outcome = asyncio.run(service.check_target_check(target, check))

    assert outcome.status == CheckStatus.UP
    assert len(checker.targets) == 2
    request_target, timeout = checker.targets[-1]
    assert request_target.address == "service.example.test"
    assert request_target.port == 8443
    assert request_target.path == "/health"
    assert timeout == 2.5


def test_secondary_http_check_passes_deep_options_and_non_http_ignores_them() -> None:
    http_checker = SequenceChecker([CheckOutcome(CheckStatus.UP)])
    http_checker.name = "http"
    tcp_checker = SequenceChecker([CheckOutcome(CheckStatus.UP)])
    registry = CheckerRegistry()
    registry.register(http_checker)
    registry.register(tcp_checker)
    service = _service(registry)
    target = MonitorTarget(site_id=1, name="Server-01", address="192.0.2.10", port=22)
    http_check = TargetCheck(
        target_id=1,
        name="Web",
        checker_type="http",
        port=80,
        retries=0,
        enabled=True,
        is_primary=False,
        http_expected_status=200,
        http_content_contains="ready",
        http_content_not_contains="error",
        http_max_response_ms=100.0,
    )
    tcp_check = TargetCheck(
        target_id=1,
        name="TCP",
        checker_type="sequence",
        port=443,
        retries=0,
        enabled=True,
        is_primary=False,
        http_expected_status=200,
        http_content_contains="ready",
        http_content_not_contains="error",
        http_max_response_ms=100.0,
    )

    asyncio.run(service.check_target_check(target, http_check))
    asyncio.run(service.check_target_check(target, tcp_check))

    http_target, _ = http_checker.targets[0]
    tcp_target, _ = tcp_checker.targets[0]
    assert http_target.http_expected_status == 200
    assert http_target.http_content_contains == "ready"
    assert http_target.http_content_not_contains == "error"
    assert http_target.http_max_response_ms == 100.0
    assert tcp_target.http_expected_status is None
    assert tcp_target.http_content_contains is None
    assert tcp_target.http_content_not_contains is None
    assert tcp_target.http_max_response_ms is None


def test_http_deep_fields_normalize_and_change_execution_signature() -> None:
    assert normalize_http_deep_fields(
        checker_type="tcp",
        expected_status=200,
        content_contains="ready",
        content_not_contains="error",
        max_response_ms=100.0,
    ) == (None, None, None, None)
    with pytest.raises(ValueError, match="100–599"):
        normalize_http_deep_fields(
            checker_type="http",
            expected_status=99,
            content_contains=None,
            content_not_contains=None,
            max_response_ms=None,
        )
    check = TargetCheck(target_id=1, name="Web", checker_type="https", port=443)
    before = check_execution_signature(check)
    check.http_content_contains = "ready"
    assert check_execution_signature(check) != before


def test_scheduler_runs_secondary_checks_only_after_primary_success() -> None:
    from monitoring.services.scheduler import CheckScheduler, ScheduledTarget

    class FakeMonitoring:
        max_parallel_checks = 4

        def __init__(self, primary_status: CheckStatus) -> None:
            self.primary_status = primary_status
            self.secondary_calls: list[int] = []

        async def check_target(self, target: MonitorTarget) -> CheckOutcome:
            return CheckOutcome(self.primary_status, 1.0, "primary")

        async def check_target_check(
            self, target: MonitorTarget, check: TargetCheck
        ) -> CheckOutcome:
            self.secondary_calls.append(check.id)
            return CheckOutcome(CheckStatus.UP, 2.0, "secondary")

    target = MonitorTarget(
        id=10,
        site_id=1,
        name="Server-01",
        checker_type="icmp",
        address="192.0.2.10",
        port=1,
        interval_seconds=300,
    )
    secondary = TargetCheck(
        id=20,
        target_id=target.id,
        name="1С",
        checker_type="tcp",
        port=1541,
        enabled=True,
        is_primary=False,
    )

    async def run_case(primary_status: CheckStatus) -> list[int]:
        monitoring = FakeMonitoring(primary_status)
        scheduler = CheckScheduler(monitoring, poll_seconds=5)
        scheduler._save_result = lambda _target_id, _outcome: []  # type: ignore[method-assign]
        scheduler._save_target_check_result = (  # type: ignore[method-assign]
            lambda _target_id, _check_id, _config_version, _outcome: []
        )
        await scheduler._check_and_save(ScheduledTarget(target, (secondary,)))
        return monitoring.secondary_calls

    assert asyncio.run(run_case(CheckStatus.DOWN)) == []
    assert asyncio.run(run_case(CheckStatus.UP)) == [secondary.id]


def test_reconfigured_check_uses_fresh_failure_confirmation_and_discards_stale_result() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        target = _target(session)
        check = TargetCheck(
            target_id=target.id,
            name="1С",
            checker_type="tcp",
            port=1541,
            enabled=True,
            is_primary=False,
            display_order=1,
            config_version=1,
        )
        session.add(check)
        session.commit()
        service = _service()

        first = service.save_target_check_result(
            session,
            target.id,
            check.id,
            CheckOutcome(CheckStatus.DOWN, message="old endpoint down"),
            expected_config_version=1,
        )
        assert first == []
        assert session.query(TargetCheckResult).count() == 1

        check.port = 1542
        check.config_version = 2
        check.unstable_pending_down = False
        session.commit()

        stale = service.save_target_check_result(
            session,
            target.id,
            check.id,
            CheckOutcome(CheckStatus.DOWN, message="stale old endpoint result"),
            expected_config_version=1,
        )
        assert stale == []
        assert session.query(TargetCheckResult).count() == 1
        assert check.unstable_pending_down is False
        assert check.unstable_until is None

        new_first = service.save_target_check_result(
            session,
            target.id,
            check.id,
            CheckOutcome(CheckStatus.DOWN, message="new endpoint down"),
            expected_config_version=2,
        )
        assert new_first == []
        assert session.query(Incident).count() == 0

        opened = service.save_target_check_result(
            session,
            target.id,
            check.id,
            CheckOutcome(CheckStatus.DOWN, message="new endpoint down"),
            expected_config_version=2,
        )
        assert [event.kind for event in opened] == [IncidentEventKind.OPENED]
        incident = session.query(Incident).one()
        assert incident.status == IncidentStatus.OPEN
        versions = [
            row.config_version
            for row in session.query(TargetCheckResult).order_by(TargetCheckResult.id)
        ]
        assert versions == [1, 2, 2]


def test_deleted_check_result_from_scheduler_race_is_ignored() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        target = _target(session)
        check = TargetCheck(
            target_id=target.id,
            name="SSH",
            checker_type="tcp",
            port=22,
            enabled=True,
            is_primary=False,
            display_order=1,
            config_version=1,
        )
        session.add(check)
        session.commit()
        check_id = check.id
        session.delete(check)
        session.commit()

        events = _service().save_target_check_result(
            session,
            target.id,
            check_id,
            CheckOutcome(CheckStatus.DOWN, message="late result"),
            expected_config_version=1,
        )

        assert events == []
        assert session.query(TargetCheckResult).count() == 0
        assert session.query(Incident).count() == 0
