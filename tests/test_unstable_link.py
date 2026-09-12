from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from monitoring.checks.base import CheckOutcome
from monitoring.checks.registry import CheckerRegistry
from monitoring.db import Base
from monitoring.models import AppSetting, CheckStatus, Incident, MonitorTarget, Site, TargetCheck
from monitoring.services.monitoring import MonitoringService
from monitoring.services.unstable_link import UNSTABLE_LINK_TTL_MINUTES, unstable_link_active


def _service() -> MonitoringService:
    return MonitoringService(CheckerRegistry(), timeout_seconds=1, max_parallel_checks=1)


def _target(session: Session) -> tuple[MonitorTarget, TargetCheck]:
    target = MonitorTarget(
        site=Site(name="Площадка"), name="Объект", address="192.0.2.10", port=443
    )
    check = TargetCheck(
        target=target,
        name="Web",
        checker_type="https",
        port=443,
        is_primary=False,
        display_order=1,
    )
    session.add_all(
        (
            target,
            check,
            AppSetting(key="failures_before_incident", value="2", description="Тест"),
        )
    )
    session.commit()
    return target, check


def test_primary_unconfirmed_down_then_up_marks_unstable_link() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        target, _check = _target(session)
        service = _service()

        service.save_result(session, target.id, CheckOutcome(CheckStatus.DOWN, message="timeout"))
        assert target.unstable_pending_down is True
        service.save_result(session, target.id, CheckOutcome(CheckStatus.UP, message="ok"))

        assert target.unstable_pending_down is False
        assert unstable_link_active(target)
        assert session.query(Incident).count() == 0


def test_confirmed_primary_outage_recovery_does_not_mark_unstable_link() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        target, _check = _target(session)
        service = _service()

        service.save_result(session, target.id, CheckOutcome(CheckStatus.DOWN))
        service.save_result(session, target.id, CheckOutcome(CheckStatus.DOWN))
        assert target.unstable_until is None
        service.save_result(session, target.id, CheckOutcome(CheckStatus.UP))

        assert target.unstable_until is None


def test_secondary_unconfirmed_down_then_up_marks_and_extends_unstable_link() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        target, check = _target(session)
        service = _service()

        service.save_target_check_result(
            session, target.id, check.id, CheckOutcome(CheckStatus.DOWN)
        )
        service.save_target_check_result(session, target.id, check.id, CheckOutcome(CheckStatus.UP))
        first_until = check.unstable_until
        assert first_until is not None and unstable_link_active(check)

        service.save_target_check_result(
            session, target.id, check.id, CheckOutcome(CheckStatus.DOWN)
        )
        service.save_target_check_result(session, target.id, check.id, CheckOutcome(CheckStatus.UP))
        assert check.unstable_until is not None
        assert check.unstable_until >= first_until


def test_unknown_and_expired_marker_do_not_make_unstable_link_active() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        target, _check = _target(session)
        service = _service()

        service.save_result(session, target.id, CheckOutcome(CheckStatus.UNKNOWN))
        assert target.unstable_pending_down is False
        target.unstable_until = datetime.now(UTC) - timedelta(minutes=1)
        assert unstable_link_active(target) is False
        assert UNSTABLE_LINK_TTL_MINUTES == 60
