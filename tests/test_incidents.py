import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from monitoring.checks.base import CheckOutcome
from monitoring.checks.registry import CheckerRegistry
from monitoring.db import Base
from monitoring.models import (
    AppSetting,
    CheckStatus,
    Incident,
    IncidentStatus,
    MonitorTarget,
    Site,
)
from monitoring.services.incidents import IncidentEventKind
from monitoring.services.monitoring import MonitoringService


def make_service() -> MonitoringService:
    return MonitoringService(CheckerRegistry(), timeout_seconds=1, max_parallel_checks=1)


def make_target(session: Session) -> MonitorTarget:
    target = MonitorTarget(
        site=Site(name="Филиал"),
        name="Камера входа",
        address="192.0.2.20",
        port=80,
    )
    session.add_all(
        [
            target,
            AppSetting(
                key="failures_before_incident",
                value="2",
                description="Порог",
            ),
            AppSetting(
                key="notifications_enabled",
                value="true",
                description="Почта",
            ),
        ]
    )
    session.commit()
    return target


def test_incident_opens_and_recovers_without_duplicate_notifications() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        target = make_target(session)
        service = make_service()

        first = service.save_result(
            session, target.id, CheckOutcome(status=CheckStatus.DOWN, message="timeout")
        )
        second = service.save_result(
            session, target.id, CheckOutcome(status=CheckStatus.DOWN, message="timeout")
        )
        repeated = service.save_result(
            session, target.id, CheckOutcome(status=CheckStatus.DOWN, message="still down")
        )

        incident = session.query(Incident).one()
        assert first == []
        assert [event.kind for event in second] == [IncidentEventKind.OPENED]
        assert repeated == []
        assert incident.status == IncidentStatus.OPEN
        assert incident.failure_count == 3

        recovered = service.save_result(
            session, target.id, CheckOutcome(status=CheckStatus.UP)
        )
        healthy_again = service.save_result(
            session, target.id, CheckOutcome(status=CheckStatus.UP)
        )
        session.refresh(incident)
        assert [event.kind for event in recovered] == [IncidentEventKind.RECOVERED]
        assert healthy_again == []
        assert incident.status == IncidentStatus.RESOLVED
        assert incident.resolved_at is not None


def test_unknown_result_breaks_failure_confirmation_sequence() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        target = make_target(session)
        service = make_service()

        service.save_result(session, target.id, CheckOutcome(status=CheckStatus.DOWN))
        service.save_result(session, target.id, CheckOutcome(status=CheckStatus.UNKNOWN))
        events = service.save_result(
            session, target.id, CheckOutcome(status=CheckStatus.DOWN)
        )

        assert events == []
        assert session.query(Incident).count() == 0


@pytest.mark.parametrize(
    ("target_suppressed", "notifications_enabled", "expect_internal_events"),
    [(True, True, False), (False, False, True)],
)
def test_notification_policy_does_not_block_incident_lifecycle(
    target_suppressed: bool,
    notifications_enabled: bool,
    expect_internal_events: bool,
) -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        target = make_target(session)
        target.notifications_suppressed = target_suppressed
        setting = session.get(AppSetting, "notifications_enabled")
        assert setting is not None
        setting.value = "true" if notifications_enabled else "false"
        session.commit()
        service = make_service()

        service.save_result(
            session, target.id, CheckOutcome(status=CheckStatus.DOWN, message="timeout")
        )
        opened = service.save_result(
            session, target.id, CheckOutcome(status=CheckStatus.DOWN, message="timeout")
        )
        recovered = service.save_result(
            session, target.id, CheckOutcome(status=CheckStatus.UP)
        )

        incident = session.query(Incident).one()
        if expect_internal_events:
            assert [event.kind for event in opened] == [IncidentEventKind.OPENED]
            assert [event.kind for event in recovered] == [IncidentEventKind.RECOVERED]
            assert incident.open_notification_attempted_at is not None
            assert incident.recovery_notification_attempted_at is not None
        else:
            assert opened == []
            assert recovered == []
            assert incident.open_notification_attempted_at is None
            assert incident.recovery_notification_attempted_at is None
        assert incident.status == IncidentStatus.RESOLVED
