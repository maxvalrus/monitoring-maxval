from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from monitoring.checks.registry import CheckerRegistry
from monitoring.db import Base
from monitoring.models import CheckResult, MonitorTarget, Site
from monitoring.services.monitoring import MonitoringService


def test_due_targets_respect_individual_interval() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)

    with Session(engine) as session:
        site = Site(name="Центральный офис")
        disabled_site = Site(name="Отключённый филиал", enabled=False)
        due = MonitorTarget(site=site, name="Сервер", address="127.0.0.1", port=22)
        waiting = MonitorTarget(site=site, name="Камера", address="127.0.0.2", port=80)
        disabled = MonitorTarget(
            site=disabled_site,
            name="Отключённый сервер",
            address="127.0.0.3",
            port=22,
        )
        session.add_all([due, waiting, disabled])
        session.flush()
        session.add_all(
            [
                CheckResult(target_id=due.id, status="up", checked_at=now - timedelta(minutes=6)),
                CheckResult(target_id=waiting.id, status="up", checked_at=now),
            ]
        )
        session.commit()

        service = MonitoringService(CheckerRegistry(), timeout_seconds=1, max_parallel_checks=1)
        result = service.get_due_targets(session)
        active = service.get_active_targets(session)

    assert [target.name for target in result] == ["Сервер"]
    assert [target.name for target in active] == ["Сервер", "Камера"]
