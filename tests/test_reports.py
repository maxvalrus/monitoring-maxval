from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from monitoring.db import Base
from monitoring.models import CheckResult, MonitorTarget, Site
from monitoring.services.reports import availability_report, target_history


def test_availability_reports_group_targets_and_sites() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    with Session(engine) as session:
        site = Site(name="Офис")
        target = MonitorTarget(site=site, name="Сервер", address="127.0.0.1", port=80)
        session.add(target)
        session.flush()
        session.add_all(
            [
                CheckResult(target_id=target.id, status="up", latency_ms=10, checked_at=now),
                CheckResult(target_id=target.id, status="up", latency_ms=12, checked_at=now),
                CheckResult(target_id=target.id, status="down", checked_at=now),
                CheckResult(
                    target_id=target.id,
                    status="down",
                    checked_at=now - timedelta(days=2),
                ),
            ]
        )
        session.commit()

        targets, sites = availability_report(session, hours=24)
        history = target_history(session, target.id, hours=24)

    assert len(targets) == len(sites) == 1
    assert targets[0].availability == sites[0].availability == 66.67
    assert targets[0].up_count == 2 and targets[0].down_count == 1
    assert history.checked_count == 3
    assert history.latency_points
