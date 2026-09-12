from datetime import UTC, datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from monitoring.checks.registry import CheckerRegistry
from monitoring.db import Base
from monitoring.models import MonitorTarget, Site, WorkSchedule
from monitoring.services.monitoring import MonitoringService
from monitoring.services.system_metrics import portal_dashboard
from monitoring.services.target_transfer import export_targets_csv, import_targets_csv
from monitoring.services.work_schedules import schedule_is_working


def test_site_defaults_to_builtin_always_schedule_id() -> None:
    site = Site(name="Офис")
    assert site.schedule_id in (None, 0)


def test_weekly_schedule_and_overnight_interval() -> None:
    schedule = WorkSchedule(
        name="Ночной",
        monday_start="22:00",
        monday_end="06:00",
        is_24x7=False,
    )
    monday_late = datetime(2026, 8, 17, 20, 30, tzinfo=UTC)  # 23:30 Moscow
    tuesday_early = datetime(2026, 8, 18, 1, 0, tzinfo=UTC)  # 04:00 Moscow
    tuesday_day = datetime(2026, 8, 18, 10, 0, tzinfo=UTC)  # 13:00 Moscow
    assert schedule_is_working(schedule, monday_late, "Europe/Moscow") is True
    assert schedule_is_working(schedule, tuesday_early, "Europe/Moscow") is True
    assert schedule_is_working(schedule, tuesday_day, "Europe/Moscow") is False


def test_monitoring_skips_site_with_no_current_work_window() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        schedule = WorkSchedule(name="Закрыто", is_24x7=False)
        site = Site(name="Офис", schedule=schedule)
        target = MonitorTarget(site=site, name="Сервер", address="192.0.2.1", port=80)
        session.add(target)
        session.commit()
        service = MonitoringService(CheckerRegistry(), timeout_seconds=1, max_parallel_checks=1)
        assert service.get_due_targets(session) == []
        assert service.get_active_targets(session) == []


def test_target_comment_round_trips_through_csv() -> None:
    source_engine = create_engine("sqlite://")
    Base.metadata.create_all(source_engine)
    with Session(source_engine) as session:
        session.add(
            MonitorTarget(
                site=Site(name="Офис"),
                name="Сервер",
                address="192.0.2.1",
                port=80,
                comment="Основной сервер бухгалтерии",
            )
        )
        session.commit()
        data = export_targets_csv(session).encode("utf-8")
    target_engine = create_engine("sqlite://")
    Base.metadata.create_all(target_engine)
    with Session(target_engine) as session:
        import_targets_csv(session, data)
        session.commit()
        assert session.query(MonitorTarget).one().comment == "Основной сервер бухгалтерии"


def test_portal_dashboard_has_disk_graph_points() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        dashboard = portal_dashboard(session)
    assert dashboard.disk_points
