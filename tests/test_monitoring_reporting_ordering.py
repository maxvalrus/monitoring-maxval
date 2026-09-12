from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from monitoring.db import Base
from monitoring.models import AppSetting, AuditLog, CheckResult, MonitorTarget, Site
from monitoring.services.maintenance import cleanup_audit_log
from monitoring.services.reports import availability_report, target_history
from monitoring.services.site_order import move_site
from monitoring.services.system_metrics import portal_dashboard
from monitoring.services.target_order import move_target


def test_target_history_uses_configured_result_limit_for_statistics() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    with Session(engine) as session:
        target = MonitorTarget(
            site=Site(name="Офис"),
            name="Сервер",
            address="192.0.2.10",
            port=80,
        )
        session.add_all(
            [
                target,
                AppSetting(
                    key="target_history_max_results",
                    value="100",
                    description="Лимит результатов",
                ),
            ]
        )
        session.flush()
        session.add_all(
            [
                CheckResult(
                    target_id=target.id,
                    status="up" if number % 2 else "down",
                    checked_at=now - timedelta(minutes=number),
                )
                for number in range(105)
            ]
        )
        session.commit()

        history = target_history(session, target.id, hours=24)

    assert history.result_limit == 100
    assert history.checked_count == 100
    assert history.up_count + history.down_count + history.unknown_count == 100
    assert len(history.results) == 100


def test_audit_cleanup_uses_separate_retention_setting() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    with Session(engine) as session:
        session.add_all(
            [
                AppSetting(
                    key="audit_retention_days",
                    value="7",
                    description="Хранение аудита",
                ),
                AuditLog(action="old", created_at=now - timedelta(days=8)),
                AuditLog(action="new", created_at=now - timedelta(days=6)),
            ]
        )
        session.commit()

        deleted = cleanup_audit_log(session, now=now)
        actions = list(session.scalars(select(AuditLog.action)).all())

    assert deleted == 1
    assert actions == ["new"]


def test_report_kind_filter_applies_to_targets_and_site_summary() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    with Session(engine) as session:
        site = Site(name="Офис")
        server = MonitorTarget(
            site=site,
            name="Сервер",
            kind="server",
            address="192.0.2.10",
            port=80,
        )
        camera = MonitorTarget(
            site=site,
            name="Камера",
            kind="camera",
            address="192.0.2.20",
            port=554,
        )
        session.add_all([server, camera])
        session.flush()
        session.add_all(
            [
                CheckResult(target_id=server.id, status="down", checked_at=now),
                CheckResult(target_id=camera.id, status="up", checked_at=now),
            ]
        )
        session.commit()

        targets, sites = availability_report(session, hours=24, kind="camera")

    assert [row.target_name for row in targets] == ["Камера"]
    assert len(sites) == 1
    assert sites[0].up_count == 1
    assert sites[0].down_count == 0
    assert sites[0].availability == 100.0


def test_manual_target_order_never_crosses_favorite_group_boundary() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        site = Site(name="Офис")
        favorite_one = MonitorTarget(
            site=site,
            name="Избранный 1",
            address="192.0.2.1",
            port=80,
            favorite=True,
            display_order=1,
        )
        favorite_two = MonitorTarget(
            site=site,
            name="Избранный 2",
            address="192.0.2.2",
            port=80,
            favorite=True,
            display_order=2,
        )
        normal = MonitorTarget(
            site=site,
            name="Обычный",
            address="192.0.2.3",
            port=80,
            favorite=False,
            display_order=1,
        )
        session.add_all([favorite_one, favorite_two, normal])
        session.commit()

        assert move_target(session, favorite_one, "down") is True
        session.commit()
        assert favorite_one.display_order == 2
        assert favorite_two.display_order == 1
        assert move_target(session, favorite_one, "down") is False
        assert favorite_one.favorite is True
        assert normal.favorite is False


def test_manual_site_order_swaps_neighbours_and_preserves_boundaries() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        first = Site(name="Первый", display_order=1)
        second = Site(name="Второй", display_order=2)
        session.add_all([first, second])
        session.commit()

        assert move_site(session, second, "up") is True
        session.commit()
        assert second.display_order == 1
        assert first.display_order == 2
        assert move_site(session, second, "up") is False


def test_portal_dashboard_exposes_current_memory_and_disk_sizes() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        dashboard = portal_dashboard(session)

    assert 0 <= dashboard.memory_used_bytes <= dashboard.memory_total_bytes
    assert 0 <= dashboard.disk_used_bytes <= dashboard.disk_total_bytes
    assert dashboard.memory_total_bytes > 0
    assert dashboard.disk_total_bytes > 0
