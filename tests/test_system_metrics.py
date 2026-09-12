from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from monitoring.db import Base
from monitoring.models import (
    AppSetting,
    MonitorTarget,
    PortalMetric,
    Site,
    SnmpConfig,
    SnmpInterface,
    SnmpMetric,
    SnmpSupply,
)
from monitoring.services.scheduler_metrics import SchedulerHealthSnapshot
from monitoring.services.system_metrics import (
    chart_data,
    cleanup_portal_metrics,
    collect_system_metric,
    portal_dashboard,
    portal_health,
    portal_workload,
)


def metric(at: datetime, received: int, sent: int) -> PortalMetric:
    return PortalMetric(
        cpu_percent=20,
        memory_percent=40,
        disk_percent=30,
        uptime_seconds=1000,
        bytes_sent=sent,
        bytes_received=received,
        packets_sent=sent // 100,
        packets_received=received // 100,
        collected_at=at,
    )


def test_linux_metric_snapshot_has_safe_ranges() -> None:
    current = collect_system_metric()
    assert 0 <= current.cpu_percent <= 100
    assert 0 <= current.memory_percent <= 100
    assert 0 <= current.disk_percent <= 100
    assert current.uptime_seconds >= 0
    assert current.bytes_received >= 0


def test_single_chart_value_is_rendered_as_a_flat_line() -> None:
    chart = chart_data([100.0], [datetime.now(UTC)])

    assert chart.values == (100.0,)
    left, right = chart.points.split()
    assert left.split(",")[1] == right.split(",")[1]


def test_dashboard_calculates_network_rates_and_cleanup_respects_retention() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    with Session(engine) as session:
        session.add(AppSetting(key="portal_metric_retention_hours", value="24"))
        session.add_all(
            [
                metric(now - timedelta(hours=25), 1, 1),
                metric(now - timedelta(minutes=1), 1000, 500),
                metric(now, 7000, 3500),
            ]
        )
        session.commit()
        dashboard = portal_dashboard(session)
        assert dashboard.receive_rate == 100
        assert dashboard.send_rate == 50
        assert dashboard.cpu_points
        assert cleanup_portal_metrics(session, now=now) == 1
        assert len(session.scalars(select(PortalMetric)).all()) == 2


def test_portal_workload_counts_only_enabled_snmp_telemetry() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        site = Site(name="Офис")
        enabled_target = MonitorTarget(
            site=site,
            name="SNMP включён",
            address="192.0.2.1",
            port=161,
        )
        disabled_target = MonitorTarget(
            site=site,
            name="SNMP выключен",
            address="192.0.2.2",
            port=161,
        )
        session.add_all((enabled_target, disabled_target))
        session.flush()
        session.add_all(
            (
                SnmpConfig(target_id=enabled_target.id, enabled=True),
                SnmpConfig(target_id=disabled_target.id, enabled=False),
            )
        )
        for target in (enabled_target, disabled_target):
            session.add_all(
                (
                    SnmpMetric(
                        target_id=target.id,
                        oid=f"1.3.6.1.4.1.{target.id}",
                        name="Температура",
                        enabled=True,
                    ),
                    SnmpInterface(
                        target_id=target.id,
                        if_index=1,
                        monitor_enabled=True,
                        present=True,
                    ),
                    SnmpSupply(
                        target_id=target.id,
                        hr_device_index=1,
                        supply_index=1,
                        present=True,
                    ),
                )
            )
        session.commit()

        workload = portal_workload(session)

        assert workload.active_targets == 2
        assert workload.snmp_targets == 1
        assert workload.snmp_metrics == 1
        assert workload.snmp_interfaces == 1
        assert workload.snmp_supplies == 1


def scheduler_snapshot(**overrides) -> SchedulerHealthSnapshot:
    values = {
        "running": True,
        "manual_running": False,
        "poll_seconds": 15,
        "parallel_limit": 10,
        "queue_count": 0,
        "delayed_count": 0,
        "missed_interval_count": 0,
        "oldest_lag_seconds": 0.0,
        "current_batch_size": 0,
        "last_batch_size": 10,
        "last_batch_duration_seconds": 60.0,
        "last_batch_shortest_interval_seconds": 300,
        "headroom_percent": 75.0,
        "checks_5m": 100,
        "unknown_5m": 0,
        "average_check_seconds": 0.2,
        "p95_check_seconds": 0.5,
        "scheduler_errors_5m": 0,
        "scheduler_error_events": (),
        "last_scan_at": datetime.now(UTC),
    }
    values.update(overrides)
    return SchedulerHealthSnapshot(**values)


def test_portal_health_prioritizes_scheduler_backlog() -> None:
    current = metric(datetime.now(UTC), 0, 0)
    health = portal_health(
        current,
        scheduler_snapshot(missed_interval_count=2, delayed_count=4),
    )

    assert health.level == "critical"
    assert health.label == "Scheduler отстаёт"


def test_portal_health_warns_when_scheduler_headroom_is_low() -> None:
    current = metric(datetime.now(UTC), 0, 0)
    health = portal_health(current, scheduler_snapshot(headroom_percent=8.5))

    assert health.level == "warning"
    assert "запас" in health.label.casefold()
