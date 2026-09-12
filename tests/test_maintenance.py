from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from monitoring.db import Base
from monitoring.models import (
    AppSetting,
    CheckResult,
    MonitorTarget,
    Site,
    SnmpInterface,
    SnmpInterfaceSample,
    SnmpMetric,
    SnmpSample,
)
from monitoring.services.maintenance import cleanup_check_history, cleanup_snmp_samples


def test_cleanup_removes_only_expired_check_results() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    with Session(engine) as session:
        target = MonitorTarget(
            site=Site(name="Филиал"),
            name="Сервер",
            address="192.0.2.10",
            port=80,
        )
        target.results.extend(
            [
                CheckResult(status="up", checked_at=now - timedelta(days=91)),
                CheckResult(status="up", checked_at=now - timedelta(days=89)),
            ]
        )
        session.add_all(
            [
                target,
                AppSetting(
                    key="history_retention_days",
                    value="90",
                    description="Хранение истории",
                ),
            ]
        )
        session.commit()

        deleted = cleanup_check_history(session, now=now)

        assert deleted == 1
        assert session.query(CheckResult).count() == 1


def test_snmp_retention_removes_metric_and_interface_samples() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    with Session(engine) as session:
        target = MonitorTarget(
            site=Site(name="Филиал"), name="Коммутатор", address="192.0.2.10", port=161
        )
        session.add(target)
        session.flush()
        metric = SnmpMetric(target_id=target.id, oid="1.3.6.1.4.1.1.0", name="CPU")
        interface = SnmpInterface(target_id=target.id, if_index=1, if_name="ether1")
        session.add_all((metric, interface))
        session.flush()
        old = now - timedelta(days=31)
        session.add_all(
            (
                SnmpSample(metric_id=metric.id, value=1, collected_at=old),
                SnmpSample(metric_id=metric.id, value=2, collected_at=now),
                SnmpInterfaceSample(interface_id=interface.id, rx_bps=1, collected_at=old),
                SnmpInterfaceSample(interface_id=interface.id, rx_bps=2, collected_at=now),
                AppSetting(key="snmp_sample_retention_days", value="30", description=""),
            )
        )
        session.commit()
        assert cleanup_snmp_samples(session, now=now) == 2
        assert session.query(SnmpSample).count() == 1
        assert session.query(SnmpInterfaceSample).count() == 1
