from decimal import Decimal

from sqlalchemy import create_engine, delete, event, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from monitoring.db import Base
from monitoring.models import (
    CheckResult,
    MonitorTarget,
    Site,
    SnmpConfig,
    SnmpInterface,
    SnmpInterfaceSample,
    SnmpMetric,
    SnmpSample,
    SnmpSupply,
    SnmpThreshold,
    SnmpUpsEvent,
    SnmpUpsLine,
    SnmpUpsSample,
    SnmpUpsState,
    TargetCheck,
    TargetCheckResult,
    WorkSchedule,
)
from monitoring.services.target_checks import sync_target_primary_check
from monitoring.services.target_clone import clone_target_configuration


def _session_factory(*, foreign_keys: bool = False):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    if foreign_keys:
        @event.listens_for(engine, "connect")
        def _enable_foreign_keys(connection, _record) -> None:
            connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def test_target_clone_copies_configuration_without_operational_data() -> None:
    factory = _session_factory()
    with factory() as session:
        site = Site(name="Копирование")
        source = MonitorTarget(
            site=site,
            name="Источник",
            kind="server",
            checker_type="tcp",
            address="192.0.2.10",
            port=443,
            interval_seconds=120,
        )
        destination = MonitorTarget(
            site=site,
            name="Копия источника",
            kind="server",
            checker_type="tcp",
            address="192.0.2.11",
            port=443,
            interval_seconds=120,
        )
        session.add_all((source, destination))
        session.flush()
        sync_target_primary_check(session, destination)
        session.add(
            SnmpConfig(
                target_id=source.id,
                enabled=True,
                port=1161,
                community_encrypted="encrypted-community",
                timeout_seconds=5,
                retries=2,
                ups_enabled=True,
                last_error="old runtime error",
            )
        )
        session.add(
            TargetCheck(
                target_id=source.id,
                name="HTTPS API",
                checker_type="https",
                address_override="api.example.test",
                port=8443,
                path="/health",
                timeout_seconds=4,
                retries=2,
                display_order=1,
                http_expected_status=204,
                tls_monitor_enabled=True,
                tls_warning_days=20,
                tls_critical_days=5,
                directory_password_encrypted="encrypted-directory-password",
                directory_last_files=[{"name": "old.zip"}],
            )
        )
        metric = SnmpMetric(
            target_id=source.id,
            oid="1.3.6.1.2.1.1.3.0",
            name="Uptime",
            unit="s",
            display_order=1,
            last_value="old value",
            last_numeric_value=Decimal("123"),
        )
        formula_metric = SnmpMetric(
            target_id=source.id,
            source_kind="formula",
            formula="${metric:1} / 1024",
            name="Memory MiB",
            unit="MiB",
            display_order=2,
        )
        interface = SnmpInterface(
            target_id=source.id,
            if_index=7,
            if_name="ether1",
            speed_bps=1_000_000_000,
            monitor_enabled=True,
            rx_bps=1_234,
        )
        supply = SnmpSupply(
            target_id=source.id,
            hr_device_index=1,
            supply_index=2,
            description="Black toner",
            custom_name="Чёрный картридж",
            percent_remaining=42,
        )
        session.add_all((metric, formula_metric, interface, supply))
        session.flush()
        session.add_all(
            (
                SnmpSample(metric_id=metric.id, value=Decimal("123")),
                SnmpInterfaceSample(interface_id=interface.id, rx_bps=1_234),
                SnmpThreshold(
                    target_id=source.id,
                    source_kind="metric",
                    metric_id=metric.id,
                    field="value",
                    operator="gt",
                    warning_value=100,
                ),
                SnmpThreshold(
                    target_id=source.id,
                    source_kind="interface",
                    interface_id=interface.id,
                    field="rx_bps",
                    operator="gt",
                    warning_value=100,
                ),
                SnmpThreshold(
                    target_id=source.id,
                    source_kind="supply",
                    supply_id=supply.id,
                    field="percent",
                    operator="lt",
                    warning_value=20,
                ),
                SnmpThreshold(
                    target_id=source.id,
                    source_kind="ups",
                    field="battery_charge_percent",
                    operator="lt",
                    warning_value=20,
                ),
            )
        )
        session.flush()
        secondary = session.scalar(
            select(TargetCheck).where(
                TargetCheck.target_id == source.id, TargetCheck.is_primary.is_(False)
            )
        )
        assert secondary is not None
        session.add_all(
            (
                CheckResult(target_id=source.id, status="up"),
                TargetCheckResult(check_id=secondary.id, status="up"),
            )
        )
        session.commit()

        result = clone_target_configuration(session, source, destination)
        session.commit()

        assert result.audit_details() == {
            "checks": 1,
            "metrics": 2,
            "interfaces": 1,
            "supplies": 1,
            "thresholds": 4,
            "snmp_configured": True,
        }
        copied_config = session.get(SnmpConfig, destination.id)
        assert copied_config is not None
        assert copied_config.community_encrypted == "encrypted-community"
        assert copied_config.last_error is None
        copied_checks = session.scalars(
            select(TargetCheck)
            .where(TargetCheck.target_id == destination.id)
            .order_by(TargetCheck.is_primary.desc(), TargetCheck.display_order)
        ).all()
        assert len(copied_checks) == 2
        copied_secondary = next(check for check in copied_checks if not check.is_primary)
        assert copied_secondary.directory_password_encrypted == "encrypted-directory-password"
        assert copied_secondary.directory_last_files is None
        assert session.scalar(
            select(TargetCheckResult).where(TargetCheckResult.check_id == copied_secondary.id)
        ) is None

        copied_metrics = session.scalars(
            select(SnmpMetric)
            .where(SnmpMetric.target_id == destination.id)
            .order_by(SnmpMetric.display_order)
        ).all()
        assert [item.name for item in copied_metrics] == ["Uptime", "Memory MiB"]
        assert copied_metrics[0].last_value is None
        assert copied_metrics[1].formula == "${metric:1} / 1024"
        assert session.scalar(
            select(SnmpSample).where(SnmpSample.metric_id == copied_metrics[0].id)
        ) is None

        copied_interface = session.scalar(
            select(SnmpInterface).where(SnmpInterface.target_id == destination.id)
        )
        assert copied_interface is not None
        assert copied_interface.monitor_enabled is True
        assert copied_interface.rx_bps is None
        copied_supply = session.scalar(
            select(SnmpSupply).where(SnmpSupply.target_id == destination.id)
        )
        assert copied_supply is not None
        assert copied_supply.custom_name == "Чёрный картридж"
        assert copied_supply.percent_remaining is None
        copied_thresholds = session.scalars(
            select(SnmpThreshold)
            .where(SnmpThreshold.target_id == destination.id)
            .order_by(SnmpThreshold.source_kind)
        ).all()
        assert len(copied_thresholds) == 4
        assert {item.source_kind for item in copied_thresholds} == {
            "metric",
            "interface",
            "supply",
            "ups",
        }
        assert all(item.last_evaluated_at is None for item in copied_thresholds)
        assert session.scalar(select(CheckResult).where(CheckResult.target_id == destination.id)) is None


def test_database_cascade_removes_all_target_operational_records() -> None:
    """Keep every Target-owned table covered when a new subsystem is added."""
    factory = _session_factory(foreign_keys=True)
    with factory() as session:
        session.add(WorkSchedule(id=0, name="Круглосуточно", is_24x7=True, built_in=True))
        session.flush()
        target = MonitorTarget(
            site=Site(name="Cascade"),
            name="Delete me",
            address="192.0.2.70",
            port=161,
        )
        session.add(target)
        session.flush()
        check = TargetCheck(
            target_id=target.id,
            name="Secondary",
            checker_type="tcp",
            port=443,
            is_primary=False,
        )
        metric = SnmpMetric(
            target_id=target.id,
            oid="1.3.6.1.2.1.1.3.0",
            name="Uptime",
        )
        interface = SnmpInterface(target_id=target.id, if_index=1, if_name="ether1")
        supply = SnmpSupply(target_id=target.id, hr_device_index=1, supply_index=1)
        ups_state = SnmpUpsState(target_id=target.id, manufacturer="APC")
        session.add_all(
            (
                SnmpConfig(target_id=target.id, enabled=True),
                check,
                metric,
                interface,
                supply,
                ups_state,
                CheckResult(target_id=target.id, status="up"),
            )
        )
        session.flush()
        session.add_all(
            (
                TargetCheckResult(check_id=check.id, status="up"),
                SnmpSample(metric_id=metric.id, value=Decimal("1")),
                SnmpInterfaceSample(interface_id=interface.id, rx_bps=1),
                SnmpThreshold(
                    target_id=target.id,
                    source_kind="metric",
                    metric_id=metric.id,
                    field="value",
                    operator="gt",
                    warning_value=1,
                ),
                SnmpUpsLine(target_id=target.id, direction="input", line_index=1),
                SnmpUpsSample(
                    target_id=target.id,
                    metric_key="battery_charge_percent",
                    value=Decimal("100"),
                ),
                SnmpUpsEvent(target_id=target.id, event_key="output_source", value=3),
            )
        )
        session.commit()
        target_id = target.id

        session.execute(delete(MonitorTarget).where(MonitorTarget.id == target_id))
        session.commit()

        for model in (
            MonitorTarget,
            CheckResult,
            TargetCheck,
            TargetCheckResult,
            SnmpConfig,
            SnmpMetric,
            SnmpSample,
            SnmpInterface,
            SnmpInterfaceSample,
            SnmpSupply,
            SnmpThreshold,
            SnmpUpsState,
            SnmpUpsLine,
            SnmpUpsSample,
            SnmpUpsEvent,
        ):
            assert session.scalar(select(model).limit(1)) is None, model.__tablename__
