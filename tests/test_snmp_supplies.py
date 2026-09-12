import asyncio

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from monitoring.config import Settings
from monitoring.db import Base
from monitoring.models import Incident, MonitorTarget, Site, SnmpSupply, SnmpThreshold
from monitoring.services.snmp import SnmpService, SnmpSettingsForm
from monitoring.services.snmp_client import (
    SnmpRequest,
    SnmpVarBind,
    SnmpWalkResult,
)
from monitoring.services.snmp_supplies import (
    PRINTER_SUPPLIES_ENTRY_ROOT,
    build_supply_snapshots,
    normalize_supply_level,
    supply_oid,
)
from monitoring.services.snmp_thresholds import SnmpThresholdService


def _system_values() -> dict[str, SnmpVarBind]:
    return {
        "1.3.6.1.2.1.1.1.0": SnmpVarBind(
            "1.3.6.1.2.1.1.1.0", "printer", "OctetString"
        ),
        "1.3.6.1.2.1.1.2.0": SnmpVarBind(
            "1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.11", "ObjectIdentifier"
        ),
        "1.3.6.1.2.1.1.3.0": SnmpVarBind(
            "1.3.6.1.2.1.1.3.0", "12345", "TimeTicks"
        ),
        "1.3.6.1.2.1.1.5.0": SnmpVarBind(
            "1.3.6.1.2.1.1.5.0", "office-printer", "OctetString"
        ),
    }


def _supply_walk(level: int = 17) -> tuple[SnmpVarBind, ...]:
    suffix = "7.1"
    return (
        SnmpVarBind(f"{PRINTER_SUPPLIES_ENTRY_ROOT}.2.{suffix}", "1", "Integer32"),
        SnmpVarBind(f"{PRINTER_SUPPLIES_ENTRY_ROOT}.3.{suffix}", "1", "Integer32"),
        SnmpVarBind(f"{PRINTER_SUPPLIES_ENTRY_ROOT}.4.{suffix}", "3", "Integer32"),
        SnmpVarBind(f"{PRINTER_SUPPLIES_ENTRY_ROOT}.5.{suffix}", "3", "Integer32"),
        SnmpVarBind(
            f"{PRINTER_SUPPLIES_ENTRY_ROOT}.6.{suffix}", "Black Toner", "OctetString"
        ),
        SnmpVarBind(f"{PRINTER_SUPPLIES_ENTRY_ROOT}.7.{suffix}", "19", "Integer32"),
        SnmpVarBind(f"{PRINTER_SUPPLIES_ENTRY_ROOT}.8.{suffix}", "100", "Integer32"),
        SnmpVarBind(
            f"{PRINTER_SUPPLIES_ENTRY_ROOT}.9.{suffix}", str(level), "Integer32"
        ),
    )


class FakePrinterSnmpClient:
    def __init__(self) -> None:
        self.values = _system_values()
        self.values[supply_oid("max_capacity", 7, 1)] = SnmpVarBind(
            supply_oid("max_capacity", 7, 1), "100", "Integer32"
        )
        self.values[supply_oid("level", 7, 1)] = SnmpVarBind(
            supply_oid("level", 7, 1), "8", "Integer32"
        )
        self.walk_items = _supply_walk()

    async def get(self, request: SnmpRequest, oids):
        return [self.values[oid] for oid in oids if oid in self.values]

    async def walk(self, request: SnmpRequest, root_oid: str, *, max_results: int):
        items = tuple(
            item for item in self.walk_items if item.oid.startswith(f"{root_oid}.")
        )
        return SnmpWalkResult(items[:max_results], truncated=len(items) > max_results)


def _service():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    fake = FakePrinterSnmpClient()
    service = SnmpService(
        factory,
        Settings(secret_key="printer-test-secret", _env_file=None),
        fake,
        asyncio.Semaphore(4),
    )
    with factory() as session:
        target = MonitorTarget(
            site=Site(name="Printers"),
            name="office-printer",
            address="192.0.2.50",
            port=80,
        )
        session.add(target)
        session.commit()
        target_id = target.id
        service.save_settings(
            session,
            target_id,
            SnmpSettingsForm(True, 161, "private", 3, 1),
        )
        session.commit()
    return factory, service, fake, target_id


def test_printer_mib_special_values_never_become_low_percent() -> None:
    assert normalize_supply_level(supply_class=3, unit_code=19, max_capacity=100, level=17) == (17.0, "ok")
    assert normalize_supply_level(supply_class=3, unit_code=7, max_capacity=6000, level=1200) == (
        20.0,
        "ok",
    )
    assert normalize_supply_level(supply_class=3, unit_code=19, max_capacity=100, level=-1) == (
        None,
        "other",
    )
    assert normalize_supply_level(supply_class=3, unit_code=19, max_capacity=100, level=-2) == (
        None,
        "unknown",
    )
    assert normalize_supply_level(supply_class=3, unit_code=19, max_capacity=100, level=-3) == (
        None,
        "some",
    )


def test_receptacle_level_is_normalized_to_free_capacity() -> None:
    percent, state = normalize_supply_level(
        supply_class=4, unit_code=19, max_capacity=100, level=84
    )
    assert state == "ok"
    assert percent == 16.0


def test_build_supply_snapshots_uses_hr_device_and_supply_indexes() -> None:
    snapshots = build_supply_snapshots(_supply_walk(17))
    assert len(snapshots) == 1
    supply = snapshots[0]
    assert supply.hr_device_index == 7
    assert supply.supply_index == 1
    assert supply.description == "Black Toner"
    assert supply.supply_type == 3
    assert supply.percent_remaining == 17.0


def test_supply_discovery_poll_and_threshold_use_existing_incident_flow() -> None:
    factory, service, fake, target_id = _service()

    result = asyncio.run(service.discover_supplies_target(target_id))
    assert result.status == "ok"
    with factory() as session:
        supply = session.scalar(select(SnmpSupply).where(SnmpSupply.target_id == target_id))
        assert supply is not None
        assert supply.description == "Black Toner"
        assert supply.percent_remaining == 17.0
        supply.custom_name = "Чёрный картридж"
        threshold = SnmpThreshold(
            target_id=target_id,
            source_kind="supply",
            supply_id=supply.id,
            field="percent",
            operator="lt",
            warning_value=20,
            critical_value=10,
            enabled=True,
        )
        session.add(threshold)
        session.commit()
        threshold_id = threshold.id

    # Repeated discovery refreshes the MIB description but preserves the operator alias.
    asyncio.run(service.discover_supplies_target(target_id))
    with factory() as session:
        supply = session.scalar(select(SnmpSupply).where(SnmpSupply.target_id == target_id))
        assert supply is not None
        assert supply.custom_name == "Чёрный картридж"
        assert supply.display_name == "Чёрный картридж"

    events = asyncio.run(service.poll_target(target_id))
    assert len(events) == 1
    with factory() as session:
        supply = session.scalar(select(SnmpSupply).where(SnmpSupply.target_id == target_id))
        threshold = session.get(SnmpThreshold, threshold_id)
        incident = session.scalar(select(Incident))
        assert supply is not None and supply.percent_remaining == 8.0
        assert threshold is not None and threshold.current_level == "critical"
        assert threshold.last_value == 8.0
        assert incident is not None and incident.source_kind == "snmp"
        assert incident.severity == "critical"

    fake.values[supply_oid("level", 7, 1)] = SnmpVarBind(
        supply_oid("level", 7, 1), "-2", "Integer32"
    )
    assert asyncio.run(service.poll_target(target_id)) == []
    with factory() as session:
        supply = session.scalar(select(SnmpSupply).where(SnmpSupply.target_id == target_id))
        threshold = session.get(SnmpThreshold, threshold_id)
        incident = session.scalar(select(Incident))
        assert supply is not None and supply.percent_remaining is None
        assert supply.level_state == "unknown"
        assert threshold is not None and threshold.current_level == "critical"
        assert threshold.last_value == 8.0
        assert incident is not None and incident.status == "open"


def test_supply_can_be_selected_as_threshold_source() -> None:
    factory, service, _fake, target_id = _service()
    asyncio.run(service.discover_supplies_target(target_id))
    with factory() as session:
        supply = session.scalar(select(SnmpSupply).where(SnmpSupply.target_id == target_id))
        assert supply is not None
        supply.custom_name = "Чёрный картридж"
        session.commit()
        parsed = SnmpThresholdService.parse_source(
            session, target_id, f"supply:{supply.id}:percent"
        )
        assert parsed == ("supply", None, None, supply.id, "percent")
        options = SnmpThresholdService().source_options(session, target_id)
        option = next(item for item in options if item.value == f"supply:{supply.id}:percent")
        assert "Чёрный картридж" in option.label
