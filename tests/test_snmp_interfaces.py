import asyncio
from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from monitoring.config import Settings
from monitoring.db import Base
from monitoring.models import MonitorTarget, Site, SnmpInterface, SnmpInterfaceSample
from monitoring.services.snmp import SnmpService, SnmpSettingsForm
from monitoring.services.snmp_client import SnmpRequest, SnmpVarBind, SnmpWalkResult
from monitoring.services.snmp_interfaces import (
    IF_ADMIN_STATUS_BASE,
    IF_COLUMNS,
    IF_HC_IN_OCTETS_BASE,
    IF_HC_OUT_OCTETS_BASE,
    IF_IN_DISCARDS_BASE,
    IF_IN_ERRORS_BASE,
    IF_IN_OCTETS_BASE,
    IF_OPER_STATUS_BASE,
    IF_OUT_DISCARDS_BASE,
    IF_OUT_ERRORS_BASE,
    IF_OUT_OCTETS_BASE,
    MAX_SNMP_INTERFACES,
    TRAFFIC_COUNTER_HC64,
    TRAFFIC_COUNTER_LEGACY32,
    build_interface_snapshots,
    build_traffic_snapshot,
    counter_rate_bps,
    format_interface_rate,
    format_interface_speed,
    interface_status_label,
    traffic_poll_oids,
)


class FakeInterfaceClient:
    def __init__(self, walks=None, values=None):
        self.walks = walks or {}
        self.values = values or {}
        self.walk_calls: list[str] = []
        self.get_calls: list[tuple[str, ...]] = []

    async def walk(
        self, request: SnmpRequest, root_oid: str, *, max_results: int
    ) -> SnmpWalkResult:
        self.walk_calls.append(root_oid)
        result = self.walks.get(root_oid, SnmpWalkResult(()))
        if len(result.items) <= max_results:
            return result
        return SnmpWalkResult(result.items[:max_results], truncated=True)

    async def get(self, request: SnmpRequest, oids):
        self.get_calls.append(tuple(oids))
        return [self.values[oid] for oid in oids if oid in self.values]


def _factory_and_service(fake: FakeInterfaceClient):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    settings = Settings(secret_key="snmp-interface-test-secret", _env_file=None)
    service = SnmpService(factory, settings, fake, asyncio.Semaphore(2))
    with factory() as session:
        target = MonitorTarget(
            site=Site(name="SNMP"),
            name="switch",
            address="192.0.2.10",
            port=443,
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
    return factory, service, target_id


def _walk_item(base: str, if_index: int, value: str, type_name: str) -> SnmpVarBind:
    return SnmpVarBind(f"{base}.{if_index}", value, type_name)


def _interface_walks(name: str = "ether1") -> dict[str, SnmpWalkResult]:
    values = {
        "if_index": ("1", "Integer"),
        "if_descr": ("ether1", "OctetString"),
        "if_type": ("6", "Integer"),
        "if_mtu": ("1500", "Integer"),
        "if_speed": ("1000000000", "Gauge32"),
        "if_phys_address": ("aa:bb:cc:dd:ee:ff", "OctetString"),
        "if_admin_status": ("1", "Integer"),
        "if_oper_status": ("1", "Integer"),
        "if_name": (name, "OctetString"),
        "if_high_speed": ("1000", "Gauge32"),
        "if_alias": ("WAN", "OctetString"),
    }
    return {
        IF_COLUMNS[key]: SnmpWalkResult(
            (_walk_item(IF_COLUMNS[key], 1, value, type_name),)
        )
        for key, (value, type_name) in values.items()
    }


def _system_values() -> dict[str, SnmpVarBind]:
    return {
        "1.3.6.1.2.1.1.1.0": SnmpVarBind("1.3.6.1.2.1.1.1.0", "switch", "OctetString"),
        "1.3.6.1.2.1.1.2.0": SnmpVarBind("1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.14988", "ObjectIdentifier"),
        "1.3.6.1.2.1.1.3.0": SnmpVarBind("1.3.6.1.2.1.1.3.0", "12345", "TimeTicks"),
        "1.3.6.1.2.1.1.5.0": SnmpVarBind("1.3.6.1.2.1.1.5.0", "core", "OctetString"),
    }


def test_interface_snapshot_prefers_if_high_speed() -> None:
    snapshots = build_interface_snapshots(
        {
            "if_name": (_walk_item(IF_COLUMNS["if_name"], 5, "ether5", "OctetString"),),
            "if_speed": (_walk_item(IF_COLUMNS["if_speed"], 5, "100000000", "Gauge32"),),
            "if_high_speed": (_walk_item(IF_COLUMNS["if_high_speed"], 5, "1000", "Gauge32"),),
            "if_oper_status": (_walk_item(IF_COLUMNS["if_oper_status"], 5, "1", "Integer"),),
        }
    )
    assert len(snapshots) == 1
    assert snapshots[0].if_index == 5
    assert snapshots[0].if_name == "ether5"
    assert snapshots[0].speed_bps == 1_000_000_000
    assert snapshots[0].oper_status == 1
    assert format_interface_speed(snapshots[0].speed_bps) == "1 Gbit/s"
    assert interface_status_label(1) == "Up"


def test_manual_interface_discovery_persists_inventory() -> None:
    fake = FakeInterfaceClient(walks=_interface_walks())
    factory, service, target_id = _factory_and_service(fake)
    result = asyncio.run(service.discover_interfaces_target(target_id))
    assert result.status == "ok"
    assert len(result.items) == 1
    assert set(fake.walk_calls) == set(IF_COLUMNS.values())
    with factory() as session:
        item = session.scalar(select(SnmpInterface).where(SnmpInterface.target_id == target_id))
        assert item is not None
        assert item.if_name == "ether1"
        assert item.if_alias == "WAN"
        assert item.speed_bps == 1_000_000_000
        assert item.present is True
        assert item.monitor_enabled is False


def test_ifindex_identity_change_disables_monitoring() -> None:
    fake = FakeInterfaceClient(walks=_interface_walks("ether1"))
    factory, service, target_id = _factory_and_service(fake)
    asyncio.run(service.discover_interfaces_target(target_id))
    with factory() as session:
        item = session.scalar(select(SnmpInterface))
        assert item is not None
        item.monitor_enabled = True
        session.flush()
        session.add(SnmpInterfaceSample(interface_id=item.id, rx_bps=100))
        session.commit()
    fake.walks = _interface_walks("vlan100")
    asyncio.run(service.discover_interfaces_target(target_id))
    with factory() as session:
        item = session.scalar(select(SnmpInterface))
        assert item is not None
        assert item.if_name == "vlan100"
        assert item.monitor_enabled is False
        assert session.scalar(select(SnmpInterfaceSample)) is None


def test_selected_interface_status_is_polled_with_snmp_core() -> None:
    values = _system_values()
    values.update(
        {
            f"{IF_ADMIN_STATUS_BASE}.1": SnmpVarBind(f"{IF_ADMIN_STATUS_BASE}.1", "1", "Integer"),
            f"{IF_OPER_STATUS_BASE}.1": SnmpVarBind(f"{IF_OPER_STATUS_BASE}.1", "2", "Integer"),
        }
    )
    fake = FakeInterfaceClient(values=values)
    factory, service, target_id = _factory_and_service(fake)
    with factory() as session:
        session.add(
            SnmpInterface(
                target_id=target_id,
                if_index=1,
                if_name="ether1",
                monitor_enabled=True,
                present=True,
            )
        )
        session.commit()
    asyncio.run(service.poll_target(target_id))
    with factory() as session:
        item = session.scalar(select(SnmpInterface))
        assert item is not None
        assert item.admin_status == 1
        assert item.oper_status == 2
        assert item.last_polled_at is not None
        assert item.last_error is None
    requested = {oid for call in fake.get_calls for oid in call}
    assert f"{IF_ADMIN_STATUS_BASE}.1" in requested
    assert f"{IF_OPER_STATUS_BASE}.1" in requested


def test_interface_snapshot_limit_is_enforced() -> None:
    fake = FakeInterfaceClient(
        walks={
            IF_COLUMNS["if_name"]: SnmpWalkResult(
                tuple(
                    _walk_item(IF_COLUMNS["if_name"], index, f"ether{index}", "OctetString")
                    for index in range(1, MAX_SNMP_INTERFACES + 2)
                )
            )
        }
    )
    _factory, service, target_id = _factory_and_service(fake)
    result = asyncio.run(service.discover_interfaces_target(target_id))
    assert result.status == "ok"
    assert len(result.items) == MAX_SNMP_INTERFACES
    assert result.truncated is True


def test_target_delete_cascades_interface_inventory() -> None:
    fake = FakeInterfaceClient()
    factory, _service, target_id = _factory_and_service(fake)
    with factory() as session:
        interface = SnmpInterface(
            target_id=target_id,
            if_index=1,
            if_name="ether1",
            monitor_enabled=True,
        )
        session.add(interface)
        session.flush()
        session.add(SnmpInterfaceSample(interface_id=interface.id, rx_bps=100))
        session.commit()
        target = session.get(MonitorTarget, target_id)
        assert target is not None
        session.delete(target)
        session.commit()
        assert session.scalar(select(SnmpInterface)) is None
        assert session.scalar(select(SnmpInterfaceSample)) is None


def _system_and_status_values(*, uptime: int = 12_345) -> dict[str, SnmpVarBind]:
    values = _system_values()
    values["1.3.6.1.2.1.1.3.0"] = SnmpVarBind(
        "1.3.6.1.2.1.1.3.0", str(uptime), "TimeTicks"
    )
    values.update(
        {
            f"{IF_ADMIN_STATUS_BASE}.1": SnmpVarBind(
                f"{IF_ADMIN_STATUS_BASE}.1", "1", "Integer"
            ),
            f"{IF_OPER_STATUS_BASE}.1": SnmpVarBind(
                f"{IF_OPER_STATUS_BASE}.1", "1", "Integer"
            ),
        }
    )
    return values


def _traffic_values(
    *,
    mode: str = TRAFFIC_COUNTER_HC64,
    in_octets: int = 1_000_000,
    out_octets: int = 2_000_000,
    uptime: int = 12_345,
) -> dict[str, SnmpVarBind]:
    values = _system_and_status_values(uptime=uptime)
    if mode == TRAFFIC_COUNTER_HC64:
        in_base, out_base, type_name = (
            IF_HC_IN_OCTETS_BASE,
            IF_HC_OUT_OCTETS_BASE,
            "Counter64",
        )
    else:
        in_base, out_base, type_name = IF_IN_OCTETS_BASE, IF_OUT_OCTETS_BASE, "Counter32"
    values.update(
        {
            f"{in_base}.1": SnmpVarBind(f"{in_base}.1", str(in_octets), type_name),
            f"{out_base}.1": SnmpVarBind(f"{out_base}.1", str(out_octets), type_name),
            f"{IF_IN_ERRORS_BASE}.1": SnmpVarBind(
                f"{IF_IN_ERRORS_BASE}.1", "3", "Counter32"
            ),
            f"{IF_OUT_ERRORS_BASE}.1": SnmpVarBind(
                f"{IF_OUT_ERRORS_BASE}.1", "4", "Counter32"
            ),
            f"{IF_IN_DISCARDS_BASE}.1": SnmpVarBind(
                f"{IF_IN_DISCARDS_BASE}.1", "5", "Counter32"
            ),
            f"{IF_OUT_DISCARDS_BASE}.1": SnmpVarBind(
                f"{IF_OUT_DISCARDS_BASE}.1", "6", "Counter32"
            ),
        }
    )
    return values


def _add_monitored_interface(factory, target_id: int) -> None:
    with factory() as session:
        session.add(
            SnmpInterface(
                target_id=target_id,
                if_index=1,
                if_name="ether1",
                speed_bps=1_000_000_000,
                monitor_enabled=True,
                present=True,
            )
        )
        session.commit()


def test_traffic_poll_oids_and_counter_rate_are_safe() -> None:
    assert f"{IF_HC_IN_OCTETS_BASE}.1" in traffic_poll_oids(1, None)
    assert f"{IF_IN_OCTETS_BASE}.1" in traffic_poll_oids(1, None)
    assert f"{IF_IN_OCTETS_BASE}.1" not in traffic_poll_oids(1, TRAFFIC_COUNTER_HC64)
    assert counter_rate_bps(2_000, 1_000, 10, counter_mode=TRAFFIC_COUNTER_HC64) == 800
    assert counter_rate_bps(1_000, 2_000, 10, counter_mode=TRAFFIC_COUNTER_HC64) is None
    assert (
        counter_rate_bps(100, (1 << 32) - 100, 10, counter_mode=TRAFFIC_COUNTER_LEGACY32)
        == 160
    )
    assert format_interface_rate(1_500_000) == "1.5"


def test_interface_traffic_hc64_baseline_then_rate_and_reboot_reset() -> None:
    fake = FakeInterfaceClient(values=_traffic_values())
    factory, service, target_id = _factory_and_service(fake)
    _add_monitored_interface(factory, target_id)
    asyncio.run(service.poll_target(target_id))
    with factory() as session:
        item = session.scalar(select(SnmpInterface))
        assert item is not None
        assert item.traffic_counter_mode == TRAFFIC_COUNTER_HC64
        assert item.in_octets == "1000000"
        assert item.rx_bps is None and item.tx_bps is None
        assert item.in_errors == 3 and item.out_discards == 6
        sample = session.scalar(select(SnmpInterfaceSample))
        assert sample is not None and sample.rx_bps is None and sample.tx_bps is None
        item.traffic_at = datetime.now(UTC) - timedelta(seconds=10)
        session.commit()
    fake.values = _traffic_values(in_octets=1_010_000, out_octets=2_020_000, uptime=13_345)
    asyncio.run(service.poll_target(target_id))
    with factory() as session:
        item = session.scalar(select(SnmpInterface))
        assert item is not None and item.rx_bps is not None and item.tx_bps is not None
        assert 7_000 <= item.rx_bps <= 9_000
        assert session.scalar(select(SnmpInterfaceSample).order_by(SnmpInterfaceSample.id.desc())).rx_bps is not None
        fake.values = _traffic_values(in_octets=2_000_000, out_octets=3_000_000, uptime=100)
    asyncio.run(service.poll_target(target_id))
    with factory() as session:
        item = session.scalar(select(SnmpInterface))
        assert item is not None and item.rx_bps is None and item.tx_bps is None
        assert item.traffic_uptime_ticks == 100


def test_interface_traffic_falls_back_to_counter32_and_clear_keeps_selection() -> None:
    fake = FakeInterfaceClient(values=_traffic_values(mode=TRAFFIC_COUNTER_LEGACY32))
    factory, service, target_id = _factory_and_service(fake)
    _add_monitored_interface(factory, target_id)
    asyncio.run(service.poll_target(target_id))
    with factory() as session:
        item = session.scalar(select(SnmpInterface))
        assert item is not None and item.traffic_counter_mode == TRAFFIC_COUNTER_LEGACY32
        service.clear_data(session, target_id)
        session.commit()
        assert item.monitor_enabled is True
        assert item.traffic_counter_mode is None
        assert item.in_octets is None and item.in_errors is None
        assert session.scalar(select(SnmpInterfaceSample)) is None


def test_traffic_snapshot_error_does_not_break_interface_status() -> None:
    values = _system_and_status_values()
    snapshot = build_traffic_snapshot(values, 1, None)
    assert snapshot.counter_mode is None
    assert snapshot.error == "OID счётчиков трафика не вернули данные"


def test_traffic_poll_error_does_not_create_interface_sample() -> None:
    fake = FakeInterfaceClient(values=_system_and_status_values())
    factory, service, target_id = _factory_and_service(fake)
    _add_monitored_interface(factory, target_id)
    asyncio.run(service.poll_target(target_id))
    with factory() as session:
        assert session.scalar(select(SnmpInterfaceSample)) is None
