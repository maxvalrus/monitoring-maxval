import asyncio

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from monitoring.config import Settings
from monitoring.db import Base
from monitoring.models import MonitorTarget, Site
from monitoring.services.snmp import SnmpService, SnmpSettingsForm
from monitoring.services.snmp_client import (
    SnmpRequest,
    SnmpVarBind,
    SnmpWalkResult,
)
from monitoring.services.snmp_discovery import (
    SnmpDiscoveryResult,
    SnmpDiscoveryStore,
    discovery_roots,
)
from monitoring.services.snmp_oid_catalog import (
    discovery_oid_category,
    discovery_oid_category_label,
    is_recommended_oid,
    is_system_oid,
    standard_oid_name,
)


class FakeDiscoveryClient:
    def __init__(self, walks: dict[str, SnmpWalkResult]):
        self.walks = walks
        self.walk_calls: list[tuple[SnmpRequest, str, int]] = []
        self.get_calls: list[tuple[SnmpRequest, tuple[str, ...]]] = []

    async def get(self, request: SnmpRequest, oids):
        self.get_calls.append((request, tuple(oids)))
        return []

    async def walk(
        self, request: SnmpRequest, root_oid: str, *, max_results: int
    ) -> SnmpWalkResult:
        self.walk_calls.append((request, root_oid, max_results))
        result = self.walks.get(root_oid, SnmpWalkResult(()))
        if len(result.items) <= max_results:
            return result
        return SnmpWalkResult(result.items[:max_results], truncated=True)


def _service(fake: FakeDiscoveryClient):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    settings = Settings(secret_key="snmp-discovery-test-secret", _env_file=None)
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
    return factory, service, target_id


def _enable(session: Session, service: SnmpService, target_id: int) -> None:
    service.save_settings(
        session,
        target_id,
        SnmpSettingsForm(True, 161, "private", 3, 1),
    )
    session.commit()


def test_discovery_disabled_does_not_walk() -> None:
    fake = FakeDiscoveryClient({})
    _factory, service, target_id = _service(fake)
    result = asyncio.run(service.discover_target(target_id, ("1.3.6.1.2.1.1",)))
    assert result.status == "disabled"
    assert fake.walk_calls == []


def test_discovery_walks_branch_and_labels_standard_oids() -> None:
    root = "1.3.6.1.2.1.31"
    fake = FakeDiscoveryClient(
        {
            root: SnmpWalkResult(
                (
                    SnmpVarBind(
                        "1.3.6.1.2.1.31.1.1.1.1.5",
                        "ether5",
                        "OctetString",
                    ),
                    SnmpVarBind(
                        "1.3.6.1.2.1.31.1.1.1.6.5",
                        "123456",
                        "Counter64",
                    ),
                )
            )
        }
    )
    factory, service, target_id = _service(fake)
    with factory() as session:
        _enable(session, service, target_id)
    result = asyncio.run(service.discover_target(target_id, (root,)))
    assert result.status == "ok"
    assert [item.name for item in result.items] == ["ifName.5", "ifHCInOctets.5"]
    assert fake.walk_calls[0][0].community == "private"
    assert fake.walk_calls[0][1] == root


def test_discovery_deduplicates_roots_and_respects_result_limit() -> None:
    first = "1.3.6.1.2.1.2"
    second = "1.3.6.1.2.1.31"
    shared = SnmpVarBind("1.3.6.1.2.1.31.1.1.1.1.1", "ether1", "OctetString")
    fake = FakeDiscoveryClient(
        {
            first: SnmpWalkResult((shared,)),
            second: SnmpWalkResult(
                (
                    shared,
                    SnmpVarBind("1.3.6.1.2.1.31.1.1.1.1.2", "ether2", "OctetString"),
                )
            ),
        }
    )
    factory, service, target_id = _service(fake)
    with factory() as session:
        _enable(session, service, target_id)
    result = asyncio.run(service.discover_target(target_id, (first, second), max_results=2))
    assert len(result.items) == 2
    assert result.truncated is True


def test_catalog_marks_system_and_unknown_oids() -> None:
    assert standard_oid_name("1.3.6.1.2.1.1.5.0") == "sysName.0"
    assert is_system_oid("1.3.6.1.2.1.1.5.0") is True
    assert standard_oid_name("1.3.6.1.4.1.14988.1.1.3.10.0") is None


def test_discovery_roots_validate_custom_oid() -> None:
    assert discovery_roots("custom", ".1.3.6.1.4.1.14988") == (
        "1.3.6.1.4.1.14988",
    )
    assert discovery_roots("system") == ("1.3.6.1.2.1.1",)


def test_discovery_store_is_scoped_to_target_and_user() -> None:
    store = SnmpDiscoveryStore(ttl_seconds=60, max_sessions=2)
    result = SnmpDiscoveryResult("ok", "ok", (), ("1.3.6.1.2.1.1",))
    token = store.put(target_id=10, user_id=20, result=result)
    assert store.get(token, target_id=10, user_id=20) is result
    assert store.get(token, target_id=11, user_id=20) is None
    assert store.get(token, target_id=10, user_id=21) is None


def test_discovery_categories_make_standard_results_readable() -> None:
    assert discovery_oid_category("1.3.6.1.2.1.1.5.0") == "system"
    assert discovery_oid_category("1.3.6.1.2.1.2.2.1.8.1") == "port_status"
    assert discovery_oid_category("1.3.6.1.2.1.31.1.1.1.6.1") == "traffic"
    assert discovery_oid_category("1.3.6.1.2.1.2.2.1.14.1") == "errors"
    assert discovery_oid_category("1.3.6.1.2.1.31.1.1.1.1.1") == "interface"
    assert discovery_oid_category("1.3.6.1.4.1.14988.1.1.3.10.0") == "vendor"
    assert discovery_oid_category_label("1.3.6.1.2.1.31.1.1.1.6.1") == "Трафик"


def test_recommended_filter_marks_practical_core_oids() -> None:
    assert is_recommended_oid("1.3.6.1.2.1.1.3.0") is True
    assert is_recommended_oid("1.3.6.1.2.1.31.1.1.1.6.5") is True
    assert is_recommended_oid("1.3.6.1.2.1.31.1.1.1.10.5") is True
    assert is_recommended_oid("1.3.6.1.2.1.2.2.1.3.5") is False
    assert is_recommended_oid("1.3.6.1.4.1.14988.1.1.3.10.0") is False
