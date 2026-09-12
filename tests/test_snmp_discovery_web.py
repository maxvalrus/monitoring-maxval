import asyncio
import re
from collections.abc import Generator
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from monitoring.config import Settings
from monitoring.db import Base, get_db
from monitoring.main import app
from monitoring.models import (
    MonitorTarget,
    Site,
    SnmpInterface,
    SnmpMetric,
    SnmpSupply,
    UserRole,
)
from monitoring.services.auth import create_user
from monitoring.services.snmp import SnmpService, SnmpTestResult
from monitoring.services.snmp_client import SnmpRequest, SnmpVarBind
from monitoring.services.snmp_discovery import (
    SnmpDiscoveryItem,
    SnmpDiscoveryResult,
)


def _csrf(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


class _NoopSnmpClient:
    async def get(self, request: SnmpRequest, oids):
        return [SnmpVarBind(oid, None, "NoSuchObject", "Объект OID не существует") for oid in oids]

    async def walk(self, request: SnmpRequest, root_oid: str, *, max_results: int):
        raise AssertionError("web discovery test should use its scheduler result")


class _DiscoveryScheduler:
    def __init__(self, result: SnmpDiscoveryResult, snmp_service: SnmpService) -> None:
        self.result = result
        self.snmp_service = snmp_service
        self.calls: list[tuple[int, tuple[str, ...]]] = []

    async def discover_snmp_now(
        self, target_id: int, roots: tuple[str, ...]
    ) -> SnmpDiscoveryResult:
        self.calls.append((target_id, roots))
        return self.result


class _InterfacePollScheduler:
    def __init__(self, result: SnmpTestResult) -> None:
        self.result = result
        self.calls: list[int] = []

    async def poll_snmp_interfaces_now(self, target_id: int) -> SnmpTestResult:
        self.calls.append(target_id)
        return self.result


def _database() -> tuple[sessionmaker[Session], int]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as session:
        create_user(session, "admin", "administrator password", UserRole.ADMIN)
        create_user(session, "viewer", "viewer password", UserRole.VIEWER)
        target = MonitorTarget(
            site=Site(name="Discovery"), name="switch", address="192.0.2.10", port=161
        )
        session.add(target)
        session.commit()
        return factory, target.id


def _override(factory: sessionmaker[Session]) -> Generator[Session, None, None]:
    with factory() as session:
        yield session


def _login(client: TestClient, username: str, password: str) -> None:
    page = client.get("/login")
    response = client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": _csrf(page.text)},
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_discovery_web_access_csrf_run_and_add() -> None:
    factory, target_id = _database()

    def override_db() -> Generator[Session, None, None]:
        yield from _override(factory)

    app.dependency_overrides[get_db] = override_db
    try:
        result = SnmpDiscoveryResult(
            "ok",
            "Найдено OID: 2",
            (
                SnmpDiscoveryItem(
                    "1.3.6.1.2.1.1.5.0", "sysName.0", "switch", "OctetString", None, True
                ),
                SnmpDiscoveryItem(
                    "1.3.6.1.4.1.14988.1.1.3.10.0", None, "ether1", "OctetString", None
                ),
            ),
            ("1.3.6.1.2.1.1",),
        )
        service = SnmpService(
            factory,
            Settings(secret_key="discovery-web-test", _env_file=None),
            _NoopSnmpClient(),
            asyncio.Semaphore(1),
        )

        with TestClient(app, base_url="https://localhost") as client:
            _login(client, "admin", "administrator password")
            page = client.get(f"/targets/{target_id}/snmp/discovery")
            assert page.status_code == 200
            csrf = _csrf(page.text)

            app.state.scheduler = _DiscoveryScheduler(result, service)
            rejected = client.post(
                f"/targets/{target_id}/snmp/discovery/run",
                data={"csrf_token": "invalid", "mode": "system"},
                follow_redirects=False,
            )
            assert rejected.status_code == 400

            scheduler = app.state.scheduler
            run = client.post(
                f"/targets/{target_id}/snmp/discovery/run",
                data={"csrf_token": csrf, "mode": "custom", "custom_oid": "1.3.6.1.4.1.14988"},
                follow_redirects=False,
            )
            assert run.status_code == 303
            assert scheduler.calls == [(target_id, ("1.3.6.1.4.1.14988",))]
            location = run.headers["location"]
            token = parse_qs(urlsplit(location).query)["token"][0]
            result_page = client.get(location)
            assert result_page.status_code == 200
            assert "ether1" in result_page.text
            assert "sysName.0" in result_page.text
            assert "Категория" in result_page.text
            assert "Только рекомендуемые" in result_page.text
            assert "Добавить</th>" not in result_page.text

            exported = client.get(f"/targets/{target_id}/snmp/discovery/export.json?token={token}")
            assert exported.status_code == 200
            assert exported.headers["content-type"].startswith("application/json")
            assert (
                'attachment; filename="snmp-discovery-target-'
                in exported.headers["content-disposition"]
            )
            payload = exported.json()
            assert payload["target"]["id"] == target_id
            assert payload["discovery"]["roots"] == ["1.3.6.1.2.1.1"]
            assert payload["items"][1]["oid"] == "1.3.6.1.4.1.14988.1.1.3.10.0"
            assert "community" not in exported.text.casefold()

            vendor_page = client.get(f"{location}&category=vendor")
            assert vendor_page.status_code == 200
            assert "ether1" in vendor_page.text
            assert 'value="vendor" selected' in vendor_page.text

            recommended_page = client.get(f"{location}&recommended=1")
            assert recommended_page.status_code == 200
            assert "sysName.0" in recommended_page.text
            assert "ether1" not in recommended_page.text

            add = client.post(
                f"/targets/{target_id}/snmp/discovery/add",
                data={
                    "csrf_token": csrf,
                    "token": token,
                    "selected_index": "1",
                    "oid_1": "1.3.6.1.4.1.14988.1.1.3.10.0",
                    "name_1": "ether1",
                    "unit_1": "",
                },
                follow_redirects=False,
            )
            assert add.status_code == 303
            assert "notice=" in add.headers["location"], add.headers["location"]

        with factory() as session:
            metric = session.scalar(select(SnmpMetric).where(SnmpMetric.target_id == target_id))
            assert metric is not None and metric.oid == "1.3.6.1.4.1.14988.1.1.3.10.0"
    finally:
        app.dependency_overrides.clear()


def test_invalid_formula_keeps_metric_create_form_values() -> None:
    factory, target_id = _database()

    def override_db() -> Generator[Session, None, None]:
        yield from _override(factory)

    app.dependency_overrides[get_db] = override_db
    try:
        service = SnmpService(
            factory,
            Settings(secret_key="metric-form-test", _env_file=None),
            _NoopSnmpClient(),
            asyncio.Semaphore(1),
        )
        result = SnmpDiscoveryResult("ok", "", (), ())
        with TestClient(app, base_url="https://localhost") as client:
            _login(client, "admin", "administrator password")
            page = client.get(f"/targets/{target_id}/snmp")
            app.state.scheduler = _DiscoveryScheduler(result, service)
            formula = "oid(1.3.6.1.4.1.14988.1.1.3.10.0) / 10"
            response = client.post(
                f"/targets/{target_id}/snmp/metrics",
                data={
                    "csrf_token": _csrf(page.text),
                    "name": "Температура CPU",
                    "source_kind": "formula",
                    "formula": formula,
                    "unit": "°C",
                    "enabled": "true",
                },
                follow_redirects=False,
            )

        assert response.status_code == 200
        assert response.headers["X-Monitoring-Page-Path"] == f"/targets/{target_id}/snmp"
        assert "Формула" in response.text
        assert 'value="Температура CPU"' in response.text
        assert f'value="{formula}"' in response.text
        assert 'value="°C"' in response.text
        with factory() as session:
            assert session.scalar(select(SnmpMetric.id)) is None
    finally:
        app.dependency_overrides.clear()


def test_viewer_cannot_open_discovery() -> None:
    factory, target_id = _database()

    def override_db() -> Generator[Session, None, None]:
        yield from _override(factory)

    app.dependency_overrides[get_db] = override_db
    try:
        with TestClient(app, base_url="https://localhost") as client:
            _login(client, "viewer", "viewer password")
            response = client.get(f"/targets/{target_id}/snmp/discovery")
            assert response.status_code == 403
    finally:
        app.dependency_overrides.clear()


def test_interfaces_are_visible_to_viewer_and_selection_is_admin_only() -> None:
    factory, target_id = _database()

    def override_db() -> Generator[Session, None, None]:
        yield from _override(factory)

    app.dependency_overrides[get_db] = override_db
    try:
        with factory() as session:
            interface = SnmpInterface(
                target_id=target_id,
                if_index=1,
                if_name="ether1",
                present=True,
            )
            session.add(interface)
            session.commit()
            interface_id = interface.id

        with TestClient(app, base_url="https://localhost") as viewer:
            _login(viewer, "viewer", "viewer password")
            page = viewer.get(f"/targets/{target_id}/snmp/interfaces")
            assert 'aria-label="Справка по интерфейсам"' in page.text
            assert "RX (receive)" in page.text and "TX (transmit)" in page.text
            assert page.status_code == 200
            assert "ether1" in page.text
            assert "Обновить список интерфейсов" not in page.text
            assert "/snmp/interfaces/poll" not in page.text
            assert "/snmp/discovery" not in page.text
            assert (
                viewer.post(f"/targets/{target_id}/snmp/interfaces/selection", data={}).status_code
                == 403
            )

        with TestClient(app, base_url="https://localhost") as admin:
            _login(admin, "admin", "administrator password")
            page = admin.get(f"/targets/{target_id}/snmp/interfaces")
            assert page.status_code == 200
            assert 'title="Обновить данные интерфейсов"' in page.text
            csrf = _csrf(page.text)
            poll_scheduler = _InterfacePollScheduler(
                SnmpTestResult("ok", "Данные выбранных интерфейсов обновлены", {})
            )
            app.state.scheduler = poll_scheduler
            poll = admin.post(
                f"/targets/{target_id}/snmp/interfaces/poll",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            assert poll.status_code == 303
            assert "notice=" in poll.headers["location"]
            assert poll_scheduler.calls == [target_id]
            response = admin.post(
                f"/targets/{target_id}/snmp/interfaces/selection",
                data={
                    "csrf_token": csrf,
                    "visible_interface_id": str(interface_id),
                    "selected_interface_id": str(interface_id),
                },
                follow_redirects=False,
            )
            assert response.status_code == 303, response.text
        with factory() as session:
            assert session.get(SnmpInterface, interface_id).monitor_enabled is True
    finally:
        app.dependency_overrides.clear()


def test_supplies_page_is_visible_to_viewer_and_managed_by_admin() -> None:
    factory, target_id = _database()

    def override_db() -> Generator[Session, None, None]:
        yield from _override(factory)

    with factory() as session:
        session.add(
            SnmpSupply(
                target_id=target_id,
                hr_device_index=7,
                supply_index=1,
                supply_class=3,
                supply_type=3,
                description="Black Toner",
                unit_code=19,
                max_capacity=100,
                level=42,
                percent_remaining=42,
                level_state="ok",
                present=True,
            )
        )
        session.commit()

    app.dependency_overrides[get_db] = override_db
    try:
        with TestClient(app, base_url="https://localhost") as viewer:
            _login(viewer, "viewer", "viewer password")
            page = viewer.get(f"/targets/{target_id}/snmp/supplies")
            assert page.status_code == 200
            assert "Black Toner" in page.text
            assert "42%" in page.text
            assert "/snmp/supplies/discover" not in page.text
            assert "/snmp/supplies/poll" not in page.text

        with TestClient(app, base_url="https://localhost") as admin:
            _login(admin, "admin", "administrator password")
            page = admin.get(f"/targets/{target_id}/snmp/supplies")
            assert page.status_code == 200
            assert "/snmp/supplies/discover" in page.text
            assert "/snmp/supplies/poll" in page.text
            assert _csrf(page.text)
    finally:
        app.dependency_overrides.clear()


def test_threshold_refresh_is_admin_only() -> None:
    factory, target_id = _database()

    def override_db() -> Generator[Session, None, None]:
        yield from _override(factory)

    app.dependency_overrides[get_db] = override_db
    try:
        with TestClient(app, base_url="https://localhost") as viewer:
            _login(viewer, "viewer", "viewer password")
            page = viewer.get(f"/targets/{target_id}/snmp/thresholds")
            assert page.status_code == 200
            assert "/snmp/thresholds/test" not in page.text
            assert (
                viewer.post(f"/targets/{target_id}/snmp/thresholds/test", data={}).status_code
                == 403
            )

        with TestClient(app, base_url="https://localhost") as admin:
            _login(admin, "admin", "administrator password")
            page = admin.get(f"/targets/{target_id}/snmp/thresholds")
            assert page.status_code == 200
            assert 'title="Обновить данные и проверить пороги"' in page.text
            scheduler = _InterfacePollScheduler(SnmpTestResult("ok", "Данные обновлены", {}))
            app.state.scheduler = scheduler
            response = admin.post(
                f"/targets/{target_id}/snmp/thresholds/test",
                data={"csrf_token": _csrf(page.text)},
                follow_redirects=False,
            )
            assert response.status_code == 303
            assert "notice=" in response.headers["location"]
            assert scheduler.calls == [target_id]
    finally:
        app.dependency_overrides.clear()
