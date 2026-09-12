import re
from collections.abc import Generator
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from monitoring.db import Base, get_db
from monitoring.main import app
from monitoring.models import (
    AuditLog,
    CheckResult,
    Incident,
    LoginBlock,
    MonitorTarget,
    Site,
    SnmpConfig,
    TargetCheck,
    UserRole,
)
from monitoring.services.auth import create_user, utc_now


def csrf_from(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def make_database():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def login(client: TestClient) -> None:
    page = client.get("/login")
    response = client.post(
        "/login",
        data={
            "username": "admin",
            "password": "administrator password",
            "csrf_token": csrf_from(page.text),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_checker_defaults_are_applied_without_an_icmp_port() -> None:
    factory = make_database()

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with factory() as session:
            create_user(session, "admin", "administrator password", UserRole.ADMIN)
            site = Site(name="Проверка портов")
            session.add(site)
            session.commit()
            site_id = site.id

        with TestClient(app, base_url="https://localhost") as client:
            login(client)
            csrf = csrf_from(client.get("/targets").text)
            common = {
                "site_id": str(site_id),
                "kind": "service",
                "address": "example.test",
                "interval_seconds": "300",
                "csrf_token": csrf,
            }
            for name, checker in (("HTTP", "http"), ("HTTPS", "https"), ("Ping", "icmp")):
                response = client.post(
                    "/targets",
                    data={
                        **common,
                        "name": name,
                        "checker_type": checker,
                        **(
                            {"notifications_suppressed": "true"}
                            if checker == "http"
                            else {}
                        ),
                    },
                    follow_redirects=False,
                )
                assert response.status_code == 303

            missing_tcp_port = client.post(
                "/targets",
                data={**common, "name": "TCP", "checker_type": "tcp"},
                follow_redirects=False,
            )
            assert "error=" in missing_tcp_port.headers["location"]

        with factory() as session:
            ports = {
                target.checker_type: target.port
                for target in session.scalars(select(MonitorTarget)).all()
            }
            assert ports == {"http": 80, "https": 443, "icmp": 1}
            http_target = session.scalar(
                select(MonitorTarget).where(MonitorTarget.checker_type == "http")
            )
            assert http_target is not None
            assert http_target.notifications_suppressed is True
    finally:
        app.dependency_overrides.clear()


def test_admin_can_create_a_target_copy_from_the_targets_page() -> None:
    factory = make_database()

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with factory() as session:
            create_user(session, "admin", "administrator password", UserRole.ADMIN)
            site = Site(name="Копирование")
            source = MonitorTarget(
                site=site,
                name="Исходный объект",
                kind="server",
                checker_type="tcp",
                address="192.0.2.10",
                port=443,
                interval_seconds=120,
                enabled=False,
            )
            session.add(source)
            session.flush()
            session.add(
                TargetCheck(
                    target_id=source.id,
                    name="HTTPS API",
                    checker_type="https",
                    address_override="api.example.test",
                    port=8443,
                    path="/health",
                    display_order=1,
                )
            )
            session.commit()
            source_id = source.id
            site_id = site.id

        with TestClient(app, base_url="https://localhost") as client:
            login(client)
            copy_page = client.get(f"/targets?copy_target_id={source_id}")
            assert copy_page.status_code == 200
            assert "Скопировать объект" in copy_page.text
            assert "Копия Исходный объект" in copy_page.text
            csrf = csrf_from(copy_page.text)
            response = client.post(
                "/targets",
                data={
                    "csrf_token": csrf,
                    "copy_target_id": str(source_id),
                    "site_id": str(site_id),
                    "name": "Новый объект",
                    "kind": "server",
                    "checker_type": "tcp",
                    "address": "192.0.2.11",
                    "port": "443",
                    "interval_seconds": "120",
                },
                follow_redirects=False,
            )
            assert response.status_code == 303
            assert "notice=" in response.headers["location"]

        with factory() as session:
            copied = session.scalar(
                select(MonitorTarget).where(MonitorTarget.name == "Новый объект")
            )
            assert copied is not None
            assert copied.enabled is False
            copied_checks = session.scalars(
                select(TargetCheck).where(TargetCheck.target_id == copied.id)
            ).all()
            assert len(copied_checks) == 2
            assert any(check.name == "HTTPS API" for check in copied_checks)
            clone_audit = session.scalar(
                select(AuditLog).where(AuditLog.action == "target.cloned")
            )
            assert clone_audit is not None
            assert "encrypted" not in (clone_audit.details or "")
    finally:
        app.dependency_overrides.clear()


def test_duplicate_target_is_rejected_and_notification_filter_is_server_side() -> None:
    factory = make_database()

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with factory() as session:
            create_user(session, "admin", "administrator password", UserRole.ADMIN)
            site = Site(name="Площадка")
            session.add(site)
            session.flush()
            camera = MonitorTarget(
                site=site,
                name="Камера входа",
                kind="camera",
                checker_type="tcp",
                address="camera.example.test",
                port=80,
                interval_seconds=300,
                notifications_suppressed=True,
                favorite=True,
            )
            server = MonitorTarget(
                site=site,
                name="Сервер",
                kind="server",
                checker_type="tcp",
                address="server.example.test",
                port=443,
                interval_seconds=300,
            )
            session.add_all([camera, server])
            session.flush()
            session.add_all(
                [
                    SnmpConfig(target_id=camera.id, enabled=True),
                    SnmpConfig(target_id=server.id, enabled=False),
                ]
            )
            session.commit()
            site_id = site.id

        with TestClient(app, base_url="https://localhost") as client:
            login(client)
            filtered = client.get(
                "/targets?notifications_suppressed=true&per_page=100"
            )
            assert filtered.status_code == 200
            assert "Камера входа</strong>" in filtered.text
            assert "<strong>Сервер</strong>" not in filtered.text
            assert 'name="notifications_suppressed"' in filtered.text
            assert 'value="true" selected' in filtered.text
            assert "notifications_suppressed=true" in filtered.text

            favorites = client.get("/targets?favorite=true&per_page=100")
            assert favorites.status_code == 200
            assert "<strong><span" in favorites.text
            assert "Камера входа</strong>" in favorites.text
            assert "<strong>Сервер</strong>" not in favorites.text
            assert 'name="favorite"' in favorites.text
            assert "favorite=true" in favorites.text

            snmp_targets = client.get("/targets?snmp_enabled=true&per_page=100")
            assert snmp_targets.status_code == 200
            assert "Камера входа</strong>" in snmp_targets.text
            assert "<strong>Сервер</strong>" not in snmp_targets.text
            assert 'name="snmp_enabled"' in snmp_targets.text
            assert 'value="true" selected' in snmp_targets.text
            assert "snmp_enabled=true" in snmp_targets.text

            duplicate = client.post(
                "/targets",
                data={
                    "site_id": str(site_id),
                    "name": "  КАМЕРА ВХОДА  ",
                    "kind": "camera",
                    "checker_type": "tcp",
                    "address": "CAMERA.EXAMPLE.TEST",
                    "port": "80",
                    "interval_seconds": "300",
                    "notifications_suppressed": "true",
                    "csrf_token": csrf_from(filtered.text),
                },
                follow_redirects=False,
            )
            assert duplicate.status_code == 303
            assert "error=" in duplicate.headers["location"]

        with factory() as session:
            assert session.query(MonitorTarget).count() == 2
    finally:
        app.dependency_overrides.clear()


def test_favorite_targets_are_first_and_admin_can_toggle_with_audit() -> None:
    factory = make_database()

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with factory() as session:
            create_user(session, "admin", "administrator password", UserRole.ADMIN)
            site = Site(name="Площадка")
            regular = MonitorTarget(
                site=site,
                name="Альфа",
                address="192.0.2.10",
                port=80,
            )
            favorite = MonitorTarget(
                site=site,
                name="Ядро",
                address="192.0.2.11",
                port=443,
                favorite=True,
            )
            session.add_all([regular, favorite])
            session.commit()
            regular_id = regular.id

        with TestClient(app, base_url="https://localhost") as client:
            login(client)
            first_page = client.get("/?per_page=1")
            assert first_page.status_code == 200
            assert "Ядро" in first_page.text
            assert "Альфа" not in first_page.text
            assert "Избранный объект" in first_page.text

            targets_page = client.get("/targets?per_page=100")
            assert f'action="/targets/{regular_id}/favorite"' in targets_page.text
            assert "target-favorite-action" in targets_page.text
            assert "target-toggle-action" in targets_page.text
            assert "target-delete-action" in targets_page.text
            assert "target-edit-button" in targets_page.text
            assert 'data-table-editor-toggle="target-' in targets_page.text
            toggled = client.post(
                f"/targets/{regular_id}/favorite",
                data={"csrf_token": csrf_from(targets_page.text)},
                follow_redirects=False,
            )
            assert toggled.status_code == 303

        with factory() as session:
            target = session.get(MonitorTarget, regular_id)
            assert target is not None and target.favorite is True
            assert session.scalar(
                select(AuditLog).where(AuditLog.action == "target.favorite_changed")
            ) is not None
    finally:
        app.dependency_overrides.clear()


def test_admin_can_delete_targets_sites_incidents_and_login_blocks() -> None:
    factory = make_database()

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with factory() as session:
            create_user(session, "admin", "administrator password", UserRole.ADMIN)
            site = Site(name="Удаляемая площадка")
            first = MonitorTarget(site=site, name="Первый", address="192.0.2.1", port=80)
            second = MonitorTarget(site=site, name="Второй", address="192.0.2.2", port=80)
            session.add_all([first, second])
            session.flush()
            session.add(CheckResult(target_id=first.id, status="down"))
            first_incident = Incident(target_id=first.id, status="open", failure_count=2)
            second_incident = Incident(target_id=second.id, status="resolved", failure_count=2)
            session.add_all([first_incident, second_incident])
            block = LoginBlock(
                username="unknown",
                ip_address="192.0.2.50",
                blocked_until=utc_now() + timedelta(minutes=10),
            )
            session.add(block)
            session.commit()
            site_id = site.id
            first_id = first.id
            first_incident_id = first_incident.id
            block_id = block.id

        with TestClient(app, base_url="https://localhost") as client:
            login(client)
            csrf = csrf_from(client.get("/sites").text)

            incidents_page = client.get("/incidents")
            assert "Отключить объект" in incidents_page.text
            assert "Действия с журналом" not in incidents_page.text
            assert "Удалить закрытые" in incidents_page.text
            disabled_target = client.post(
                f"/incidents/{first_incident_id}/disable-target",
                data={"csrf_token": csrf_from(incidents_page.text)},
                follow_redirects=False,
            )
            assert disabled_target.status_code == 303
            with factory() as session:
                disabled = session.get(MonitorTarget, first_id)
                assert disabled is not None and disabled.enabled is False

            deleted_incident = client.post(
                f"/incidents/{first_incident_id}/delete",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            assert deleted_incident.status_code == 303

            deleted_resolved = client.post(
                "/incidents/delete-resolved",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            assert deleted_resolved.status_code == 303
            with factory() as session:
                assert session.scalar(
                    select(Incident).where(Incident.status == "resolved")
                ) is None

            deleted_target = client.post(
                f"/targets/{first_id}/delete",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            assert deleted_target.status_code == 303

            cleared_incidents = client.post(
                "/incidents/delete-all",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            assert cleared_incidents.status_code == 303

            cleared_site = client.post(
                f"/sites/{site_id}/targets/delete-all",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            assert cleared_site.status_code == 303

            deleted_site = client.post(
                f"/sites/{site_id}/delete",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            assert deleted_site.status_code == 303

            users_page = client.get("/users")
            assert "Разблокировать" in users_page.text
            unblocked = client.post(
                f"/users/blocks/{block_id}/delete",
                data={"csrf_token": csrf_from(users_page.text)},
                follow_redirects=False,
            )
            assert unblocked.status_code == 303

        with factory() as session:
            assert session.query(Site).count() == 0
            assert session.query(MonitorTarget).count() == 0
            assert session.query(CheckResult).count() == 0
            assert session.query(Incident).count() == 0
            assert session.query(LoginBlock).count() == 0
            actions = set(session.scalars(select(AuditLog.action)).all())
            assert {
                "target.deleted",
                "target.enabled_changed",
                "incident.deleted",
                "incident.all_deleted",
                "site.targets_deleted",
                "site.deleted",
                "auth.block_removed",
            } <= actions
    finally:
        app.dependency_overrides.clear()


def test_audit_filters_and_sorting_are_server_side() -> None:
    factory = make_database()

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with factory() as session:
            create_user(session, "admin", "administrator password", UserRole.ADMIN)
            session.add_all(
                [
                    AuditLog(action="zeta.event", entity_type="site", ip_address="192.0.2.9"),
                    AuditLog(action="alpha.event", entity_type="target", ip_address="192.0.2.8"),
                ]
            )
            session.commit()

        with TestClient(app, base_url="https://localhost") as client:
            login(client)
            filtered = client.get(
                "/audit?action=alpha.event&entity_type=target&sort=created_at"
                "&direction=asc&per_page=10"
            )
            assert filtered.status_code == 200
            assert "<code>alpha.event</code>" in filtered.text
            assert "<code>zeta.event</code>" not in filtered.text
            assert "Всего: 1" in filtered.text
            assert 'value="alpha.event" selected' in filtered.text

            sorted_page = client.get("/audit?sort=action&direction=desc&per_page=100")
            assert sorted_page.text.index("<code>zeta.event</code>") < sorted_page.text.index(
                "<code>alpha.event</code>"
            )
    finally:
        app.dependency_overrides.clear()


def test_all_header_tables_apply_server_side_sorting() -> None:
    factory = make_database()

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with factory() as session:
            create_user(session, "admin", "administrator password", UserRole.ADMIN)
            create_user(session, "alpha-user", "alpha user password", UserRole.VIEWER)
            create_user(session, "zeta-user", "zeta user password", UserRole.VIEWER)
            alpha_site = Site(name="Альфа")
            beta_site = Site(name="Бета")
            session.add_all([alpha_site, beta_site])
            session.flush()
            session.add_all(
                [
                    MonitorTarget(
                        site=alpha_site,
                        name="Низкий порт",
                        address="192.0.2.10",
                        port=80,
                    ),
                    MonitorTarget(
                        site=alpha_site,
                        name="Высокий порт",
                        address="192.0.2.11",
                        port=443,
                    ),
                    LoginBlock(
                        username="block-a",
                        ip_address="192.0.2.20",
                        blocked_until=utc_now() + timedelta(minutes=10),
                    ),
                    LoginBlock(
                        username="block-z",
                        ip_address="192.0.2.21",
                        blocked_until=utc_now() + timedelta(minutes=20),
                    ),
                    AuditLog(action="alpha.sort"),
                    AuditLog(action="zeta.sort"),
                ]
            )
            session.commit()

        with TestClient(app, base_url="https://localhost") as client:
            login(client)

            sites = client.get("/sites?sort=name&direction=desc&per_page=100")
            assert sites.text.index("<strong>Бета</strong>") < sites.text.index(
                "<strong>Альфа</strong>"
            )

            targets = client.get("/targets?sort=port&direction=desc&per_page=100")
            assert targets.text.index("<strong>Высокий порт</strong>") < targets.text.index(
                "<strong>Низкий порт</strong>"
            )

            users = client.get("/users?sort=username&direction=desc&per_page=100")
            assert users.text.index("zeta-user") < users.text.index("alpha-user")

            blocks = client.get(
                "/users?block_sort=username&block_direction=desc&per_page=100"
            )
            assert blocks.text.index("block-z") < blocks.text.index("block-a")

            audit = client.get("/audit?sort=action&direction=desc&per_page=100")
            assert audit.text.index("<code>zeta.sort</code>") < audit.text.index(
                "<code>alpha.sort</code>"
            )
    finally:
        app.dependency_overrides.clear()
