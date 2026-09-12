import json
import re
from collections.abc import Generator
from pathlib import Path
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from monitoring.checks.base import CheckOutcome
from monitoring.db import Base, get_db
from monitoring.main import app
from monitoring.models import (
    AuditLog,
    CheckResult,
    CheckStatus,
    Incident,
    IncidentSeverity,
    IncidentSourceKind,
    IncidentStatus,
    MonitorTarget,
    Site,
    TargetCheck,
    UserRole,
)
from monitoring.services.auth import create_user
from monitoring.services.target_checks import ensure_primary_check


def _csrf_from(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def _database():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def _login(client: TestClient) -> None:
    page = client.get("/login")
    response = client.post(
        "/login",
        data={
            "username": "admin",
            "password": "administrator password",
            "csrf_token": _csrf_from(page.text),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_admin_can_get_current_http_status_for_unsaved_service(monkeypatch) -> None:
    factory = _database()

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with factory() as session:
            create_user(session, "admin", "administrator password", UserRole.ADMIN)
            target = MonitorTarget(
                site=Site(name="Web"),
                name="Portal",
                kind="website",
                checker_type="tcp",
                address="192.0.2.70",
                port=443,
                interval_seconds=300,
            )
            session.add(target)
            session.flush()
            ensure_primary_check(session, target)
            session.commit()
            target_id = target.id

        with TestClient(app, base_url="https://localhost") as client:
            _login(client)
            page = client.get(f"/targets?focus_target_id={target_id}")
            probe = AsyncMock(
                return_value=CheckOutcome(
                    CheckStatus.DOWN,
                    latency_ms=123.45,
                    message="HTTP вернул код 503",
                    http_status_code=503,
                )
            )
            monkeypatch.setattr(client.app.state.scheduler.monitoring, "probe_http_status", probe)

            response = client.post(
                f"/targets/{target_id}/checks/current-http-status",
                data={
                    "csrf_token": _csrf_from(page.text),
                    "checker_type": "https",
                    "address_override": "status.example.test",
                    "port": "8443",
                    "path": "health",
                    "timeout_seconds": "2.5",
                },
            )

            assert response.status_code == 200
            assert response.json() == {"status_code": 503, "latency_ms": 123.45}
            probe.assert_awaited_once_with(
                checker_type="https",
                address="status.example.test",
                port=8443,
                path="/health",
                timeout_seconds=2.5,
            )
            assert 'data-current-http-status' in page.text
    finally:
        app.dependency_overrides.clear()


def test_admin_can_manage_secondary_target_check() -> None:
    factory = _database()

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with factory() as session:
            create_user(session, "admin", "administrator password", UserRole.ADMIN)
            target = MonitorTarget(
                site=Site(name="Центральный офис"),
                name="Server-01",
                kind="server",
                checker_type="icmp",
                address="192.0.2.10",
                port=1,
                interval_seconds=300,
            )
            session.add(target)
            session.flush()
            ensure_primary_check(session, target)
            session.commit()
            target_id = target.id

        with TestClient(app, base_url="https://localhost") as client:
            _login(client)
            history = client.get(f"/targets/{target_id}/history")
            assert history.status_code == 200
            assert 'id="services"' not in history.text
            page = client.get(f"/targets?focus_target_id={target_id}")
            assert page.status_code == 200
            assert "Сервисы" in page.text
            assert "Добавить сервис" in page.text
            assert re.search(r'<option value="dns"[^>]*>dns</option>', page.text)
            assert 'aria-label="Справка по сервисам объекта"' in page.text
            assert client.get(f"/targets/{target_id}/checks").status_code == 405

            create_page = client.get(
                f"/targets?focus_target_id={target_id}&add_service={target_id}"
            )
            assert create_page.status_code == 200
            assert re.search(
                rf'id="target-{target_id}-service-create"[^>]*\sopen(?:\s|>)',
                create_page.text,
            )

            created = client.post(
                f"/targets/{target_id}/checks",
                data={
                    "csrf_token": _csrf_from(page.text),
                    "name": "1С",
                    "checker_type": "tcp",
                    "address_override": "",
                    "port": "1541",
                    "path": "/",
                    "timeout_seconds": "2.5",
                    "retries": "1",
                    "return_to": f"/targets?focus_target_id={target_id}",
                },
                follow_redirects=False,
            )
            assert created.status_code == 303

            dns_created = client.post(
                f"/targets/{target_id}/checks",
                data={
                    "csrf_token": _csrf_from(page.text),
                    "name": "DNS сайта",
                    "checker_type": "dns",
                    "dns_name": "example.com.",
                    "dns_record_type": "A",
                    "dns_expected_address": "192.0.2.15",
                    "dns_max_response_ms": "150",
                    "timeout_seconds": "2.5",
                    "retries": "1",
                    "return_to": f"/targets?focus_target_id={target_id}",
                },
                follow_redirects=False,
            )
            assert dns_created.status_code == 303

            with factory() as session:
                check = session.scalar(
                    select(TargetCheck).where(
                        TargetCheck.target_id == target_id,
                        TargetCheck.name == "1С",
                    )
                )
                assert check is not None
                assert check.is_primary is False
                assert check.checker_type == "tcp"
                assert check.port == 1541
                assert check.timeout_seconds == 2.5
                assert check.retries == 1
                dns_check = session.scalar(
                    select(TargetCheck).where(
                        TargetCheck.target_id == target_id,
                        TargetCheck.name == "DNS сайта",
                    )
                )
                assert dns_check is not None
                assert (
                    dns_check.dns_name,
                    dns_check.dns_record_type,
                    dns_check.dns_expected_address,
                    dns_check.dns_max_response_ms,
                ) == ("example.com", "A", "192.0.2.15", 150.0)
                check_id = check.id
                assert session.scalar(
                    select(AuditLog).where(AuditLog.action == "target_check.created")
                ) is not None
                incident = Incident(
                    target_id=target_id,
                    check_id=check_id,
                    status=IncidentStatus.OPEN,
                    source_kind=IncidentSourceKind.CHECK,
                    severity="critical",
                    failure_count=2,
                    last_message="1С недоступна",
                )
                session.add(incident)
                session.commit()
                incident_id = incident.id

            page = client.get(f"/targets?focus_target_id={target_id}")
            assert "1С" in page.text
            assert "TCP" in page.text
            assert "1541" in page.text
            assert page.text.index('class="service-status-column">Статус</th>') < page.text.index('data-label="Сервис"><div class="service-name"')
            assert 'aria-label="Сервис 1С включён"' in page.text
            assert "service-row-menu" not in page.text
            assert 'aria-label="Изменить сервис 1С"' in page.text
            assert 'aria-label="Отключить сервис 1С"' in page.text
            assert 'aria-label="Удалить сервис 1С"' in page.text
            assert "Основная доступность</strong>" not in page.text
            history = client.get(f"/targets/{target_id}/history")
            assert 'id="services"' in history.text
            assert "1С" in history.text
            assert "Основная доступность" not in history.text
            updated = client.post(
                f"/targets/{target_id}/checks/{check_id}/update",
                data={
                    "csrf_token": _csrf_from(page.text),
                    "name": "1С",
                    "checker_type": "tcp",
                    "address_override": "",
                    "port": "1542",
                    "path": "/",
                    "timeout_seconds": "2.5",
                    "retries": "1",
                    "return_to": f"/targets?focus_target_id={target_id}",
                },
                follow_redirects=False,
            )
            assert updated.status_code == 303
            with factory() as session:
                updated_check = session.get(TargetCheck, check_id)
                assert updated_check.port == 1542
                assert updated_check.config_version == 2

            page = client.get(f"/targets?focus_target_id={target_id}")
            toggled = client.post(
                f"/targets/{target_id}/checks/{check_id}/toggle",
                data={
                    "csrf_token": _csrf_from(page.text),
                    "return_to": f"/targets?focus_target_id={target_id}",
                },
                follow_redirects=False,
            )
            assert toggled.status_code == 303
            with factory() as session:
                disabled_check = session.get(TargetCheck, check_id)
                assert disabled_check.enabled is False
                assert disabled_check.config_version == 3
                incident = session.get(Incident, incident_id)
                assert incident.status == IncidentStatus.RESOLVED
                assert "отключена администратором" in (incident.last_message or "")
                assert incident.recovery_notification_attempted_at is None
                orphan = Incident(
                    target_id=target_id,
                    check_id=check_id,
                    status=IncidentStatus.OPEN,
                    source_kind=IncidentSourceKind.CHECK,
                    severity="critical",
                    failure_count=2,
                    last_message="остаточный открытый инцидент",
                )
                session.add(orphan)
                session.commit()
                orphan_id = orphan.id

            page = client.get(f"/targets?focus_target_id={target_id}")
            assert 'aria-label="Сервис 1С отключён"' in page.text
            deleted = client.post(
                f"/targets/{target_id}/checks/{check_id}/delete",
                data={
                    "csrf_token": _csrf_from(page.text),
                    "return_to": f"/targets?focus_target_id={target_id}",
                },
                follow_redirects=False,
            )
            assert deleted.status_code == 303
            with factory() as session:
                assert session.get(TargetCheck, check_id) is None
                orphan = session.get(Incident, orphan_id)
                assert orphan.status == IncidentStatus.RESOLVED
                assert orphan.check_id is None
                assert "удалена администратором" in (orphan.last_message or "")
                assert orphan.recovery_notification_attempted_at is None
                assert session.scalar(
                    select(TargetCheck).where(
                        TargetCheck.target_id == target_id,
                        TargetCheck.is_primary.is_(True),
                    )
                ) is not None
    finally:
        app.dependency_overrides.clear()


def test_admin_can_configure_http_deep_check_and_non_http_clears_it() -> None:
    factory = _database()

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with factory() as session:
            create_user(session, "admin", "administrator password", UserRole.ADMIN)
            target = MonitorTarget(
                site=Site(name="Web"),
                name="Server-01",
                kind="server",
                checker_type="icmp",
                address="192.0.2.10",
                port=1,
                interval_seconds=300,
            )
            session.add(target)
            session.flush()
            ensure_primary_check(session, target)
            session.commit()
            target_id = target.id

        with TestClient(app, base_url="https://localhost") as client:
            _login(client)
            page = client.get(f"/targets?focus_target_id={target_id}")
            assert 'data-http-deep-options' in page.text
            assert 'data-tls-monitor-options' in page.text
            created = client.post(
                f"/targets/{target_id}/checks",
                data={
                    "csrf_token": _csrf_from(page.text),
                    "name": "Web",
                    "checker_type": "https",
                    "port": "443",
                    "path": "/health",
                    "timeout_seconds": "",
                    "retries": "0",
                    "expected_status": "200",
                    "content_contains": " healthy ",
                    "content_not_contains": "error",
                    "max_response_ms": "250.5",
                    "tls_monitor_enabled": "true",
                    "tls_warning_days": "30",
                    "tls_critical_days": "7",
                },
                follow_redirects=False,
            )
            assert created.status_code == 303

            with factory() as session:
                check = session.scalar(
                    select(TargetCheck).where(
                        TargetCheck.target_id == target_id,
                        TargetCheck.is_primary.is_(False),
                    )
                )
                assert check is not None
                assert check.http_expected_status == 200
                assert check.http_content_contains == "healthy"
                assert check.http_content_not_contains == "error"
                assert check.http_max_response_ms == 250.5
                assert (
                    check.tls_monitor_enabled,
                    check.tls_warning_days,
                    check.tls_critical_days,
                ) == (True, 30, 7)
                check_id = check.id
                audit = session.scalar(
                    select(AuditLog).where(AuditLog.action == "target_check.created")
                )
                assert audit is not None
                assert json.loads(audit.details or "{}")["http_deep_check"]["expected_status"] == 200
                assert json.loads(audit.details or "{}")["tls_monitoring"]["enabled"] is True
                session.add(
                    Incident(
                        target_id=target_id,
                        check_id=check_id,
                        source_kind=IncidentSourceKind.CHECK_TLS,
                        severity=IncidentSeverity.WARNING,
                        status=IncidentStatus.OPEN,
                        failure_count=1,
                        last_message="TLS: сертификат истекает через 20 дн.",
                    )
                )
                session.commit()

            page = client.get(f"/targets?focus_target_id={target_id}")
            updated = client.post(
                f"/targets/{target_id}/checks/{check_id}/update",
                data={
                    "csrf_token": _csrf_from(page.text),
                    "name": "TCP",
                    "checker_type": "tcp",
                    "port": "443",
                    "path": "/",
                    "timeout_seconds": "",
                    "retries": "0",
                    "expected_status": "200",
                    "content_contains": "healthy",
                    "content_not_contains": "error",
                    "max_response_ms": "250",
                    "tls_monitor_enabled": "true",
                    "tls_warning_days": "30",
                    "tls_critical_days": "7",
                },
                follow_redirects=False,
            )
            assert updated.status_code == 303

            with factory() as session:
                check = session.get(TargetCheck, check_id)
                assert check is not None
                assert check.config_version == 2
                assert (
                    check.http_expected_status,
                    check.http_content_contains,
                    check.http_content_not_contains,
                    check.http_max_response_ms,
                ) == (None, None, None, None)
                assert (
                    check.tls_monitor_enabled,
                    check.tls_warning_days,
                    check.tls_critical_days,
                ) == (False, None, None)
                tls_incident = session.scalar(
                    select(Incident).where(
                        Incident.source_kind == IncidentSourceKind.CHECK_TLS
                    )
                )
                assert tls_incident is not None
                assert tls_incident.status == IncidentStatus.RESOLVED
    finally:
        app.dependency_overrides.clear()


def test_viewer_can_read_services_but_cannot_manage_them() -> None:
    factory = _database()

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with factory() as session:
            create_user(session, "viewer", "viewer password", UserRole.VIEWER)
            target = MonitorTarget(
                site=Site(name="Филиал"),
                name="Server-02",
                kind="server",
                checker_type="tcp",
                address="192.0.2.20",
                port=443,
                interval_seconds=300,
            )
            session.add(target)
            session.flush()
            ensure_primary_check(session, target)
            session.add(
                TargetCheck(
                    target_id=target.id,
                    name="Web",
                    checker_type="https",
                    port=443,
                    enabled=True,
                    is_primary=False,
                    display_order=1,
                )
            )
            session.commit()
            target_id = target.id

        with TestClient(app, base_url="https://localhost") as client:
            page = client.get("/login")
            response = client.post(
                "/login",
                data={
                    "username": "viewer",
                    "password": "viewer password",
                    "csrf_token": _csrf_from(page.text),
                },
                follow_redirects=False,
            )
            assert response.status_code == 303
            history = client.get(f"/targets/{target_id}/history")
            assert history.status_code == 200
            assert "Сервисы" in history.text
            assert "Web" in history.text
            assert "Основная доступность" not in history.text
            assert "service-add-action" not in history.text
            assert "service-row-menu" not in history.text
            assert client.get(f"/targets/{target_id}/checks").status_code == 405
            assert client.post(
                f"/targets/{target_id}/checks/current-http-status",
                data={"csrf_token": "not-used-for-viewer"},
            ).status_code == 403
    finally:
        app.dependency_overrides.clear()


def test_nested_service_editor_keeps_target_editor_open() -> None:
    javascript = Path("src/monitoring/static/app.js").read_text(encoding="utf-8")

    assert "item !== editor && !item.contains(editor)" in javascript


def test_target_health_filter_precedes_pagination_and_history_is_read_only() -> None:
    factory = _database()

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with factory() as session:
            create_user(session, "admin", "administrator password", UserRole.ADMIN)
            site = Site(name="Health")
            healthy = MonitorTarget(
                site=site,
                name="Healthy",
                kind="server",
                checker_type="icmp",
                address="192.0.2.30",
                port=1,
            )
            critical = MonitorTarget(
                site=site,
                name="Critical target",
                kind="server",
                checker_type="tcp",
                address="192.0.2.31",
                port=22,
            )
            session.add_all((healthy, critical))
            session.flush()
            ensure_primary_check(session, healthy)
            ensure_primary_check(session, critical)
            service = TargetCheck(
                target_id=critical.id,
                name="1С",
                checker_type="tcp",
                port=1541,
                enabled=True,
                is_primary=False,
                display_order=1,
            )
            session.add_all(
                (
                    service,
                    CheckResult(target_id=healthy.id, status="up", message="ok"),
                    CheckResult(target_id=critical.id, status="up", message="ok"),
                )
            )
            session.flush()
            session.add(
                Incident(
                    target_id=critical.id,
                    check_id=service.id,
                    status=IncidentStatus.OPEN,
                    source_kind=IncidentSourceKind.CHECK,
                    severity="critical",
                    failure_count=2,
                    last_message="1С недоступен",
                )
            )
            session.commit()
            critical_id = critical.id

        with TestClient(app, base_url="https://localhost") as client:
            _login(client)
            dashboard = client.get("/?health=critical&per_page=1")
            assert dashboard.status_code == 200
            assert "Critical target" in dashboard.text
            assert "Healthy" not in dashboard.text
            assert 'name="health"' in dashboard.text
            assert "1С недоступен" in dashboard.text

            history = client.get(f"/targets/{critical_id}/history")
            assert history.status_code == 200
            assert '<span class="badge badge-danger">Critical</span>' in history.text
            assert '<span class="badge badge-danger">Недоступен</span>' in history.text
            assert "Основная</strong>" not in history.text
            assert "service-add-action" not in history.text
            assert "service-row-menu" not in history.text
    finally:
        app.dependency_overrides.clear()
