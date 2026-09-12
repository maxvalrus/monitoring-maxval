import re
from collections.abc import Generator
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from monitoring.db import Base, get_db
from monitoring.main import app
from monitoring.models import AppSetting, AuditLog, User, UserRole, UserSession
from monitoring.services.auth import create_user
from monitoring.services.smtp_settings import SMTP_SETTING_KEYS


def csrf_from(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def login(client: TestClient, username: str, password: str) -> None:
    page = client.get("/login")
    response = client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": csrf_from(page.text)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/"


def make_web_database():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine, expire_on_commit=False)


def test_login_admin_write_and_viewer_read_only() -> None:
    _, factory = make_web_database()

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with factory() as session:
            create_user(session, "admin", "administrator password", UserRole.ADMIN)
            create_user(session, "viewer", "viewer secure password", UserRole.VIEWER)
            session.add_all(
                [
                    AppSetting(
                        key="notifications_enabled",
                        value="false",
                        description="Автоматические уведомления",
                    ),
                    AppSetting(
                        key="display_timezone",
                        value="Europe/Moscow",
                        description="Часовой пояс интерфейса",
                    ),
                ]
            )
            for key in SMTP_SETTING_KEYS:
                session.add(
                    AppSetting(
                        key=key,
                        value=(
                            "587"
                            if key == "smtp_port"
                            else "true"
                            if key == "smtp_enabled"
                            else ""
                        ),
                        description=key,
                    )
                )
            session.commit()

        with TestClient(app, base_url="https://localhost") as admin_client:
            assert admin_client.get("/", follow_redirects=False).status_code == 303
            login_page = admin_client.get("/login")
            assert 'class="login-heading"' in login_page.text
            assert "favicon.svg" in login_page.text
            favicon = admin_client.get("/static/favicon.svg")
            assert favicon.status_code == 200
            assert favicon.headers["content-type"].startswith("image/svg+xml")
            login(admin_client, "admin", "administrator password")
            dashboard = admin_client.get("/")
            assert dashboard.status_code == 200
            assert dashboard.headers["cache-control"] == "no-store"
            assert dashboard.headers["x-frame-options"] == "DENY"
            assert "frame-ancestors 'none'" in dashboard.headers["content-security-policy"]
            assert 'href="/incidents"' in dashboard.text
            assert 'class="user-menu"' in dashboard.text
            assert 'class="header-user-name">admin</span>' in dashboard.text
            assert 'class="header-user-role">администратор</span>' in dashboard.text
            assert 'class="theme-toggle-icon"' in dashboard.text
            assert 'class="link-button logout-button"' in dashboard.text
            assert dashboard.text.index('data-theme-toggle') < dashboard.text.index(
                'class="header-user-name"'
            )
            assert 'class="brand-mark"' in dashboard.text
            assert 'action="/checks/run-now"' in dashboard.text
            cookie = admin_client.cookies.get("monitoring_session_https")
            assert cookie is not None
            csrf = csrf_from(dashboard.text)
            scheduler = admin_client.app.state.scheduler
            with patch.object(scheduler, "trigger_all", return_value=True) as trigger:
                manual_check = admin_client.post(
                    "/checks/run-now",
                    data={"csrf_token": csrf},
                    follow_redirects=False,
                )
            assert manual_check.status_code == 303
            assert "notice=" in manual_check.headers["location"]
            trigger.assert_called_once_with()
            with patch.object(scheduler, "trigger_all", return_value=True) as trigger:
                wallboard_check = admin_client.post(
                    "/checks/run-now",
                    data={"csrf_token": csrf, "return_to": "/wallboard"},
                    follow_redirects=False,
                )
            assert wallboard_check.status_code == 303
            assert wallboard_check.headers["location"].startswith("/wallboard?notice=")
            trigger.assert_called_once_with()
            rejected = admin_client.post(
                "/sites",
                data={"name": "Без CSRF", "description": ""},
                follow_redirects=False,
            )
            assert rejected.status_code == 400
            created = admin_client.post(
                "/sites",
                data={
                    "name": "Центральный офис",
                    "description": "Основная площадка",
                    "csrf_token": csrf,
                },
                follow_redirects=False,
            )
            assert created.status_code == 303
            assert "Центральный офис" in admin_client.get("/sites").text
            assert admin_client.get("/incidents").status_code == 200

            settings_page = admin_client.get("/settings")
            disabled_clean_smtp = admin_client.post(
                "/settings/smtp",
                data={
                    "csrf_token": csrf_from(settings_page.text),
                    "smtp_port": "587",
                },
                follow_redirects=False,
            )
            assert disabled_clean_smtp.status_code == 303
            assert disabled_clean_smtp.headers["location"].startswith("/settings?notice=")
            with factory() as session:
                smtp_channel = session.get(AppSetting, "smtp_enabled")
                assert smtp_channel is not None and smtp_channel.value == "false"

            enable_without_smtp = admin_client.post(
                "/settings",
                data={
                    "key": "notifications_enabled",
                    "value": "true",
                    "csrf_token": csrf_from(settings_page.text),
                },
                follow_redirects=False,
            )
            assert enable_without_smtp.status_code == 303
            assert "notice=" in enable_without_smtp.headers["location"]

            changed_timezone = admin_client.post(
                "/settings",
                data={
                    "key": "display_timezone",
                    "value": "Europe/Berlin",
                    "csrf_token": csrf_from(settings_page.text),
                },
                follow_redirects=False,
            )
            assert changed_timezone.status_code == 303
            assert "notice=" in changed_timezone.headers["location"]

            saved_smtp = admin_client.post(
                "/settings/smtp",
                data={
                    "csrf_token": csrf_from(settings_page.text),
                    "smtp_host": "smtp.example.test",
                    "smtp_port": "587",
                    "smtp_username": "monitoring",
                    "smtp_password": "private-smtp-password",
                    "smtp_enabled": "true",
                    "smtp_sender": "monitoring@example.test",
                    "smtp_recipient": "admin@example.test",
                    "smtp_starttls": "true",
                },
                follow_redirects=False,
            )
            assert saved_smtp.status_code == 303
            assert saved_smtp.headers["location"].startswith("/settings?notice=")
            settings_page = admin_client.get("/settings")
            assert "smtp.example.test" in settings_page.text
            assert 'name="smtp_enabled" value="true" checked' in settings_page.text
            assert "private-smtp-password" not in settings_page.text
            with factory() as session:
                password_before_update = session.get(AppSetting, "smtp_password")
                assert password_before_update is not None
                encrypted_password = password_before_update.value

            saved_without_new_password = admin_client.post(
                "/settings/smtp",
                data={
                    "csrf_token": csrf_from(settings_page.text),
                    "smtp_host": "smtp.changed.example.test",
                    "smtp_port": "587",
                    "smtp_username": "monitoring",
                    "smtp_enabled": "true",
                    "smtp_sender": "monitoring@example.test",
                    "smtp_recipient": "admin@example.test",
                    "smtp_starttls": "true",
                },
                follow_redirects=False,
            )
            assert saved_without_new_password.status_code == 303
            assert saved_without_new_password.headers["location"].startswith(
                "/settings?notice="
            )
            settings_page = admin_client.get("/settings")
            assert "smtp.changed.example.test" in settings_page.text
            with patch(
                "monitoring.web.routes.EmailNotifier.send", new=AsyncMock()
            ) as send:
                test_email = admin_client.post(
                    "/settings/test-email",
                    data={"csrf_token": csrf_from(settings_page.text)},
                    follow_redirects=False,
                )
            assert test_email.status_code == 303
            assert test_email.headers["location"].startswith("/settings?notice=")
            send.assert_awaited_once()
            assert send.await_args.kwargs == {"force": True}

        with factory() as session:
            email_enabled = session.get(AppSetting, "notifications_enabled")
            assert email_enabled is not None and email_enabled.value == "true"
            timezone = session.get(AppSetting, "display_timezone")
            assert timezone is not None and timezone.value == "Europe/Berlin"
            smtp_password = session.get(AppSetting, "smtp_password")
            assert smtp_password is not None
            assert smtp_password.value == encrypted_password
            assert smtp_password.value != "private-smtp-password"
            assert "private-smtp-password" not in smtp_password.value
            smtp_audits = session.scalars(
                select(AuditLog).where(AuditLog.action == "setting.smtp_updated")
            ).all()
            assert len(smtp_audits) == 3
            for smtp_audit in smtp_audits:
                assert "private-smtp-password" not in (smtp_audit.details or "")
                assert "smtp.example.test" not in (smtp_audit.details or "")
                assert "admin@example.test" not in (smtp_audit.details or "")
            manual_audits = session.scalars(
                select(AuditLog).where(AuditLog.action == "check.manual_started")
            ).all()
            assert len(manual_audits) == 2
            assert all(item.entity_type == "monitoring" for item in manual_audits)

        with TestClient(app, base_url="https://localhost") as viewer_client:
            login(viewer_client, "viewer", "viewer secure password")
            sites_page = viewer_client.get("/sites")
            assert sites_page.status_code == 200
            denied = viewer_client.post(
                "/sites",
                data={
                    "name": "Запрещённая площадка",
                    "description": "",
                    "csrf_token": csrf_from(sites_page.text),
                },
                follow_redirects=False,
            )
            assert denied.status_code == 403
            manual_denied = viewer_client.post(
                "/checks/run-now",
                data={"csrf_token": csrf_from(sites_page.text)},
                follow_redirects=False,
            )
            assert manual_denied.status_code == 403
            logout = viewer_client.post(
                "/logout",
                data={"csrf_token": csrf_from(sites_page.text)},
                follow_redirects=False,
            )
            assert logout.status_code == 303
            assert logout.headers["location"] == "/login"
            assert viewer_client.get("/", follow_redirects=False).status_code == 303
    finally:
        app.dependency_overrides.clear()


def test_last_admin_and_password_session_protections() -> None:
    _, factory = make_web_database()

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with factory() as session:
            admin = create_user(session, "admin", "administrator password", UserRole.ADMIN)
            session.commit()
            admin_id = admin.id

        with TestClient(app, base_url="https://localhost") as client:
            login(client, "admin", "administrator password")
            csrf = csrf_from(client.get("/users").text)
            protected = client.post(
                f"/users/{admin_id}/update",
                data={"role": "viewer", "active": "true", "csrf_token": csrf},
                follow_redirects=False,
            )
            assert protected.status_code == 303
            assert "error=" in protected.headers["location"]

            changed = client.post(
                f"/users/{admin_id}/password",
                data={"password": "a completely new password", "csrf_token": csrf},
                follow_redirects=False,
            )
            assert changed.status_code == 303
            assert client.get("/", follow_redirects=False).status_code == 303

        with factory() as session:
            user = session.get(User, admin_id)
            assert user is not None and user.role == UserRole.ADMIN and user.active
            assert session.query(UserSession).count() == 0
    finally:
        app.dependency_overrides.clear()
