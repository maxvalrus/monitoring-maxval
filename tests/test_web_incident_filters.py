import re
from collections.abc import Generator
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from monitoring.db import Base, get_db
from monitoring.main import app
from monitoring.models import AppSetting, CheckResult, Incident, MonitorTarget, Site, UserRole
from monitoring.services.auth import create_user


def csrf_from(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def test_incidents_filter_by_kind_and_status_and_use_database_timezone() -> None:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with factory() as session:
            create_user(session, "admin", "administrator password", UserRole.ADMIN)
            site = Site(name="Филиал")
            server = MonitorTarget(
                site=site,
                name="Сервер приложений",
                kind="server",
                address="192.0.2.10",
                port=443,
            )
            camera = MonitorTarget(
                site=site,
                name="Камера входа",
                kind="camera",
                address="192.0.2.20",
                port=80,
            )
            session.add_all(
                [
                    server,
                    camera,
                    AppSetting(
                        key="display_timezone",
                        value="Europe/Berlin",
                        description="Часовой пояс интерфейса",
                    ),
                ]
            )
            session.flush()
            session.add_all(
                [
                    Incident(target_id=server.id, status="open", failure_count=2),
                    Incident(target_id=camera.id, status="resolved", failure_count=2),
                    CheckResult(
                        target_id=camera.id,
                        status="up",
                        checked_at=datetime(2026, 8, 15, 12, 30, 45, tzinfo=UTC),
                    ),
                ]
            )
            session.commit()

        with TestClient(app, base_url="https://localhost") as client:
            login_page = client.get("/login")
            response = client.post(
                "/login",
                data={
                    "username": "admin",
                    "password": "administrator password",
                    "csrf_token": csrf_from(login_page.text),
                },
                follow_redirects=False,
            )
            assert response.status_code == 303

            incidents = client.get(
                "/incidents?kind=camera&status=resolved&per_page=10"
            )
            assert incidents.status_code == 200
            assert "Камера входа" in incidents.text
            assert "Сервер приложений" not in incidents.text
            assert "kind=camera" in incidents.text
            assert "status=resolved" in incidents.text
            assert "Всего: 1" in incidents.text

            opened = client.get("/incidents?kind=all&status=open&per_page=10")
            assert "Сервер приложений" in opened.text
            assert "Камера входа" not in opened.text
            assert "Всего: 1" in opened.text

            target_filtered = client.get(
                f"/incidents?status=all&target_id={camera.id}&per_page=10"
            )
            assert "Камера входа" in target_filtered.text
            assert "Сервер приложений" not in target_filtered.text
            assert f"target_id={camera.id}" in target_filtered.text
            assert "Снять фильтр" in target_filtered.text

            invalid_filter = client.get("/incidents?kind=invalid&per_page=10")
            assert "Камера входа" in invalid_filter.text
            assert "Сервер приложений" in invalid_filter.text

            dashboard = client.get("/")
            assert "15.08.2026 14:30:45 CEST" in dashboard.text
    finally:
        app.dependency_overrides.clear()
