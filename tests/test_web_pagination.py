import re
from collections.abc import Generator

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from monitoring.db import Base, get_db
from monitoring.main import app
from monitoring.models import AuditLog, Incident, MonitorTarget, Site, User, UserRole
from monitoring.services.auth import create_user


def csrf_from(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def test_all_required_lists_use_server_side_pagination_and_keep_filters() -> None:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with factory() as session:
            admin = create_user(session, "admin", "administrator password", UserRole.ADMIN)
            site = Site(name="Тестовая площадка")
            session.add_all([Site(name=f"Площадка {number:03d}") for number in range(104)])
            targets = [
                MonitorTarget(
                    site=site,
                    name=f"Объект {number:03d}",
                    kind="server",
                    address=f"192.0.2.{(number % 250) + 1}",
                    port=80,
                )
                for number in range(105)
            ]
            session.add_all(targets)
            session.flush()
            session.add_all(
                [
                    User(
                        username=f"viewer{number:03d}",
                        password_hash=admin.password_hash,
                        role=UserRole.VIEWER,
                    )
                    for number in range(104)
                ]
            )
            session.add_all(
                [
                    Incident(
                        target_id=targets[0].id,
                        status="resolved",
                        failure_count=2,
                    )
                    for _ in range(105)
                ]
            )
            session.add_all([AuditLog(action="test.event") for _ in range(105)])
            session.commit()
            site_id = site.id

        with TestClient(app, base_url="https://localhost") as client:
            login_page = client.get("/login")
            logged_in = client.post(
                "/login",
                data={
                    "username": "admin",
                    "password": "administrator password",
                    "csrf_token": csrf_from(login_page.text),
                },
                follow_redirects=False,
            )
            assert logged_in.status_code == 303

            pages = {
                "state": client.get(
                    f"/?site_id={site_id}&status=unknown&page=2&per_page=10"
                ),
                "targets": client.get(
                    f"/targets?site_id={site_id}&kind=server&page=2&per_page=10"
                ),
                "sites": client.get("/sites?page=2&per_page=10"),
                "users": client.get("/users?page=2&per_page=10"),
                "audit": client.get("/audit?page=2&per_page=10"),
                "incidents": client.get("/incidents?kind=server&page=2&per_page=10"),
                "reports": client.get(
                    f"/reports?site_id={site_id}&kind=server&page=2&per_page=10"
                ),
            }
            for response in pages.values():
                assert response.status_code == 200
                assert "Страница <strong>2</strong> из <strong>11</strong>" in response.text
                assert "Строк на странице" in response.text
                assert "Последняя страница" in response.text

            assert "Всего: 105" in pages["state"].text
            assert "status=unknown" in pages["state"].text
            assert "kind=server" in pages["targets"].text
            assert "kind=server" in pages["incidents"].text
            assert "kind=server" in pages["reports"].text
            assert pages["state"].text.count(
                'class="monitoring-object-row monitoring-objects-grid'
            ) == 10
            assert pages["targets"].text.count("target-table-row") == 10

            clamped = client.get("/incidents?page=999&per_page=10")
            assert "Страница <strong>11</strong> из <strong>11</strong>" in clamped.text
    finally:
        app.dependency_overrides.clear()
