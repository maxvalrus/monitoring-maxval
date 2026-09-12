import json
import re
from collections.abc import Generator

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from monitoring.db import Base, get_db
from monitoring.main import app
from monitoring.models import AuditLog, CheckResult, MonitorTarget, Site, UserRole, WorkSchedule
from monitoring.services.auth import create_user
from monitoring.services.scheduler import ManualTargetCheckResult


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


def test_exports_sort_and_manual_target_check() -> None:
    factory = make_database()

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with factory() as session:
            create_user(session, "admin", "administrator password", UserRole.ADMIN)
            early = WorkSchedule(id=10, name="Альфа", is_24x7=True)
            late = WorkSchedule(id=11, name="Январь", is_24x7=True)
            first = Site(name="Первая", schedule=late)
            second = Site(name="Вторая", schedule=early)
            target = MonitorTarget(
                site=first,
                name="Сервер",
                kind="server",
                checker_type="tcp",
                address="192.0.2.10",
                port=443,
                interval_seconds=300,
            )
            session.add_all([early, late, first, second, target])
            session.flush()
            session.add(CheckResult(target_id=target.id, status="up", latency_ms=5.5))
            session.add_all(
                [
                    AuditLog(
                        action="site.updated",
                        entity_type="site",
                        entity_id=str(first.id),
                        details='{"schedule": {"old": "А", "new": "Б"}}',
                    ),
                    AuditLog(
                        action="user.created",
                        entity_type="user",
                        entity_id="99",
                        details='{"name": "test"}',
                    ),
                ]
            )
            session.commit()
            target_id = target.id
            second_site_id = second.id

        with TestClient(app, base_url="https://localhost") as client:
            login(client)

            sites = client.get("/sites?sort=schedule&direction=asc&per_page=100")
            assert sites.status_code == 200
            assert sites.text.index("Вторая") < sites.text.index("Первая")

            ordered_sites = client.get("/sites")
            moved_site = client.post(
                f"/sites/{second_site_id}/move",
                data={
                    "csrf_token": csrf_from(ordered_sites.text),
                    "direction": "up",
                    "return_to": "/sites",
                },
                follow_redirects=False,
            )
            assert moved_site.status_code == 303
            assert moved_site.headers["location"].startswith("/sites?notice=")
            ordered_sites = client.get("/sites")
            assert ordered_sites.text.index("Вторая") < ordered_sites.text.index("Первая")

            audit_json = client.get(
                "/audit/export/json?scope=current&action=site.updated&sort=created_at&direction=desc"
            )
            assert audit_json.status_code == 200
            payload = json.loads(audit_json.content)
            assert payload["count"] == 1
            assert payload["records"][0]["action"] == "site.updated"
            assert isinstance(payload["records"][0]["details"], dict)

            audit_xlsx = client.get("/audit/export/xlsx?scope=all")
            assert audit_xlsx.status_code == 200
            assert audit_xlsx.content.startswith(b"PK")
            assert audit_xlsx.headers["content-type"].startswith(
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )

            report_xlsx = client.get("/reports/export/xlsx?hours=24&site_id=0&kind=all")
            assert report_xlsx.status_code == 200
            assert report_xlsx.content.startswith(b"PK")
            report_pdf = client.get("/reports/export/pdf?hours=24&site_id=0&kind=all")
            assert report_pdf.status_code == 200
            assert report_pdf.content.startswith(b"%PDF-")

            class FakeScheduler:
                def __init__(self) -> None:
                    self.called_with = None

                async def run_target_now(self, selected_id: int):
                    self.called_with = selected_id
                    return ManualTargetCheckResult(
                        status="up",
                        latency_ms=7.2,
                        message="OK",
                        off_hours=False,
                        saved=True,
                    )

            fake = FakeScheduler()
            app.state.scheduler = fake
            page = client.get("/")
            assert f'action="/checks/targets/{target_id}/run-now"' in page.text
            manual = client.post(
                f"/checks/targets/{target_id}/run-now",
                data={"csrf_token": csrf_from(page.text), "return_to": "/"},
                follow_redirects=False,
            )
            assert manual.status_code == 303
            assert fake.called_with == target_id
            assert manual.headers["location"].startswith("/?notice=")

            snmp_manual = client.post(
                f"/checks/targets/{target_id}/run-now",
                data={
                    "csrf_token": csrf_from(page.text),
                    "return_to": f"/targets/{target_id}/snmp",
                },
                follow_redirects=False,
            )
            assert snmp_manual.status_code == 303
            assert snmp_manual.headers["location"].startswith(
                f"/targets/{target_id}/snmp?notice="
            )
    finally:
        app.dependency_overrides.clear()
