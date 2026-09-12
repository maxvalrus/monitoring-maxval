import re
from collections.abc import Generator

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from monitoring.db import Base, get_db
from monitoring.main import app
from monitoring.models import AuditLog, User, UserRole
from monitoring.services.auth import create_user


def csrf_from(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def make_database():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
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


def test_user_warning_delete_and_audit_details() -> None:
    factory = make_database()

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with factory() as session:
            admin = create_user(session, "admin", "administrator password", UserRole.ADMIN)
            admin.must_change_default_password = True
            viewer = create_user(session, "viewer", "viewer password", UserRole.VIEWER)
            session.add(
                AuditLog(
                    user_id=admin.id,
                    action="site.updated",
                    entity_type="site",
                    entity_id="12",
                    details='{"name": {"old": "Старая", "new": "Новая"}}',
                    ip_address="192.0.2.10",
                )
            )
            session.commit()
            admin_id, viewer_id = admin.id, viewer.id

        with TestClient(app, base_url="https://localhost") as client:
            login(client)
            users = client.get("/users")
            assert "data-default-password-warning" in users.text
            assert f"ID: {admin_id}" in users.text
            assert f'action="/users/{viewer_id}/delete"' in users.text

            blocked = client.post(
                f"/users/{admin_id}/delete",
                data={"csrf_token": csrf_from(users.text), "return_to": "/users"},
                follow_redirects=False,
            )
            assert blocked.status_code == 303
            assert "error=" in blocked.headers["location"]

            deleted = client.post(
                f"/users/{viewer_id}/delete",
                data={"csrf_token": csrf_from(users.text), "return_to": "/users"},
                follow_redirects=False,
            )
            assert deleted.status_code == 303
            with factory() as session:
                deleted_user = session.get(User, viewer_id)
                assert deleted_user is not None
                assert deleted_user.active is False
                assert deleted_user.deleted_at is not None

            audit = client.get("/audit")
            assert "data-audit-details=" in audit.text
            assert "Открыть расшифровку" in audit.text
            assert "Старая" in audit.text and "Новая" in audit.text
    finally:
        app.dependency_overrides.clear()


def test_password_change_clears_default_warning_flag() -> None:
    factory = make_database()

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with factory() as session:
            admin = create_user(session, "admin", "administrator password", UserRole.ADMIN)
            admin.must_change_default_password = True
            session.commit()
            admin_id = admin.id
        with TestClient(app, base_url="https://localhost") as client:
            login(client)
            page = client.get("/users")
            response = client.post(
                f"/users/{admin_id}/password",
                data={
                    "password": "new administrator password",
                    "csrf_token": csrf_from(page.text),
                    "return_to": "/users",
                },
                follow_redirects=False,
            )
            assert response.status_code == 303
        with factory() as session:
            user = session.scalar(select(User).where(User.id == admin_id))
            assert user is not None and user.must_change_default_password is False
    finally:
        app.dependency_overrides.clear()
