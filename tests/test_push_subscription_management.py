import re
from collections.abc import Generator
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import monitoring.services.push as push_service
import monitoring.web.routes as web_routes
from monitoring.db import Base, get_db
from monitoring.main import app
from monitoring.models import AuditLog, PushSubscription, UserNotification, UserRole
from monitoring.services.auth import create_user
from monitoring.services.push import (
    PushDeliveryResult,
    push_device_label,
    set_vapid_subject,
    vapid_subject,
)


def _csrf(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def _database_factory():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def _login(client: TestClient) -> None:
    response = client.post(
        "/login",
        data={
            "username": "admin",
            "password": "administrator password",
            "csrf_token": _csrf(client.get("/login").text),
        },
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_push_subscription_subject_and_device_labels_are_safe() -> None:
    factory = _database_factory()
    with factory() as session:
        assert set_vapid_subject(session, "https://192.0.2.10:8443/") is True
        assert vapid_subject(session) == "https://192.0.2.10:8443"
        assert set_vapid_subject(session, "http://192.0.2.10/") is False
        assert vapid_subject(session) == "https://192.0.2.10:8443"
    assert push_device_label("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0)") == "iPhone"
    assert push_device_label("Mozilla/5.0 (Linux; Android 15)") == "Android"
    assert push_device_label(None) == "Неизвестное устройство"


def test_stale_push_subscription_is_removed_and_creates_reconnect_notice(monkeypatch) -> None:
    factory = _database_factory()
    monkeypatch.setattr(push_service, "SessionLocal", factory)
    with factory() as session:
        user = create_user(session, "operator", "operator password", UserRole.VIEWER)
        subscription = PushSubscription(
            user_id=user.id,
            endpoint="https://push.example.test/stale",
            p256dh="public-key",
            auth="auth-secret",
        )
        session.add(subscription)
        session.commit()
        user_id = user.id

    push_service._remove_stale_subscriptions(user_id, ["https://push.example.test/stale"])

    with factory() as session:
        assert session.scalar(select(PushSubscription)) is None
        notice = session.scalar(
            select(UserNotification).where(UserNotification.kind == "push_subscription_invalid")
        )
        assert notice is not None
        assert notice.user_id == user_id
        assert notice.link == "/settings"
        assert "повторного подключения" in notice.title


def test_push_client_reconciles_existing_browser_subscription() -> None:
    javascript = Path("src/monitoring/static/app.js").read_text(encoding="utf-8")

    assert "const syncCurrentPushSubscription" in javascript
    assert 'fetch("/push/subscribe"' in javascript
    assert "syncCurrentPushSubscription();" in javascript
    assert "Push на этом устройстве требует повторного подключения" in javascript


def test_admin_can_list_test_and_delete_push_subscriptions(monkeypatch) -> None:
    factory = _database_factory()

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    calls: list[int] = []
    monkeypatch.setattr(
        web_routes,
        "send_test_push_to_subscription",
        lambda subscription_id: calls.append(subscription_id) or PushDeliveryResult(1, 0),
    )
    try:
        with factory() as session:
            admin = create_user(session, "admin", "administrator password", UserRole.ADMIN)
            viewer = create_user(session, "viewer", "viewer password", UserRole.VIEWER)
            subscription = PushSubscription(
                user_id=viewer.id,
                endpoint="https://push.example.test/subscription",
                p256dh="public-key",
                auth="auth-secret",
                user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 18_0)",
            )
            session.add(subscription)
            session.commit()
            subscription_id = subscription.id
            admin_id = admin.id

        with TestClient(app, base_url="https://localhost") as client:
            _login(client)
            page = client.get("/settings")
            assert "Подписки устройств" in page.text
            assert "iPhone" in page.text
            assert "push.example.test" not in page.text
            csrf = _csrf(page.text)
            test_response = client.post(
                f"/settings/push/subscriptions/{subscription_id}/test",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            assert test_response.status_code == 303
            assert "notice=" in test_response.headers["location"]
            assert calls == [subscription_id]

            delete_response = client.post(
                f"/settings/push/subscriptions/{subscription_id}/delete",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            assert delete_response.status_code == 303

        with factory() as session:
            assert session.get(PushSubscription, subscription_id) is None
            actions = session.scalars(
                select(AuditLog.action).where(AuditLog.user_id == admin_id).order_by(AuditLog.id)
            ).all()
            assert actions[-2:] == ["push.test_sent", "push.subscription_deleted"]
    finally:
        app.dependency_overrides.clear()
