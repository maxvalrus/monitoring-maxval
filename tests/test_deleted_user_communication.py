import re
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from monitoring.db import Base, get_db
from monitoring.main import app
from monitoring.models import ChatDeletionRequest, ChatMessage, User, UserNotification, UserRole
from monitoring.services.auth import create_user
from monitoring.services.backups import _table_rows
from monitoring.services.communication import (
    chat_contacts,
    cleanup_deleted_user_communication,
    conversation_page,
    delete_conversation_immediately,
    hidden_cutoff,
    request_conversation_deletion,
)


def _session() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return Session(engine)


def _users(session: Session) -> tuple[User, User]:
    first = User(username="first", password_hash="x", role=UserRole.ADMIN, active=True)
    second = User(username="second", password_hash="x", role=UserRole.VIEWER, active=True)
    session.add_all([first, second])
    session.flush()
    return first, second


def _soft_delete(session: Session, user: User) -> int:
    user.active = False
    user.deleted_at = datetime.now(UTC)
    return cleanup_deleted_user_communication(session, user=user)


def test_deleted_user_schema_is_in_baseline() -> None:
    migration = Path("alembic/versions/0036_baseline_0_8_5.py").read_text(encoding="utf-8")
    assert "op.create_table('users'" in migration
    assert "deleted_at" in migration


def test_deleting_one_user_preserves_chat_for_live_peer() -> None:
    with _session() as session:
        deleted, live = _users(session)
        message = ChatMessage(sender_id=deleted.id, recipient_id=live.id, body="keep me")
        session.add(message)
        session.flush()

        assert _soft_delete(session, deleted) == 0
        session.flush()

        assert session.get(ChatMessage, message.id) is not None
        assert [row.body for row in conversation_page(session, live.id, deleted.id).messages] == [
            "keep me"
        ]
        contact = next(row for row in chat_contacts(session, live.id) if row.user.id == deleted.id)
        assert contact.user.deleted_at is not None
        assert contact.online is False


def test_deleted_peer_history_is_removed_immediately_without_request() -> None:
    with _session() as session:
        deleted, live = _users(session)
        session.add_all(
            [
                ChatMessage(sender_id=deleted.id, recipient_id=live.id, body="one"),
                ChatMessage(sender_id=live.id, recipient_id=deleted.id, body="two"),
            ]
        )
        session.flush()
        _soft_delete(session, deleted)
        session.flush()

        assert delete_conversation_immediately(session, user_id=live.id, peer_id=deleted.id) == 2
        session.flush()
        assert conversation_page(session, live.id, deleted.id).messages == []
        assert all(row.user.id != deleted.id for row in chat_contacts(session, live.id))


def test_when_both_users_are_deleted_their_chat_is_purged() -> None:
    with _session() as session:
        first, second = _users(session)
        message = ChatMessage(sender_id=first.id, recipient_id=second.id, body="temporary")
        session.add(message)
        session.flush()

        assert _soft_delete(session, first) == 0
        session.flush()
        assert session.get(ChatMessage, message.id) is not None

        assert _soft_delete(session, second) == 1
        session.flush()
        assert session.get(ChatMessage, message.id) is None


def test_user_deletion_clears_pending_delete_workflow_and_restores_history() -> None:
    with _session() as session:
        requester, peer = _users(session)
        old = ChatMessage(
            sender_id=requester.id,
            recipient_id=peer.id,
            body="old",
            created_at=datetime.now(UTC) - timedelta(minutes=5),
        )
        session.add(old)
        session.flush()
        request = request_conversation_deletion(session, requester=requester, peer_id=peer.id)
        session.flush()
        assert hidden_cutoff(session, requester.id, peer.id) is not None
        assert (
            session.scalar(
                select(UserNotification).where(UserNotification.source_id == str(request.id))
            )
            is not None
        )

        _soft_delete(session, peer)
        session.flush()

        assert session.get(ChatDeletionRequest, request.id) is None
        assert hidden_cutoff(session, requester.id, peer.id) is None
        assert [row.body for row in conversation_page(session, requester.id, peer.id).messages] == [
            "old"
        ]
        assert (
            session.scalar(
                select(UserNotification).where(UserNotification.source_id == str(request.id))
            )
            is None
        )


def _csrf(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def test_web_delete_preserves_chat_and_shows_deleted_peer() -> None:
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
            viewer = create_user(session, "viewer", "viewer secure password", UserRole.VIEWER)
            session.flush()
            session.add(ChatMessage(sender_id=viewer.id, recipient_id=admin.id, body="history"))
            session.commit()
            viewer_id = viewer.id

        with TestClient(app, base_url="https://localhost") as client:
            login_page = client.get("/login")
            login = client.post(
                "/login",
                data={
                    "username": "admin",
                    "password": "administrator password",
                    "csrf_token": _csrf(login_page.text),
                },
                follow_redirects=False,
            )
            assert login.status_code == 303
            users = client.get("/users")
            deleted = client.post(
                f"/users/{viewer_id}/delete",
                data={"csrf_token": _csrf(users.text), "return_to": "/users"},
                follow_redirects=False,
            )
            assert deleted.status_code == 303
            chat = client.get(f"/chat?user_id={viewer_id}")
            assert chat.status_code == 200
            assert "viewer (удалён)" in chat.text
            assert "Пользователь удалён. История доступна только для просмотра." in chat.text
            assert "history" in chat.text
            assert 'name="recipient_id"' not in chat.text
    finally:
        app.dependency_overrides.clear()


def test_configuration_backup_excludes_deleted_user_tombstones() -> None:
    with _session() as session:
        live, deleted = _users(session)
        _soft_delete(session, deleted)
        session.flush()
        config_usernames = {
            row["username"] for row in _table_rows(session, "users", include_deleted_users=False)
        }
        full_usernames = {
            row["username"] for row in _table_rows(session, "users", include_deleted_users=True)
        }
        assert config_usernames == {live.username}
        assert full_usernames == {live.username, deleted.username}


def test_ui_and_admin_delete_use_deleted_user_tombstones() -> None:
    chat = Path("src/monitoring/templates/chat.html").read_text(encoding="utf-8")
    routes = Path("src/monitoring/web/communication_routes.py").read_text(encoding="utf-8")
    admin = Path("src/monitoring/web/admin_routes.py").read_text(encoding="utf-8")
    model = Path("src/monitoring/models/auth.py").read_text(encoding="utf-8")
    assert "(удалён)" in chat
    assert "Пользователь удалён. История доступна только для просмотра." in chat
    assert "история будет удалена сразу без подтверждения" in chat
    assert "chat.deletion_immediate" in routes
    assert "allow_deleted_conversation=True" in routes
    assert "user.deleted_at = utc_now()" in admin
    assert "cleanup_deleted_user_communication(session, user=user)" in admin
    assert ".where(User.deleted_at.is_(None))" in admin
    assert "session.delete(user)" not in admin
    assert "deleted_at: Mapped[datetime | None]" in model


def test_settings_code_names_are_second_line_and_mobile_safe() -> None:
    template = Path("src/monitoring/templates/settings.html").read_text(encoding="utf-8")
    css = Path("src/monitoring/static/app.css").read_text(encoding="utf-8")
    assert 'class="setting-title-copy"' in template
    assert (
        '<strong>{{ setting_labels.get(item.key, item.key) }}</strong><span class="setting-code-name">({{ item.key }})</span>'
        in template
    )
    assert ".setting-title-copy { min-width: 0; display: flex; flex-direction: column;" in css
    assert ".setting-code-name { display: block; max-width: 100%;" in css
    assert "overflow-wrap: anywhere; word-break: break-word;" in css


def test_ios_fullscreen_chat_is_centered_by_viewport_edges() -> None:
    css = Path("src/monitoring/static/app.css").read_text(encoding="utf-8")
    worker = Path("src/monitoring/static/sw.js").read_text(encoding="utf-8")
    assert "body.chat-fullscreen main.container {" in css
    assert "top: max(8px, env(safe-area-inset-top));" in css
    assert "right: max(8px, env(safe-area-inset-right));" in css
    assert "bottom: max(8px, env(safe-area-inset-bottom));" in css
    assert "left: max(8px, env(safe-area-inset-left));" in css
    assert "width: auto;" in css and "height: auto;" in css
    assert "padding: 0 !important;" in css
    assert "iOS fullscreen chat geometry" in worker
