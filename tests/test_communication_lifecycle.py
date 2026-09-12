from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from monitoring.db import Base
from monitoring.models import (
    AppSetting,
    ChatDeletionRequest,
    ChatMessage,
    User,
    UserNotification,
    UserRole,
    UserSession,
)
from monitoring.services.auth import hash_password
from monitoring.services.backups import FULL_TABLES
from monitoring.services.communication import (
    chat_contacts,
    conversation_page,
    request_conversation_deletion,
    resolve_deletion_request,
)
from monitoring.services.maintenance import cleanup_user_notifications


def _session() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_chat_notification_and_target_layout_contract() -> None:
    css = Path("src/monitoring/static/app.css").read_text(encoding="utf-8")
    chat = Path("src/monitoring/templates/chat.html").read_text(encoding="utf-8")
    notifications = Path("src/monitoring/templates/notifications.html").read_text(encoding="utf-8")
    settings = Path("src/monitoring/templates/settings.html").read_text(encoding="utf-8")
    assert ".target-tool-actions" in css and ".target-tool-badges" in css
    assert "data-chat-history-loader" in chat and "Удалить диалог" in chat
    assert "presence-dot" in chat and "chat-role" in chat
    assert "Удалить прочитанные" in notifications and "Удалить все" in notifications
    assert "push-option" in settings and "push-settings-panel" not in notifications


def test_online_status_uses_recent_session_activity() -> None:
    with _session() as session:
        alice = User(
            username="alice", password_hash=hash_password("password1"), role=UserRole.ADMIN
        )
        bob = User(username="bob", password_hash=hash_password("password2"), role=UserRole.VIEWER)
        session.add_all([alice, bob])
        session.flush()
        now = datetime.now(UTC)
        session.add(
            UserSession(
                user_id=bob.id,
                token_hash="x",
                csrf_token="y",
                created_at=now,
                last_seen_at=now - timedelta(minutes=2),
                expires_at=now + timedelta(hours=1),
            )
        )
        session.flush()
        contact = next(item for item in chat_contacts(session, alice.id) if item.user.id == bob.id)
        assert contact.online is True


def test_delete_request_hides_then_physically_deletes_old_history_only() -> None:
    with _session() as session:
        alice = User(
            username="alice", password_hash=hash_password("password1"), role=UserRole.ADMIN
        )
        bob = User(username="bob", password_hash=hash_password("password2"), role=UserRole.VIEWER)
        session.add_all([alice, bob])
        session.flush()
        old = ChatMessage(
            sender_id=alice.id,
            recipient_id=bob.id,
            body="old",
            created_at=datetime.now(UTC) - timedelta(minutes=2),
        )
        session.add(old)
        session.flush()
        request = request_conversation_deletion(session, requester=alice, peer_id=bob.id)
        session.flush()
        assert conversation_page(session, alice.id, bob.id).messages == []
        assert [m.body for m in conversation_page(session, bob.id, alice.id).messages] == ["old"]
        new = ChatMessage(
            sender_id=bob.id,
            recipient_id=alice.id,
            body="new",
            created_at=request.cutoff_at + timedelta(seconds=1),
        )
        session.add(new)
        session.flush()
        resolve_deletion_request(session, request_id=request.id, peer_user_id=bob.id, confirm=True)
        session.flush()
        assert session.scalar(select(ChatMessage).where(ChatMessage.id == old.id)) is None
        assert session.scalar(select(ChatMessage).where(ChatMessage.id == new.id)) is not None
        assert session.get(ChatDeletionRequest, request.id).status == "confirmed"


def test_notification_retention_defaults_to_30_days() -> None:
    with _session() as session:
        user = User(username="user", password_hash=hash_password("password1"), role=UserRole.VIEWER)
        session.add(user)
        session.flush()
        session.add(
            AppSetting(key="notification_retention_days", value="30", description="retention")
        )
        now = datetime.now(UTC)
        session.add_all(
            [
                UserNotification(
                    user_id=user.id,
                    kind="x",
                    title="old",
                    body="old",
                    created_at=now - timedelta(days=31),
                ),
                UserNotification(
                    user_id=user.id,
                    kind="x",
                    title="new",
                    body="new",
                    created_at=now - timedelta(days=1),
                ),
            ]
        )
        session.commit()
        assert cleanup_user_notifications(session, now=now) == 1
        assert (
            session.scalar(select(UserNotification).where(UserNotification.title == "new"))
            is not None
        )


def test_full_backup_contains_chat_deletion_requests() -> None:
    assert "chat_deletion_requests" in FULL_TABLES
    assert "chat_deletion_requests" in Base.metadata.tables
