import base64
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from monitoring.db import Base
from monitoring.models import ChatMessage, User, UserNotification, UserRole
from monitoring.services.auth import hash_password
from monitoring.services.backups import CONFIGURATION_TABLES, FULL_TABLES
from monitoring.services.communication import (
    create_chat_message,
    edit_chat_message,
    mark_conversation_read,
    unread_counts,
)
from monitoring.services.push import ensure_vapid_keys, user_push_category_enabled


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def _session() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_project_state_is_portable() -> None:
    state = Path("docs/PROJECT_STATE.md").read_text(encoding="utf-8")
    roadmap = Path("docs/ROADMAP.md").read_text(encoding="utf-8")
    assert "Текущая рабочая и якорная версия: **0.8.5**" in state
    assert "внутренний личный чат" in state
    assert "SMS" in roadmap and "Windows-агенты" in roadmap
    assert "0.8.5" in roadmap


def test_vapid_keys_use_webpush_raw_formats() -> None:
    with _session() as session:
        private, public = ensure_vapid_keys(session)
        again = ensure_vapid_keys(session)
        assert again == (private, public)
        assert len(_b64decode(private)) == 32
        public_raw = _b64decode(public)
        assert len(public_raw) == 65
        assert public_raw[0] == 4


def test_chat_and_unread_counters() -> None:
    with _session() as session:
        alice = User(
            username="alice", password_hash=hash_password("password1"), role=UserRole.ADMIN
        )
        bob = User(username="bob", password_hash=hash_password("password2"), role=UserRole.VIEWER)
        session.add_all([alice, bob])
        session.flush()
        create_chat_message(session, sender=alice, recipient_id=bob.id, body="Привет")
        chat_count, notification_count = unread_counts(session, bob.id)
        # С 0.6.9 обычные сообщения учитываются только счётчиком чата и не дублируются в центре оповещений.
        assert (chat_count, notification_count) == (1, 0)
        assert mark_conversation_read(session, bob.id, alice.id) == 1
        chat_count, notification_count = unread_counts(session, bob.id)
        assert chat_count == 0
        assert notification_count == 0


def test_only_sender_can_edit_own_chat_message() -> None:
    with _session() as session:
        alice = User(username="alice", password_hash=hash_password("password1"), role=UserRole.ADMIN)
        bob = User(username="bob", password_hash=hash_password("password2"), role=UserRole.VIEWER)
        session.add_all([alice, bob])
        session.flush()
        message, _ = create_chat_message(session, sender=alice, recipient_id=bob.id, body="Черновик")
        edited = edit_chat_message(
            session,
            sender_id=alice.id,
            recipient_id=bob.id,
            message_id=message.id,
            body="Исправленный текст",
        )
        assert edited.body == "Исправленный текст"
        assert edited.edited_at is not None
        try:
            edit_chat_message(
                session,
                sender_id=bob.id,
                recipient_id=alice.id,
                message_id=message.id,
                body="Чужая правка",
            )
        except ValueError as error:
            assert "не найдено" in str(error)
        else:
            raise AssertionError("Получатель не должен редактировать чужое сообщение")


def test_push_preferences_are_independent() -> None:
    user = User(
        username="u",
        password_hash="x",
        push_chat_enabled=True,
        push_incident_enabled=False,
        push_recovery_enabled=True,
    )
    assert user_push_category_enabled(user, "chat") is True
    assert user_push_category_enabled(user, "incident_opened") is False
    assert user_push_category_enabled(user, "incident_recovered") is True


def test_full_backup_contains_communication_but_configuration_does_not() -> None:
    communication = {"chat_messages", "user_notifications", "push_subscriptions"}
    assert communication.isdisjoint(CONFIGURATION_TABLES)
    assert communication.issubset(FULL_TABLES)


def test_pwa_worker_handles_push_and_click() -> None:
    worker = Path("src/monitoring/static/sw.js").read_text(encoding="utf-8")
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    assert 'addEventListener("push"' in worker
    assert 'addEventListener("notificationclick"' in worker
    assert "pywebpush==2.3.0" in pyproject


def test_schema_models_include_communication_tables() -> None:
    assert {"chat_messages", "user_notifications", "push_subscriptions"}.issubset(
        Base.metadata.tables
    )
    assert ChatMessage.__tablename__ == "chat_messages"
    assert UserNotification.__tablename__ == "user_notifications"


def test_visible_dialogue_suppresses_only_chat_push() -> None:
    communication = Path("src/monitoring/services/communication.py").read_text(encoding="utf-8")
    push = Path("src/monitoring/services/push.py").read_text(encoding="utf-8")
    javascript = Path("src/monitoring/static/app.js").read_text(encoding="utf-8")
    assert "ChatPresence" in communication and "VISIBLE_CHAT_WINDOW_SECONDS" in communication
    assert "send_chat_push_if_unseen" in push and "is_chat_visible" in push
    assert "/api/chat/${encodeURIComponent(peerId)}/presence" in javascript
