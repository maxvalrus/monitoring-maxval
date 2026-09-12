from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from monitoring.db import Base
from monitoring.models import ChatMessage, User, UserRole
from monitoring.services.auth import hash_password
from monitoring.services.communication import (
    chat_contacts,
    request_conversation_deletion,
    resolve_deletion_request,
    unread_counts,
)


def _session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return Session(engine)


def _users(session):
    a = User(username="a", password_hash=hash_password("password1"), role=UserRole.ADMIN)
    b = User(username="b", password_hash=hash_password("password1"), role=UserRole.VIEWER)
    session.add_all([a, b])
    session.flush()
    return a, b


def test_deletion_requests_are_repeatable_and_unread_in_chat_only():
    with _session() as session:
        a, b = _users(session)
        session.add(
            ChatMessage(
                sender_id=a.id,
                recipient_id=b.id,
                body="old",
                created_at=datetime.now(UTC) - timedelta(minutes=3),
            )
        )
        session.flush()
        first = request_conversation_deletion(session, requester=a, peer_id=b.id)
        resolve_deletion_request(session, request_id=first.id, peer_user_id=b.id, confirm=False)
        second = request_conversation_deletion(session, requester=b, peer_id=a.id)
        assert second.id != first.id
        chat_unread, notification_unread = unread_counts(session, a.id)
        assert chat_unread == 1
        assert notification_unread == 0
        contact = next(row for row in chat_contacts(session, a.id) if row.user.id == b.id)
        assert contact.unread == 1
        assert contact.last_message == "Запрос на удаление истории"


def test_confirmation_deletes_only_up_to_its_own_cutoff():
    with _session() as session:
        a, b = _users(session)
        old = ChatMessage(
            sender_id=a.id,
            recipient_id=b.id,
            body="old",
            created_at=datetime.now(UTC) - timedelta(minutes=5),
        )
        session.add(old)
        session.flush()
        request = request_conversation_deletion(session, requester=a, peer_id=b.id)
        new = ChatMessage(
            sender_id=b.id,
            recipient_id=a.id,
            body="new",
            created_at=request.cutoff_at + timedelta(seconds=1),
        )
        session.add(new)
        session.flush()
        resolve_deletion_request(session, request_id=request.id, peer_user_id=b.id, confirm=True)
        bodies = list(session.scalars(select(ChatMessage.body).order_by(ChatMessage.id)))
        assert bodies == ["new"]


def test_history_and_chat_ui_contracts():
    history = Path("src/monitoring/templates/target_history.html").read_text()
    chat = Path("src/monitoring/templates/chat.html").read_text()
    css = Path("src/monitoring/static/app.css").read_text()
    assert "Текущие настройки объекта" in history
    assert "Проверить доступность сейчас" in history and "Изменить объект" in history
    assert "chat-desktop-action-stack" in chat and "chat-history-boundary" in chat
    assert "selected_online" in chat
    assert "background: var(--up) !important" in css


def test_focused_editor_persists_after_save():
    routes = Path("src/monitoring/web/admin_routes.py").read_text()
    template = Path("src/monitoring/templates/targets.html").read_text()
    assert "editor_save_return_to" in routes
    assert "editor_save_return_to if focus_target_id == target.id" in template
