from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.orm import Session

from monitoring.models import (
    ChatDeletionRequest,
    ChatMessage,
    ChatPresence,
    Incident,
    PushSubscription,
    User,
    UserNotification,
    UserSession,
)

MAX_CHAT_MESSAGE_LENGTH = 2000
CHAT_PAGE_SIZE = 50
CHAT_TARGET_MENTION_SEPARATOR = "\u2063"
_CHAT_TARGET_MENTION_PATTERN = re.compile(
    rf"@(?P<name>[^{CHAT_TARGET_MENTION_SEPARATOR}\r\n]+?){CHAT_TARGET_MENTION_SEPARATOR}\d+{CHAT_TARGET_MENTION_SEPARATOR}"
)
ONLINE_WINDOW_MINUTES = 5
VISIBLE_CHAT_WINDOW_SECONDS = 75
HIDDEN_HISTORY_STATUSES = ("pending", "rejected")


@dataclass(frozen=True, slots=True)
class ChatContact:
    user: User
    unread: int
    last_message: str | None
    last_at: datetime | None
    online: bool
    last_seen_at: datetime | None


@dataclass(frozen=True, slots=True)
class ConversationPage:
    messages: list[ChatMessage]
    has_more: bool


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def chat_display_text(body: str) -> str:
    """Remove private target ids from message previews and notification text."""
    return _CHAT_TARGET_MENTION_PATTERN.sub(lambda match: f"@{match.group('name')}", body)


def _pair_filter(user_id: int, peer_id: int):
    return or_(
        and_(ChatMessage.sender_id == user_id, ChatMessage.recipient_id == peer_id),
        and_(ChatMessage.sender_id == peer_id, ChatMessage.recipient_id == user_id),
    )


def conversation_exists(session: Session, user_id: int, peer_id: int) -> bool:
    return session.scalar(
        select(ChatMessage.id).where(_pair_filter(user_id, peer_id)).limit(1)
    ) is not None


def conversation_peer_ids(session: Session, user_id: int) -> list[int]:
    sent = select(ChatMessage.recipient_id.label("peer_id")).where(ChatMessage.sender_id == user_id)
    received = select(ChatMessage.sender_id.label("peer_id")).where(ChatMessage.recipient_id == user_id)
    return [int(value) for value in session.scalars(sent.union(received)).all()]


def delete_conversation_immediately(session: Session, *, user_id: int, peer_id: int) -> int:
    request_ids = [str(value) for value in session.scalars(
        select(ChatDeletionRequest.id).where(
            or_(
                and_(ChatDeletionRequest.requester_id == user_id, ChatDeletionRequest.peer_id == peer_id),
                and_(ChatDeletionRequest.requester_id == peer_id, ChatDeletionRequest.peer_id == user_id),
            )
        )
    ).all()]
    result = session.execute(delete(ChatMessage).where(_pair_filter(user_id, peer_id)))
    session.execute(
        delete(ChatDeletionRequest).where(
            or_(
                and_(ChatDeletionRequest.requester_id == user_id, ChatDeletionRequest.peer_id == peer_id),
                and_(ChatDeletionRequest.requester_id == peer_id, ChatDeletionRequest.peer_id == user_id),
            )
        )
    )
    if request_ids:
        session.execute(
            delete(UserNotification).where(
                UserNotification.kind == "chat_delete_request",
                UserNotification.source_id.in_(request_ids),
            )
        )
    return int(result.rowcount or 0)


def cleanup_deleted_user_communication(session: Session, *, user: User) -> int:
    """Remove ephemeral communication state while preserving chats with live users.

    When the second participant is already deleted, their shared messages are removed
    immediately because no live user remains who can access the conversation.
    """
    peer_ids = conversation_peer_ids(session, user.id)
    deleted_peer_ids: list[int] = []
    if peer_ids:
        deleted_peer_ids = [int(value) for value in session.scalars(
            select(User.id).where(User.id.in_(peer_ids), User.deleted_at.is_not(None))
        ).all()]

    request_ids = [str(value) for value in session.scalars(
        select(ChatDeletionRequest.id).where(
            or_(ChatDeletionRequest.requester_id == user.id, ChatDeletionRequest.peer_id == user.id)
        )
    ).all()]
    if request_ids:
        session.execute(
            delete(UserNotification).where(
                UserNotification.kind == "chat_delete_request",
                UserNotification.source_id.in_(request_ids),
            )
        )
    session.execute(
        delete(UserNotification).where(
            UserNotification.kind == "chat_delete_request",
            UserNotification.link == f"/chat?user_id={user.id}",
        )
    )
    session.execute(delete(ChatDeletionRequest).where(
        or_(ChatDeletionRequest.requester_id == user.id, ChatDeletionRequest.peer_id == user.id)
    ))
    session.execute(delete(UserNotification).where(UserNotification.user_id == user.id))
    session.execute(delete(PushSubscription).where(PushSubscription.user_id == user.id))

    deleted_messages = 0
    for peer_id in deleted_peer_ids:
        deleted_messages += delete_conversation_immediately(session, user_id=user.id, peer_id=peer_id)
    return deleted_messages


def hidden_cutoff(session: Session, user_id: int, peer_id: int) -> datetime | None:
    value = session.scalar(
        select(func.max(ChatDeletionRequest.cutoff_at)).where(
            ChatDeletionRequest.requester_id == user_id,
            ChatDeletionRequest.peer_id == peer_id,
            ChatDeletionRequest.status.in_(HIDDEN_HISTORY_STATUSES),
        )
    )
    return _aware(value)


def has_hidden_history(session: Session, user_id: int, peer_id: int) -> bool:
    cutoff = hidden_cutoff(session, user_id, peer_id)
    if cutoff is None:
        return False
    count = session.scalar(
        select(func.count(ChatMessage.id)).where(
            _pair_filter(user_id, peer_id),
            ChatMessage.created_at <= cutoff,
        )
    ) or 0
    return bool(count)


def restore_conversation_history(session: Session, *, user_id: int, peer_id: int) -> list[ChatDeletionRequest]:
    rows = list(session.scalars(
        select(ChatDeletionRequest).where(
            ChatDeletionRequest.requester_id == user_id,
            ChatDeletionRequest.peer_id == peer_id,
            ChatDeletionRequest.status.in_(HIDDEN_HISTORY_STATUSES),
        ).order_by(ChatDeletionRequest.created_at, ChatDeletionRequest.id)
    ).all())
    for row in rows:
        row.status = "restored"
    return rows


def chat_contacts(session: Session, current_user_id: int) -> list[ChatContact]:
    sent_peers = select(ChatMessage.recipient_id).where(ChatMessage.sender_id == current_user_id)
    received_peers = select(ChatMessage.sender_id).where(ChatMessage.recipient_id == current_user_id)
    conversation_peers = sent_peers.union(received_peers)
    users = session.scalars(
        select(User).where(
            User.id != current_user_id,
            or_(
                User.active.is_(True),
                and_(User.deleted_at.is_not(None), User.id.in_(conversation_peers)),
            ),
        ).order_by(func.lower(User.username), User.id)
    ).all()
    now = datetime.now(UTC)
    threshold = now - timedelta(minutes=ONLINE_WINDOW_MINUTES)
    result: list[ChatContact] = []
    for user in users:
        cutoff = hidden_cutoff(session, current_user_id, user.id)
        message_where = [_pair_filter(current_user_id, user.id)]
        if cutoff is not None:
            message_where.append(ChatMessage.created_at > cutoff)
        last = session.scalar(
            select(ChatMessage).where(*message_where).order_by(ChatMessage.created_at.desc(), ChatMessage.id.desc()).limit(1)
        )
        unread_where = [
            ChatMessage.sender_id == user.id,
            ChatMessage.recipient_id == current_user_id,
            ChatMessage.read_at.is_(None),
        ]
        if cutoff is not None:
            unread_where.append(ChatMessage.created_at > cutoff)
        unread_messages = session.scalar(select(func.count(ChatMessage.id)).where(*unread_where)) or 0
        delete_notice = session.scalar(
            select(UserNotification).where(
                UserNotification.user_id == current_user_id,
                UserNotification.kind == "chat_delete_request",
                UserNotification.link == f"/chat?user_id={user.id}",
            ).order_by(UserNotification.created_at.desc(), UserNotification.id.desc()).limit(1)
        )
        unread_delete_requests = session.scalar(
            select(func.count(UserNotification.id)).where(
                UserNotification.user_id == current_user_id,
                UserNotification.kind == "chat_delete_request",
                UserNotification.link == f"/chat?user_id={user.id}",
                UserNotification.read_at.is_(None),
            )
        ) or 0
        last_seen = session.scalar(select(func.max(UserSession.last_seen_at)).where(UserSession.user_id == user.id))
        last_seen = _aware(last_seen)
        last_message_at = _aware(last.created_at) if last else None
        delete_notice_at = _aware(delete_notice.created_at) if delete_notice else None
        request_is_latest = bool(delete_notice_at and (last_message_at is None or delete_notice_at > last_message_at))
        result.append(
            ChatContact(
                user=user,
                unread=int(unread_messages + unread_delete_requests),
                last_message=(
                    "Запрос на удаление истории"
                    if request_is_latest
                    else (chat_display_text(last.body) if last else None)
                ),
                last_at=delete_notice_at if request_is_latest else last_message_at,
                online=bool(user.deleted_at is None and last_seen and last_seen >= threshold),
                last_seen_at=last_seen,
            )
        )
    result.sort(key=lambda row: (row.last_at is not None, row.last_at or datetime.min.replace(tzinfo=UTC)), reverse=True)
    return result


def conversation_page(
    session: Session,
    user_id: int,
    peer_id: int,
    *,
    limit: int = CHAT_PAGE_SIZE,
    before_id: int | None = None,
) -> ConversationPage:
    limit = max(1, min(limit, 100))
    conditions = [_pair_filter(user_id, peer_id)]
    cutoff = hidden_cutoff(session, user_id, peer_id)
    if cutoff is not None:
        conditions.append(ChatMessage.created_at > cutoff)
    if before_id is not None:
        conditions.append(ChatMessage.id < before_id)
    rows = session.scalars(
        select(ChatMessage)
        .where(*conditions)
        .order_by(ChatMessage.created_at.desc(), ChatMessage.id.desc())
        .limit(limit + 1)
    ).all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    return ConversationPage(messages=list(reversed(rows)), has_more=has_more)


def conversation(session: Session, user_id: int, peer_id: int, *, limit: int = CHAT_PAGE_SIZE) -> list[ChatMessage]:
    return conversation_page(session, user_id, peer_id, limit=limit).messages


def mark_conversation_read(session: Session, user_id: int, peer_id: int) -> int:
    conditions = [
        ChatMessage.sender_id == peer_id,
        ChatMessage.recipient_id == user_id,
        ChatMessage.read_at.is_(None),
    ]
    cutoff = hidden_cutoff(session, user_id, peer_id)
    if cutoff is not None:
        conditions.append(ChatMessage.created_at > cutoff)
    result = session.execute(update(ChatMessage).where(*conditions).values(read_at=datetime.now(UTC)))
    return int(result.rowcount or 0)


def refresh_chat_presence(session: Session, *, user_id: int, peer_id: int) -> None:
    """Record a short-lived, page-specific view; it is not the generic online state."""
    now = datetime.now(UTC)
    row = session.get(ChatPresence, {"user_id": user_id, "peer_id": peer_id})
    if row is None:
        session.add(ChatPresence(user_id=user_id, peer_id=peer_id, seen_at=now))
    else:
        row.seen_at = now


def is_chat_visible(session: Session, *, user_id: int, peer_id: int) -> bool:
    threshold = datetime.now(UTC) - timedelta(seconds=VISIBLE_CHAT_WINDOW_SECONDS)
    return session.scalar(
        select(ChatPresence.user_id).where(
            ChatPresence.user_id == user_id,
            ChatPresence.peer_id == peer_id,
            ChatPresence.seen_at >= threshold,
        )
    ) is not None


def create_chat_message(session: Session, *, sender: User, recipient_id: int, body: str) -> tuple[ChatMessage, User]:
    text = body.strip()
    if not text:
        raise ValueError("Введите сообщение")
    if len(text) > MAX_CHAT_MESSAGE_LENGTH:
        raise ValueError(f"Сообщение не должно превышать {MAX_CHAT_MESSAGE_LENGTH} символов")
    if recipient_id == sender.id:
        raise ValueError("Нельзя отправить сообщение самому себе")
    recipient = session.get(User, recipient_id)
    if recipient is None or not recipient.active:
        raise ValueError("Получатель не найден или отключён")
    message = ChatMessage(sender_id=sender.id, recipient_id=recipient.id, body=text)
    session.add(message)
    session.flush()
    return message, recipient


def edit_chat_message(
    session: Session,
    *,
    sender_id: int,
    recipient_id: int,
    message_id: int,
    body: str,
) -> ChatMessage:
    """Edit only the sender's own message in the selected direct conversation."""
    text = body.strip()
    if not text:
        raise ValueError("Введите сообщение")
    if len(text) > MAX_CHAT_MESSAGE_LENGTH:
        raise ValueError(f"Сообщение не должно превышать {MAX_CHAT_MESSAGE_LENGTH} символов")
    message = session.get(ChatMessage, message_id)
    if (
        message is None
        or message.sender_id != sender_id
        or message.recipient_id != recipient_id
    ):
        raise ValueError("Сообщение для редактирования не найдено")
    if message.body != text:
        message.body = text
        message.edited_at = datetime.now(UTC)
    return message


def request_conversation_deletion(session: Session, *, requester: User, peer_id: int) -> ChatDeletionRequest:
    if peer_id == requester.id:
        raise ValueError("Нельзя удалить диалог с самим собой")
    peer = session.get(User, peer_id)
    if peer is None or not peer.active:
        raise ValueError("Пользователь не найден или отключён")
    now = datetime.now(UTC)
    row = ChatDeletionRequest(
        requester_id=requester.id,
        peer_id=peer_id,
        cutoff_at=now,
        status="pending",
        created_at=now,
    )
    session.add(row)
    session.flush()
    # Hidden history must not keep an unread badge for the requester.
    session.execute(
        update(ChatMessage)
        .where(
            ChatMessage.sender_id == peer_id,
            ChatMessage.recipient_id == requester.id,
            ChatMessage.created_at <= now,
            ChatMessage.read_at.is_(None),
        )
        .values(read_at=now)
    )
    create_notification(
        session,
        user_id=peer_id,
        kind="chat_delete_request",
        title=f"Запрос удаления диалога от {requester.username}",
        body="Пользователь хочет удалить историю вашего диалога до момента запроса. Откройте чат, чтобы подтвердить или отклонить.",
        link=f"/chat?user_id={requester.id}",
        source_type="chat_deletion_request",
        source_id=row.id,
    )
    return row


def incoming_deletion_requests(session: Session, *, user_id: int, peer_id: int) -> list[ChatDeletionRequest]:
    return list(session.scalars(
        select(ChatDeletionRequest).where(
            ChatDeletionRequest.requester_id == peer_id,
            ChatDeletionRequest.peer_id == user_id,
            ChatDeletionRequest.status == "pending",
        ).order_by(ChatDeletionRequest.created_at, ChatDeletionRequest.id)
    ).all())


def outgoing_deletion_request(session: Session, *, user_id: int, peer_id: int) -> ChatDeletionRequest | None:
    return session.scalar(
        select(ChatDeletionRequest).where(
            ChatDeletionRequest.requester_id == user_id,
            ChatDeletionRequest.peer_id == peer_id,
            ChatDeletionRequest.status.in_(HIDDEN_HISTORY_STATUSES),
        ).order_by(ChatDeletionRequest.created_at.desc(), ChatDeletionRequest.id.desc()).limit(1)
    )


def resolve_deletion_request(session: Session, *, request_id: int, peer_user_id: int, confirm: bool) -> ChatDeletionRequest:
    row = session.get(ChatDeletionRequest, request_id)
    if row is None or row.peer_id != peer_user_id or row.status != "pending":
        raise ValueError("Запрос на удаление диалога не найден или уже обработан")
    row.status = "confirmed" if confirm else "rejected"
    row.responded_at = datetime.now(UTC)
    if confirm:
        message_ids = list(session.scalars(
            select(ChatMessage.id).where(
                _pair_filter(row.requester_id, row.peer_id),
                ChatMessage.created_at <= row.cutoff_at,
            )
        ).all())
        if message_ids:
            session.execute(delete(ChatMessage).where(ChatMessage.id.in_(message_ids)))
    return row


def create_notification(
    session: Session,
    *,
    user_id: int,
    kind: str,
    title: str,
    body: str,
    link: str | None = None,
    source_type: str | None = None,
    source_id: str | int | None = None,
) -> UserNotification:
    row = UserNotification(
        user_id=user_id,
        kind=kind[:40],
        title=title[:200],
        body=body,
        link=link[:300] if link else None,
        source_type=source_type[:50] if source_type else None,
        source_id=str(source_id)[:100] if source_id is not None else None,
    )
    session.add(row)
    session.flush()
    return row


def create_incident_notifications(
    session: Session,
    *,
    incident_id: int,
    kind: str,
    target_name: str,
    site_name: str,
    message: str | None = None,
    target_id: int | None = None,
    source_kind: str = "availability",
    severity: str | None = None,
) -> list[int]:
    if source_kind == "snmp":
        if kind == "opened":
            notification_kind = "incident_opened"
            level = "Critical" if severity == "critical" else "Warning"
            title = f"SNMP {level}: {target_name}"
            body = f"{site_name}. {message or 'Порог SNMP превышен.'}"
        else:
            notification_kind = "incident_recovered"
            title = f"SNMP в норме: {target_name}"
            body = f"{site_name}. Значение вернулось в норму."
    elif source_kind == "check":
        notification_kind = "incident_opened" if kind == "opened" else "incident_recovered"
        title = (
            f"Сервис недоступен: {target_name}"
            if kind == "opened"
            else f"Сервис восстановлен: {target_name}"
        )
        body = f"{site_name}. {message or ('Проверка сервиса завершилась ошибкой.' if kind == 'opened' else 'Проверка сервиса снова успешна.')}"
    elif kind == "opened":
        notification_kind = "incident_opened"
        title = f"Недоступен: {target_name}"
        body = f"{site_name}. {message or 'Открыт новый инцидент.'}"
    else:
        notification_kind = "incident_recovered"
        title = f"Восстановлен: {target_name}"
        body = f"{site_name}. Объект снова доступен."
    link = f"/incidents?focus_id={incident_id}#incident-{incident_id}"
    source_type = "incident"
    source_id = incident_id
    user_ids = session.scalars(select(User.id).where(User.active.is_(True)).order_by(User.id)).all()
    for user_id in user_ids:
        create_notification(
            session,
            user_id=user_id,
            kind=notification_kind,
            title=title,
            body=body,
            link=link,
            source_type=source_type,
            source_id=source_id,
        )
    return list(user_ids)


def unread_counts(session: Session, user_id: int) -> tuple[int, int]:
    unread_messages = session.scalar(
        select(func.count(ChatMessage.id)).where(ChatMessage.recipient_id == user_id, ChatMessage.read_at.is_(None))
    ) or 0
    unread_chat_requests = session.scalar(
        select(func.count(UserNotification.id)).where(
            UserNotification.user_id == user_id,
            UserNotification.kind == "chat_delete_request",
            UserNotification.read_at.is_(None),
        )
    ) or 0
    notifications = session.scalar(
        select(func.count(UserNotification.id)).where(
            UserNotification.user_id == user_id,
            UserNotification.read_at.is_(None),
            UserNotification.kind.notin_(("chat", "chat_delete_request")),
        )
    ) or 0
    return int(unread_messages + unread_chat_requests), int(notifications)


def mark_notification_read(session: Session, user_id: int, notification_id: int) -> UserNotification | None:
    row = session.get(UserNotification, notification_id)
    if row is None or row.user_id != user_id:
        return None
    if row.read_at is None:
        row.read_at = datetime.now(UTC)
    return row


def notification_destination(session: Session, row: UserNotification) -> str:
    """Return the notification destination and repair legacy recovery links."""
    if (
        row.kind == "incident_recovered"
        and row.source_type == "target"
        and row.source_id
        and row.link
        and row.link.startswith("/?focus_target_id=")
    ):
        try:
            target_id = int(row.source_id)
        except ValueError:
            return row.link
        incident_id = session.scalar(
            select(Incident.id)
            .where(
                Incident.target_id == target_id,
                Incident.resolved_at.is_not(None),
                Incident.resolved_at <= row.created_at + timedelta(minutes=1),
            )
            .order_by(Incident.resolved_at.desc(), Incident.id.desc())
            .limit(1)
        )
        if incident_id is not None:
            row.link = f"/incidents?focus_id={incident_id}#incident-{incident_id}"
            row.source_type = "incident"
            row.source_id = str(incident_id)
        else:
            row.link = "/incidents?status=resolved"
            row.source_type = "incident"
            row.source_id = None
    return row.link or "/notifications"


def mark_all_notifications_read(session: Session, user_id: int) -> int:
    result = session.execute(
        update(UserNotification).where(
            UserNotification.user_id == user_id,
            UserNotification.read_at.is_(None),
            UserNotification.kind.notin_(("chat", "chat_delete_request")),
        ).values(read_at=datetime.now(UTC))
    )
    return int(result.rowcount or 0)


def delete_notification(session: Session, user_id: int, notification_id: int) -> bool:
    result = session.execute(delete(UserNotification).where(UserNotification.id == notification_id, UserNotification.user_id == user_id))
    return bool(result.rowcount)


def delete_read_notifications(session: Session, user_id: int) -> int:
    result = session.execute(delete(UserNotification).where(
            UserNotification.user_id == user_id,
            UserNotification.read_at.is_not(None),
            UserNotification.kind.notin_(("chat", "chat_delete_request")),
        ))
    return int(result.rowcount or 0)


def delete_all_notifications(session: Session, user_id: int) -> int:
    result = session.execute(delete(UserNotification).where(
            UserNotification.user_id == user_id,
            UserNotification.kind.notin_(("chat", "chat_delete_request")),
        ))
    return int(result.rowcount or 0)
