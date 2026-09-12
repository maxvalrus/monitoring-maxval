from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Annotated
from urllib.parse import quote_plus

from fastapi import APIRouter, BackgroundTasks, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import func, select, update

from monitoring.models import MonitorTarget, Site, User, UserNotification
from monitoring.services.audit import write_audit
from monitoring.services.communication import (
    CHAT_PAGE_SIZE,
    CHAT_TARGET_MENTION_SEPARATOR,
    chat_contacts,
    chat_display_text,
    conversation_exists,
    conversation_page,
    create_chat_message,
    delete_all_notifications,
    delete_conversation_immediately,
    delete_notification,
    delete_read_notifications,
    edit_chat_message,
    has_hidden_history,
    incoming_deletion_requests,
    mark_all_notifications_read,
    mark_conversation_read,
    mark_notification_read,
    notification_destination,
    outgoing_deletion_request,
    refresh_chat_presence,
    request_conversation_deletion,
    resolve_deletion_request,
    restore_conversation_history,
    unread_counts,
)
from monitoring.services.pagination import Pagination
from monitoring.services.push import (
    delete_subscription,
    ensure_vapid_keys,
    save_subscription,
    send_chat_push_if_unseen,
    send_push_to_user,
    set_vapid_subject,
)
from monitoring.services.time_display import session_datetime_formatter
from monitoring.web.dependencies import CurrentAuth, DbSession, template_context
from monitoring.web.routes import templates
from monitoring.web.security import client_ip, verify_session_csrf

router = APIRouter()

_TARGET_MENTION_PATTERN = re.compile(
    rf"@(?P<name>[^{CHAT_TARGET_MENTION_SEPARATOR}\r\n]+?){CHAT_TARGET_MENTION_SEPARATOR}(?P<target_id>\d+){CHAT_TARGET_MENTION_SEPARATOR}"
)


def _require_csrf(auth: CurrentAuth, token: str) -> None:
    if not verify_session_csrf(auth.user_session.csrf_token, token):
        raise HTTPException(status_code=400, detail="Недействительный CSRF-токен")


def _redirect(path: str, parameter: str, message: str) -> RedirectResponse:
    joiner = "&" if "?" in path else "?"
    return RedirectResponse(f"{path}{joiner}{parameter}={quote_plus(message)}", status_code=status.HTTP_303_SEE_OTHER)


def _peer(
    session: DbSession,
    current_user_id: int,
    peer_id: int,
    *,
    allow_deleted_conversation: bool = False,
) -> User:
    peer = session.get(User, peer_id)
    if peer is None or peer.id == current_user_id:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if peer.active:
        return peer
    if (
        allow_deleted_conversation
        and peer.deleted_at is not None
        and conversation_exists(session, current_user_id, peer_id)
    ):
        return peer
    raise HTTPException(status_code=404, detail="Пользователь не найден")


def _user_label(user: User) -> str:
    return f"{user.username} (удалён)" if user.deleted_at is not None else user.username


def _show_chat_edit_marker(message, *, now: datetime) -> bool:
    created_at = message.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    return message.edited_at is not None and created_at <= now - timedelta(minutes=5)


def _chat_target_options(session: DbSession) -> list[dict[str, object]]:
    """One bounded lookup powers both compose suggestions and safe message links."""
    return [
        {"id": target_id, "name": name, "site_name": site_name}
        for target_id, name, site_name in session.execute(
            select(MonitorTarget.id, MonitorTarget.name, Site.name)
            .join(Site, MonitorTarget.site_id == Site.id)
            .order_by(MonitorTarget.name, MonitorTarget.id)
        )
    ]


def _chat_message_parts(body: str, known_target_ids: set[int]) -> list[dict[str, object]]:
    """Split trusted server text into escaped text and linked target mention parts."""
    parts: list[dict[str, object]] = []
    position = 0
    for match in _TARGET_MENTION_PATTERN.finditer(body):
        if match.start() > position:
            parts.append({"text": body[position : match.start()]})
        target_id = int(match.group("target_id"))
        name = match.group("name")
        if target_id in known_target_ids and name:
            parts.append({"text": f"@{name}", "target_id": target_id})
        else:
            parts.append({"text": f"@{name}"})
        position = match.end()
    if position < len(body) or not parts:
        parts.append({"text": body[position:]})
    return parts


@router.get("/chat", response_class=HTMLResponse)
def chat_page(request: Request, session: DbSession, auth: CurrentAuth) -> HTMLResponse:
    contacts = chat_contacts(session, auth.user.id)
    raw = request.query_params.get("user_id", "")
    try:
        selected_id = int(raw) if raw else None
    except ValueError:
        selected_id = None
    if selected_id is None and contacts:
        selected_id = contacts[0].user.id
    selected_user = None
    messages = []
    has_more = False
    incoming_requests = []
    outgoing_request = None
    hidden_history_available = False
    if selected_id is not None:
        selected_user = session.get(User, selected_id)
        deleted_conversation = bool(
            selected_user is not None
            and selected_user.deleted_at is not None
            and conversation_exists(session, auth.user.id, selected_user.id)
        )
        if (
            selected_user is None
            or selected_user.id == auth.user.id
            or (not selected_user.active and not deleted_conversation)
        ):
            selected_user = None
        else:
            mark_conversation_read(session, auth.user.id, selected_user.id)
            refresh_chat_presence(session, user_id=auth.user.id, peer_id=selected_user.id)
            session.execute(
                update(UserNotification).where(
                    UserNotification.user_id == auth.user.id,
                    UserNotification.kind == "chat_delete_request",
                    UserNotification.link == f"/chat?user_id={selected_user.id}",
                    UserNotification.read_at.is_(None),
                ).values(read_at=datetime.now(UTC))
            )
            session.commit()
            contacts = chat_contacts(session, auth.user.id)
            page = conversation_page(session, auth.user.id, selected_user.id, limit=CHAT_PAGE_SIZE)
            messages = page.messages
            has_more = page.has_more
            incoming_requests = incoming_deletion_requests(session, user_id=auth.user.id, peer_id=selected_user.id)
            outgoing_request = outgoing_deletion_request(session, user_id=auth.user.id, peer_id=selected_user.id)
            hidden_history_available = has_hidden_history(session, auth.user.id, selected_user.id)
    selected_online = False
    if selected_user is not None:
        selected_online = next((item.online for item in contacts if item.user.id == selected_user.id), False)
    now = datetime.now(UTC)
    chat_targets = _chat_target_options(session)
    known_target_ids = {int(item["id"]) for item in chat_targets}
    return templates.TemplateResponse(request=request, name="chat.html", context=template_context(
        request,
        auth,
        contacts=contacts,
        selected_user=selected_user,
        selected_online=selected_online,
        messages=messages,
        has_more=has_more,
        incoming_deletion_requests=incoming_requests,
        outgoing_deletion_request=outgoing_request,
        hidden_history_available=hidden_history_available,
        edited_message_ids={
            message.id
            for message in messages
            if _show_chat_edit_marker(message, now=now)
        },
        chat_targets=chat_targets,
        message_parts={
            message.id: _chat_message_parts(message.body, known_target_ids)
            for message in messages
        },
        display_datetime=session_datetime_formatter(session),
    ))


@router.post("/api/chat/{peer_id}/presence")
def chat_presence(peer_id: int, session: DbSession, auth: CurrentAuth) -> JSONResponse:
    _peer(session, auth.user.id, peer_id, allow_deleted_conversation=True)
    refresh_chat_presence(session, user_id=auth.user.id, peer_id=peer_id)
    session.commit()
    return JSONResponse({"ok": True})


@router.get("/api/chat/{peer_id}/messages")
def chat_history(peer_id: int, request: Request, session: DbSession, auth: CurrentAuth) -> JSONResponse:
    peer = _peer(session, auth.user.id, peer_id, allow_deleted_conversation=True)
    try:
        before_id = int(request.query_params.get("before_id", ""))
    except (TypeError, ValueError) as error:
        raise HTTPException(
            status_code=400,
            detail="Некорректный идентификатор сообщения",
        ) from error
    page = conversation_page(session, auth.user.id, peer_id, limit=CHAT_PAGE_SIZE, before_id=before_id)
    display = session_datetime_formatter(session)
    now = datetime.now(UTC)
    known_target_ids = {int(item["id"]) for item in _chat_target_options(session)}
    return JSONResponse({
        "messages": [
            {
                "id": message.id,
                "sender_id": message.sender_id,
                "sender_name": auth.user.username if message.sender_id == auth.user.id else _user_label(peer),
                "body": message.body,
                "body_parts": _chat_message_parts(message.body, known_target_ids),
                "created_at": display(message.created_at, "%d.%m.%Y %H:%M"),
                "own": message.sender_id == auth.user.id,
                "read": bool(message.read_at),
                "edited": _show_chat_edit_marker(message, now=now),
            }
            for message in page.messages
        ],
        "has_more": page.has_more,
    })


@router.post("/chat/send")
def chat_send(
    request: Request,
    background_tasks: BackgroundTasks,
    session: DbSession,
    auth: CurrentAuth,
    recipient_id: Annotated[int, Form()],
    body: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    _require_csrf(auth, csrf_token)
    try:
        message, recipient = create_chat_message(session, sender=auth.user, recipient_id=recipient_id, body=body)
        # Обычная переписка не дублируется в центре оповещений и не засоряет аудит.
        session.commit()
    except ValueError as exc:
        session.rollback()
        return _redirect(f"/chat?user_id={recipient_id}", "error", str(exc))
    background_tasks.add_task(
        send_chat_push_if_unseen,
        recipient.id,
        sender_id=auth.user.id,
        title=f"Сообщение от {auth.user.username}",
        body=(
            chat_display_text(message.body)[:220]
            if len(chat_display_text(message.body)) <= 220
            else chat_display_text(message.body)[:217] + "…"
        ),
        url=f"/chat?user_id={auth.user.id}",
    )
    return RedirectResponse(f"/chat?user_id={recipient.id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/chat/messages/{message_id}/edit")
def chat_edit_message(
    message_id: int,
    session: DbSession,
    auth: CurrentAuth,
    recipient_id: Annotated[int, Form()],
    body: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    _require_csrf(auth, csrf_token)
    _peer(session, auth.user.id, recipient_id, allow_deleted_conversation=True)
    try:
        edit_chat_message(
            session,
            sender_id=auth.user.id,
            recipient_id=recipient_id,
            message_id=message_id,
            body=body,
        )
        session.commit()
    except ValueError as exc:
        session.rollback()
        return _redirect(f"/chat?user_id={recipient_id}", "error", str(exc))
    return _redirect(f"/chat?user_id={recipient_id}", "notice", "Сообщение изменено")


@router.post("/chat/{peer_id}/delete-request")
def chat_delete_request(
    peer_id: int,
    request: Request,
    background_tasks: BackgroundTasks,
    session: DbSession,
    auth: CurrentAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    _require_csrf(auth, csrf_token)
    peer = _peer(session, auth.user.id, peer_id, allow_deleted_conversation=True)
    if peer.deleted_at is not None:
        deleted_messages = delete_conversation_immediately(
            session, user_id=auth.user.id, peer_id=peer_id
        )
        write_audit(
            session,
            "chat.deletion_immediate",
            user_id=auth.user.id,
            entity_type="user",
            entity_id=peer.id,
            entity_name=peer.username,
            details={"deleted_messages": deleted_messages, "peer_deleted": True},
            ip_address=client_ip(request),
        )
        session.commit()
        return _redirect("/chat", "notice", "История диалога удалена")
    try:
        row = request_conversation_deletion(session, requester=auth.user, peer_id=peer_id)
        write_audit(
            session,
            "chat.deletion_requested",
            user_id=auth.user.id,
            entity_type="user",
            entity_id=peer.id,
            entity_name=peer.username,
            details={"request_id": row.id, "cutoff_at": row.cutoff_at.isoformat()},
            ip_address=client_ip(request),
        )
        session.commit()
    except ValueError as exc:
        session.rollback()
        return _redirect(f"/chat?user_id={peer_id}", "error", str(exc))
    background_tasks.add_task(
        send_push_to_user,
        peer.id,
        category="chat",
        title=f"Запрос удаления диалога от {auth.user.username}",
        body="Откройте чат, чтобы подтвердить или отклонить удаление старой истории.",
        url=f"/chat?user_id={auth.user.id}",
    )
    return _redirect(f"/chat?user_id={peer_id}", "notice", "Старая история скрыта. Запрос на удаление отправлен собеседнику")


@router.post("/chat/{peer_id}/restore-history")
def chat_restore_history(
    peer_id: int,
    request: Request,
    session: DbSession,
    auth: CurrentAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    _require_csrf(auth, csrf_token)
    peer = _peer(session, auth.user.id, peer_id, allow_deleted_conversation=True)
    rows = restore_conversation_history(session, user_id=auth.user.id, peer_id=peer_id)
    if not rows:
        return _redirect(f"/chat?user_id={peer_id}", "notice", "Скрытой истории для восстановления нет")
    request_ids = [str(row.id) for row in rows]
    session.execute(
        update(UserNotification).where(
            UserNotification.user_id == peer_id,
            UserNotification.kind == "chat_delete_request",
            UserNotification.source_id.in_(request_ids),
            UserNotification.read_at.is_(None),
        ).values(read_at=datetime.now(UTC))
    )
    write_audit(
        session,
        "chat.history_restored",
        user_id=auth.user.id,
        entity_type="user",
        entity_id=peer.id,
        entity_name=peer.username,
        details={"restored_requests": len(rows)},
        ip_address=client_ip(request),
    )
    session.commit()
    return _redirect(f"/chat?user_id={peer_id}", "notice", "Старая история восстановлена")


@router.post("/chat/deletion-requests/{request_id}/{decision}")
def chat_delete_decision(
    request_id: int,
    decision: str,
    request: Request,
    session: DbSession,
    auth: CurrentAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    _require_csrf(auth, csrf_token)
    if decision not in {"confirm", "reject"}:
        raise HTTPException(status_code=404, detail="Неизвестное действие")
    try:
        row = resolve_deletion_request(session, request_id=request_id, peer_user_id=auth.user.id, confirm=decision == "confirm")
        requester = session.get(User, row.requester_id)
        session.execute(
            update(UserNotification).where(
                UserNotification.user_id == auth.user.id,
                UserNotification.kind == "chat_delete_request",
                UserNotification.source_id == str(row.id),
                UserNotification.read_at.is_(None),
            ).values(read_at=datetime.now(UTC))
        )
        write_audit(
            session,
            "chat.deletion_confirmed" if decision == "confirm" else "chat.deletion_rejected",
            user_id=auth.user.id,
            entity_type="user",
            entity_id=row.requester_id,
            entity_name=requester.username if requester else str(row.requester_id),
            details={"request_id": row.id, "cutoff_at": row.cutoff_at.isoformat()},
            ip_address=client_ip(request),
        )
        session.commit()
    except ValueError as exc:
        session.rollback()
        return _redirect("/chat", "error", str(exc))
    message = "История диалога удалена для обоих участников" if decision == "confirm" else "Запрос на удаление отклонён"
    return _redirect(f"/chat?user_id={row.requester_id}", "notice", message)


@router.get("/notifications", response_class=HTMLResponse)
def notifications_page(request: Request, session: DbSession, auth: CurrentAuth) -> HTMLResponse:
    notification_conditions = (
        UserNotification.user_id == auth.user.id,
        UserNotification.kind.notin_(("chat", "chat_delete_request")),
    )
    total = session.scalar(select(func.count(UserNotification.id)).where(*notification_conditions)) or 0
    pager = Pagination.from_request(request, int(total))
    rows = session.scalars(
        select(UserNotification)
        .where(*notification_conditions)
        .order_by(UserNotification.created_at.desc(), UserNotification.id.desc())
        .offset(pager.offset)
        .limit(pager.per_page)
    ).all()
    return templates.TemplateResponse(request=request, name="notifications.html", context=template_context(
        request,
        auth,
        notifications=rows,
        pager=pager,
        display_datetime=session_datetime_formatter(session),
    ))


@router.post("/notifications/{notification_id}/read")
def notification_read(
    notification_id: int,
    session: DbSession,
    auth: CurrentAuth,
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "",
) -> RedirectResponse:
    _require_csrf(auth, csrf_token)
    row = mark_notification_read(session, auth.user.id, notification_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Оповещение не найдено")
    destination = (
        return_to
        if return_to.startswith("/notifications")
        else notification_destination(session, row)
    )
    session.commit()
    return RedirectResponse(destination, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/notifications/{notification_id}/delete")
def notification_delete(
    notification_id: int,
    session: DbSession,
    auth: CurrentAuth,
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "/notifications",
) -> RedirectResponse:
    _require_csrf(auth, csrf_token)
    if not delete_notification(session, auth.user.id, notification_id):
        raise HTTPException(status_code=404, detail="Оповещение не найдено")
    session.commit()
    return _redirect(return_to if return_to.startswith("/notifications") else "/notifications", "notice", "Оповещение удалено")


@router.post("/notifications/read-all")
def notifications_read_all(session: DbSession, auth: CurrentAuth, csrf_token: Annotated[str, Form()]) -> RedirectResponse:
    _require_csrf(auth, csrf_token)
    mark_all_notifications_read(session, auth.user.id)
    session.commit()
    return _redirect("/notifications", "notice", "Все оповещения отмечены прочитанными")


@router.post("/notifications/delete-read")
def notifications_delete_read(session: DbSession, auth: CurrentAuth, csrf_token: Annotated[str, Form()]) -> RedirectResponse:
    _require_csrf(auth, csrf_token)
    count = delete_read_notifications(session, auth.user.id)
    session.commit()
    return _redirect("/notifications", "notice", f"Удалено прочитанных оповещений: {count}")


@router.post("/notifications/delete-all")
def notifications_delete_all(session: DbSession, auth: CurrentAuth, csrf_token: Annotated[str, Form()]) -> RedirectResponse:
    _require_csrf(auth, csrf_token)
    count = delete_all_notifications(session, auth.user.id)
    session.commit()
    return _redirect("/notifications", "notice", f"Удалено оповещений: {count}")


@router.post("/notifications/preferences")
def notifications_preferences(
    request: Request,
    session: DbSession,
    auth: CurrentAuth,
    csrf_token: Annotated[str, Form()],
    push_chat: Annotated[str | None, Form()] = None,
    push_incident: Annotated[str | None, Form()] = None,
    push_recovery: Annotated[str | None, Form()] = None,
) -> RedirectResponse:
    _require_csrf(auth, csrf_token)
    auth.user.push_chat_enabled = push_chat == "true"
    auth.user.push_incident_enabled = push_incident == "true"
    auth.user.push_recovery_enabled = push_recovery == "true"
    write_audit(
        session,
        "notification.preferences_updated",
        user_id=auth.user.id,
        entity_type="user",
        entity_id=auth.user.id,
        entity_name=auth.user.username,
        details={
            "push_chat": auth.user.push_chat_enabled,
            "push_incident": auth.user.push_incident_enabled,
            "push_recovery": auth.user.push_recovery_enabled,
        },
        ip_address=client_ip(request),
    )
    session.commit()
    return _redirect("/settings", "notice", "Настройки Push сохранены")


@router.get("/api/communication/status")
def communication_status(session: DbSession, auth: CurrentAuth) -> dict[str, int]:
    chat, notifications = unread_counts(session, auth.user.id)
    return {"chat_unread": chat, "notifications_unread": notifications}


@router.get("/push/public-key")
def push_public_key(request: Request, session: DbSession, auth: CurrentAuth) -> dict[str, str]:
    del auth
    _private, public = ensure_vapid_keys(session)
    set_vapid_subject(session, str(request.base_url))
    session.commit()
    return {"public_key": public}


@router.post("/push/subscribe")
async def push_subscribe(request: Request, session: DbSession, auth: CurrentAuth) -> JSONResponse:
    payload = await request.json()
    _require_csrf(auth, request.headers.get("x-csrf-token", ""))
    keys = payload.get("keys") if isinstance(payload, dict) else None
    try:
        save_subscription(
            session,
            user_id=auth.user.id,
            endpoint=str(payload.get("endpoint", "")),
            p256dh=str((keys or {}).get("p256dh", "")),
            auth=str((keys or {}).get("auth", "")),
            user_agent=request.headers.get("user-agent"),
        )
        ensure_vapid_keys(session)
        set_vapid_subject(session, str(request.base_url))
        session.commit()
    except ValueError as exc:
        session.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return JSONResponse({"ok": True})


@router.post("/push/unsubscribe")
async def push_unsubscribe(request: Request, session: DbSession, auth: CurrentAuth) -> JSONResponse:
    payload = await request.json()
    _require_csrf(auth, request.headers.get("x-csrf-token", ""))
    endpoint = str(payload.get("endpoint", "")) if isinstance(payload, dict) else ""
    delete_subscription(session, user_id=auth.user.id, endpoint=endpoint)
    session.commit()
    return JSONResponse({"ok": True})
