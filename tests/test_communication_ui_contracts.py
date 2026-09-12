from pathlib import Path
from types import SimpleNamespace

from monitoring.services.audit import format_audit_entry_text


def test_role_independent_target_layout() -> None:
    dashboard = Path("src/monitoring/templates/dashboard.html").read_text(encoding="utf-8")
    targets = Path("src/monitoring/templates/targets.html").read_text(encoding="utf-8")
    css = Path("src/monitoring/static/app.css").read_text(encoding="utf-8")
    assert "monitoring-object-actions" in dashboard
    assert "targets-table-without-actions" in targets
    assert ".monitoring-object-actions { display: grid; place-items: center; gap: 3px; }" in css
    assert ".monitoring-order-button" in css
    assert "--objects-grid:" in css
    assert ".targets-table .target-tool-actions" in css
    assert "flex-wrap: nowrap" in css


def test_chat_compose_and_partial_navigation_contract() -> None:
    chat = Path("src/monitoring/templates/chat.html").read_text(encoding="utf-8")
    js = Path("src/monitoring/static/app.js").read_text(encoding="utf-8")
    css = Path("src/monitoring/static/app.css").read_text(encoding="utf-8")
    assert "data-chat-counter" in chat and "0 / 2000" in chat
    assert 'event.key !== "Enter" || event.shiftKey' in js
    assert "form.requestSubmit()" in js
    assert "syncDocumentShell(documentCopy)" in js
    assert "document.body.className = documentCopy.body.className" in js
    assert "reinitializeDynamicPage()" in js
    assert ".chat-character-counter" in css
    assert ".chat-contact.is-active" in css and "border-radius: 10px" in css


def test_chat_target_mentions_use_safe_target_ids_and_state_links() -> None:
    chat = Path("src/monitoring/templates/chat.html").read_text(encoding="utf-8")
    routes = Path("src/monitoring/web/communication_routes.py").read_text(encoding="utf-8")
    service = Path("src/monitoring/services/communication.py").read_text(encoding="utf-8")
    js = Path("src/monitoring/static/app.js").read_text(encoding="utf-8")
    css = Path("src/monitoring/static/app.css").read_text(encoding="utf-8")
    assert "data-chat-targets" in chat
    assert "data-chat-target-suggestions" in chat
    assert "?focus_target_id={{ part.target_id }}" in chat
    assert "_chat_message_parts" in routes
    assert "CHAT_TARGET_MENTION_SEPARATOR" in service
    assert "chat_display_text" in service
    assert "chat-target-suggestion" in js
    assert "chat-target-mention" in css


def test_chat_sender_editing_contract() -> None:
    chat = Path("src/monitoring/templates/chat.html").read_text(encoding="utf-8")
    routes = Path("src/monitoring/web/communication_routes.py").read_text(encoding="utf-8")
    service = Path("src/monitoring/services/communication.py").read_text(encoding="utf-8")
    assert "data-chat-edit-toggle" in chat
    assert "/chat/messages/{{ message.id }}/edit" in chat
    assert "chat-message-edited" in chat
    assert '@router.post("/chat/messages/{message_id}/edit")' in routes
    assert "edit_chat_message" in service and "message.sender_id != sender_id" in service


def test_chat_messages_do_not_create_center_notifications_or_audit() -> None:
    routes = Path("src/monitoring/web/communication_routes.py").read_text(encoding="utf-8")
    send_block = routes.split('@router.post("/chat/send")', 1)[1].split(
        '@router.post("/chat/{peer_id}/delete-request")', 1
    )[0]
    assert "create_chat_message" in send_block
    assert "create_chat_notification" not in send_block
    assert "write_audit" not in send_block
    notifications = Path("src/monitoring/templates/notifications.html").read_text(encoding="utf-8")
    assert "Инциденты, восстановления объектов и системные события мониторинга." in notifications


def test_push_options_and_notification_spacing_are_stable() -> None:
    css = Path("src/monitoring/static/app.css").read_text(encoding="utf-8")
    assert ".push-preferences-form .push-option {" in css
    assert "grid-template-columns: 20px minmax(0, 1fr);" in css
    assert "width: 18px !important;" in css
    assert ".push-settings-panel { margin-bottom: 20px; }" in css


def test_chat_deletion_audit_is_human_readable() -> None:
    entry = SimpleNamespace(
        action="chat.deletion_confirmed",
        created_at=None,
        entity_type="user",
        entity_id="1",
        details='{"_entity_name":"admin","cutoff_at":"2026-08-18T19:10:27+00:00","request_id":1}',
        ip_address="192.168.98.220",
    )
    text = format_audit_entry_text(entry, "demo", lambda value: "18.08.2026 22:10:27 MSK")
    assert "Событие: Очистка истории чата" in text
    assert "Инициатор: demo" in text
    assert "Объект изменения: Пользователь admin · ID 1" in text
    assert "История удалена до: 18.08.2026 22:10:27 MSK" in text
    assert "ID запроса: 1" in text
    assert "Неизвестное событие" not in text
