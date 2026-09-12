from pathlib import Path
from types import SimpleNamespace

from monitoring.services.audit import format_audit_entry_text


def test_chat_has_page_scope_and_panel_spacing() -> None:
    chat = Path("src/monitoring/templates/chat.html").read_text(encoding="utf-8")
    css = Path("src/monitoring/static/app.css").read_text(encoding="utf-8")
    base = Path("src/monitoring/templates/base.html").read_text(encoding="utf-8")
    assert "communication-page chat-page" in chat
    assert 'class="{% block body_class %}{% endblock %}"' in base
    assert ".chat-contacts { padding: 20px; }" in css
    assert ".chat-conversation { padding: 20px; }" in css
    assert ".chat-compose { padding: 14px 0 0; }" in css
    assert '.chat-page .communication-button[href="/chat"]' in css


def test_notifications_have_stable_grid_positions() -> None:
    html = Path("src/monitoring/templates/notifications.html").read_text(encoding="utf-8")
    css = Path("src/monitoring/static/app.css").read_text(encoding="utf-8")
    assert "communication-page notifications-page" in html
    assert 'class="notification-date"' in html
    assert 'class="notification-action"' in html
    assert 'class="notification-body"' in html
    assert 'name="return_to"' in html and "Прочитать" in html
    assert '"icon title date"' in css
    assert '"icon state action"' in css
    assert ".notification-date { grid-area: date; justify-self: end;" in css
    assert ".notification-action { grid-area: action; justify-self: end;" in css
    assert ".push-settings-panel { padding: 20px 22px; }" in css


def test_audit_distinguishes_actor_and_subject() -> None:
    entry = SimpleNamespace(
        action="user.updated",
        created_at=None,
        entity_type="user",
        entity_id="2",
        details='{"_entity_name":"test","role":{"old":"viewer","new":"admin"}}',
        ip_address="192.0.2.1",
    )
    text = format_audit_entry_text(entry, "admin", lambda _: "18.08.2026 17:30")
    assert "Инициатор: admin" in text
    assert "Объект изменения: Пользователь test · ID 2" in text
    assert "Событие: Обновление пользователя" in text
