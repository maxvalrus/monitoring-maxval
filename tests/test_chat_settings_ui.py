from pathlib import Path


def test_push_is_in_settings_not_notifications():
    settings = Path("src/monitoring/templates/settings.html").read_text()
    notifications = Path("src/monitoring/templates/notifications.html").read_text()
    routes = Path("src/monitoring/web/routes.py").read_text()
    communication = Path("src/monitoring/web/communication_routes.py").read_text()
    assert 'class="panel push-settings-panel settings-push-panel"' in settings
    assert "data-push-state" in settings
    assert "push-settings-panel" not in notifications
    assert "push_subscriptions=int(push_subscriptions)" in routes
    assert 'return _redirect("/settings", "notice", "Настройки Push сохранены")' in communication


def test_mobile_chat_drawer_and_compact_compose():
    chat = Path("src/monitoring/templates/chat.html").read_text()
    css = Path("src/monitoring/static/app.css").read_text()
    js = Path("src/monitoring/static/app.js").read_text()
    assert "data-chat-contacts-drawer" in chat
    assert "data-chat-dialogs-toggle" in chat
    assert "data-chat-drawer-backdrop" in chat
    assert "chat-contacts[data-chat-contacts-drawer].is-open" in css
    assert "setChatDrawerOpen" in js and "initChatDrawer()" in js
    assert "grid-column: 1 / -1 !important" in css


def test_desktop_compose_centers_send_on_textarea_row():
    css = Path("src/monitoring/static/app.css").read_text()
    assert ".chat-compose-field { display: contents; }" in css
    assert "grid-row: 1;" in css
    assert ".chat-compose > .button" in css
    assert "align-self: center !important" in css


def test_notification_badges_and_target_editor_focus():
    notifications = Path("src/monitoring/templates/notifications.html").read_text()
    targets = Path("src/monitoring/templates/targets.html").read_text()
    js = Path("src/monitoring/static/app.js").read_text()
    assert "notification-state-read" in notifications and "notification-state-new" in notifications
    assert 'id="target-{{ target.id }}-editor"' in targets
    assert 'window.location.pathname === "/targets"' in js
    assert '`target-${params.get("focus_target_id")}-editor`' in js


def test_desktop_target_tools_allow_safe_group_wrap():
    css = Path("src/monitoring/static/app.css").read_text()
    assert "@media (min-width: 1101px)" in css
    assert ".targets-table .target-tools" in css
    assert "flex-wrap: wrap" in css
    assert ".targets-table .target-tool-badges { flex: 0 0 auto; margin-left: auto; }" in css
