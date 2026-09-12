from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from monitoring.db import Base
from monitoring.models import CheckResult, MonitorTarget, Site
from monitoring.services.reports import target_history
from monitoring.web.admin_routes import safe_return_path


def _session() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_incident_id_is_a_separate_row_above_title() -> None:
    template = Path("src/monitoring/templates/incidents.html").read_text(encoding="utf-8")
    assert template.count("ID инцидента: {{ incident.id }}") == 1
    assert 'class="incident-id-row"' in template
    assert template.index('class="incident-id-row"') < template.index('class="entity-heading"')
    css = Path("src/monitoring/static/app.css").read_text(encoding="utf-8")
    assert ".incident-id-row { width: 100%; display: flex; justify-content: flex-end;" in css
    assert ".incident-heading-copy { padding-right: 0 !important; }" in css


def test_history_actions_are_direct_admin_controls() -> None:
    template = Path("src/monitoring/templates/target_history.html").read_text(encoding="utf-8")
    assert "К отчётам" not in template
    assert "{% if current_user.role == 'admin' %}" in template
    assert 'class="history-heading-actions history-inline-actions"' in template
    assert 'class="history-action-menu"' not in template
    assert 'title="Изменить объект"' in template
    assert 'title="Проверить доступность сейчас"' in template
    assert "history-live-status" in template
    css = Path("src/monitoring/static/app.css").read_text(encoding="utf-8")
    assert ".history-inline-actions { align-items: center; gap: 6px; }" in css
    assert ".history-heading .page-heading-main { flex: 1 1 auto; min-width: 0; }" in css


def test_history_manual_check_allows_same_history_return() -> None:
    route = Path("src/monitoring/web/admin_routes.py").read_text(encoding="utf-8")
    assert 'history_path = f"/targets/{target_id}/history"' in route
    value = "/targets/17/history?hours=168&per_page=50"
    assert safe_return_path(value, "/targets/17/history") == value
    assert safe_return_path("https://example.org/x", "/targets") == "/targets"


def test_target_history_uses_twenty_results_per_page_by_default() -> None:
    route = Path("src/monitoring/web/routes.py").read_text(encoding="utf-8")
    assert "Pagination.from_request(request, len(history.results), default_per_page=20)" in route


def test_directory_file_buttons_use_the_unique_secondary_check_id() -> None:
    template = Path("src/monitoring/templates/_target_health.html").read_text(encoding="utf-8")
    assert 'directory-files-{{ service.check_id }}' in template
    assert 'directory-files-{{ service.id }}' not in template


def test_current_status_uses_latest_result_outside_selected_period() -> None:
    with _session() as session:
        site = Site(name="Main", description=None, enabled=True)
        session.add(site)
        session.flush()
        target = MonitorTarget(
            site_id=site.id,
            name="srv",
            kind="server",
            checker_type="tcp",
            address="127.0.0.1",
            comment=None,
            port=443,
            interval_seconds=300,
            enabled=True,
            favorite=False,
            display_order=0,
            notifications_suppressed=False,
        )
        session.add(target)
        session.flush()
        session.add(
            CheckResult(
                target_id=target.id,
                status="up",
                latency_ms=1.2,
                message=None,
                checked_at=datetime.now(UTC) - timedelta(hours=25),
            )
        )
        session.commit()
        history = target_history(session, target.id, hours=24)
        assert history.checked_count == 0
        assert history.latest_status == "up"
        assert history.is_online is True


def test_object_badge_and_mobile_chat_contracts() -> None:
    targets = Path("src/monitoring/templates/targets.html").read_text(encoding="utf-8")
    macro = Path("src/monitoring/templates/_target_tools.html").read_text(encoding="utf-8")
    css = Path("src/monitoring/static/app.css").read_text(encoding="utf-8")
    assert 'class="target-actions-layout"' in targets
    assert "target-actions-notification-row" not in targets
    assert "target-actions-notification-badge" not in targets
    assert "target-notification-badge" in macro
    assert '.targets-table-with-actions td[data-label="Название"] .target-tools {' in css
    assert '.targets-table-with-actions td[data-label="Название"] .target-tool-badges {' in css
    assert "grid-row: 2;" in css
    assert "justify-self: start;" in css
    assert ".chat-mobile-actions { margin: 0; padding: 0; border: 0; }" in css
    assert (
        ".chat-heading-actions { flex: 0 0 auto; align-items: center; flex-wrap: nowrap; }" in css
    )


def test_chat_presence_refreshes_without_message_submit() -> None:
    template = Path("src/monitoring/templates/chat.html").read_text(encoding="utf-8")
    js = Path("src/monitoring/static/app.js").read_text(encoding="utf-8")
    css = Path("src/monitoring/static/app.css").read_text(encoding="utf-8")
    assert "data-chat-peer-presence" in template
    assert 'copy.querySelector("[data-chat-peer-presence]")' in js
    assert 'currentPeerPresence.classList.toggle("is-online", isOnline)' in js
    assert 'currentPeerPresence.classList.toggle("is-offline", !isDeleted && !isOnline)' in js
    assert ".chat-peer-heading > small { margin-left: 7px; }" in css
    assert ".chat-peer-heading small { margin-left: 0; font-size: .66rem; }" in css


def test_hidden_chat_history_can_be_restored_and_boundary_is_real() -> None:
    from monitoring.models import ChatDeletionRequest, ChatMessage, User
    from monitoring.services.communication import (
        conversation_page,
        has_hidden_history,
        hidden_cutoff,
        restore_conversation_history,
    )

    now = datetime.now(UTC)
    with _session() as session:
        first = User(username="first", password_hash="x", role="admin", active=True)
        second = User(username="second", password_hash="x", role="viewer", active=True)
        session.add_all([first, second])
        session.flush()
        message = ChatMessage(
            sender_id=first.id,
            recipient_id=second.id,
            body="old",
            created_at=now - timedelta(minutes=10),
        )
        session.add(message)
        session.flush()
        deletion = ChatDeletionRequest(
            requester_id=first.id,
            peer_id=second.id,
            cutoff_at=now - timedelta(minutes=5),
            status="rejected",
            created_at=now - timedelta(minutes=5),
            responded_at=now - timedelta(minutes=4),
        )
        session.add(deletion)
        session.commit()

        assert has_hidden_history(session, first.id, second.id) is True
        assert conversation_page(session, first.id, second.id).messages == []
        restored = restore_conversation_history(session, user_id=first.id, peer_id=second.id)
        session.commit()
        assert [row.id for row in restored] == [deletion.id]
        assert deletion.status == "restored"
        assert hidden_cutoff(session, first.id, second.id) is None
        assert [row.body for row in conversation_page(session, first.id, second.id).messages] == [
            "old"
        ]


def test_hidden_history_boundary_disappears_after_physical_delete() -> None:
    from monitoring.models import ChatDeletionRequest, ChatMessage, User
    from monitoring.services.communication import has_hidden_history, resolve_deletion_request

    now = datetime.now(UTC)
    with _session() as session:
        first = User(username="a", password_hash="x", role="admin", active=True)
        second = User(username="b", password_hash="x", role="viewer", active=True)
        session.add_all([first, second])
        session.flush()
        session.add(
            ChatMessage(
                sender_id=first.id,
                recipient_id=second.id,
                body="old",
                created_at=now - timedelta(minutes=10),
            )
        )
        session.add(
            ChatDeletionRequest(
                requester_id=first.id,
                peer_id=second.id,
                cutoff_at=now - timedelta(minutes=8),
                status="rejected",
                created_at=now - timedelta(minutes=8),
                responded_at=now - timedelta(minutes=7),
            )
        )
        incoming = ChatDeletionRequest(
            requester_id=second.id,
            peer_id=first.id,
            cutoff_at=now - timedelta(minutes=1),
            status="pending",
            created_at=now - timedelta(minutes=1),
        )
        session.add(incoming)
        session.commit()

        assert has_hidden_history(session, first.id, second.id) is True
        resolve_deletion_request(
            session, request_id=incoming.id, peer_user_id=first.id, confirm=True
        )
        session.commit()
        assert has_hidden_history(session, first.id, second.id) is False


def test_chat_restore_button_is_inside_real_hidden_history_boundary() -> None:
    template = Path("src/monitoring/templates/chat.html").read_text(encoding="utf-8")
    css = Path("src/monitoring/static/app.css").read_text(encoding="utf-8")
    route = Path("src/monitoring/web/communication_routes.py").read_text(encoding="utf-8")
    assert "hidden_history_available and outgoing_deletion_request" in template
    assert template.count("Восстановить историю") == 2
    assert "/restore-history" in template
    assert '@router.post("/chat/{peer_id}/restore-history")' in route
    assert ".chat-history-boundary form { margin: 0; }" in css
    assert ".chat-history-restore { min-height: 30px;" in css


def test_settings_show_code_names_next_to_human_labels() -> None:
    template = Path("src/monitoring/templates/settings.html").read_text(encoding="utf-8")
    routes = Path("src/monitoring/web/routes.py").read_text(encoding="utf-8")
    assert "setting_labels.get(item.key, item.key)" in template
    assert "({{ item.key }})" in template
    assert '"min_password_length": "Минимальная длина пароля"' in routes
    assert '"notification_retention_days": "Хранение оповещений, дней"' in routes
    assert "setting_labels=SETTING_LABELS" in routes
