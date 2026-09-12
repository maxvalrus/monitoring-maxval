from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from monitoring.db import Base
from monitoring.models import Incident, MonitorTarget, Site, User, UserNotification, UserRole
from monitoring.services.auth import hash_password
from monitoring.services.communication import (
    create_incident_notifications,
    notification_destination,
)


def _session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_chat_contract():
    chat = Path("src/monitoring/templates/chat.html").read_text()
    css = Path("src/monitoring/static/app.css").read_text()
    js = Path("src/monitoring/static/app.js").read_text()
    assert "data-chat-fullscreen-toggle" in chat and "data-chat-read-state" in chat
    assert "body.chat-fullscreen" in css and "@media (max-width:1100px)" in css
    assert (
        "incomingState.dataset.chatReadState !== currentState.dataset.chatReadState" in js
        and "initChatFullscreen()" in js
    )


def test_notification_links():
    with _session() as session:
        user = User(username="admin", password_hash=hash_password("password1"), role=UserRole.ADMIN)
        session.add(user)
        session.flush()
        create_incident_notifications(
            session,
            incident_id=17,
            kind="opened",
            target_name="Server",
            site_name="Office",
            target_id=9,
        )
        row = session.query(UserNotification).one()
        assert row.link == "/incidents?focus_id=17#incident-17"
        session.delete(row)
        session.flush()
        create_incident_notifications(
            session,
            incident_id=17,
            kind="recovered",
            target_name="Server",
            site_name="Office",
            target_id=9,
        )
        row = session.query(UserNotification).one()
        assert row.link == "/incidents?focus_id=17#incident-17"
        assert row.source_type == "incident" and row.source_id == "17"


def test_legacy_recovery_notification_opens_its_incident():
    with _session() as session:
        now = datetime.now(UTC)
        site = Site(name="Office", description=None)
        session.add(site)
        session.flush()
        target = MonitorTarget(
            site_id=site.id,
            name="Server",
            address="127.0.0.1",
            port=80,
            comment=None,
        )
        session.add(target)
        session.flush()
        incident = Incident(
            target_id=target.id,
            status="resolved",
            opened_at=now - timedelta(minutes=5),
            resolved_at=now,
            last_failure_at=now - timedelta(minutes=1),
        )
        session.add(incident)
        session.flush()
        row = UserNotification(
            user_id=1,
            kind="incident_recovered",
            title="Восстановлен: Server",
            body="Office. Объект снова доступен.",
            link=f"/?focus_target_id={target.id}#target-{target.id}",
            source_type="target",
            source_id=str(target.id),
            created_at=now + timedelta(seconds=1),
        )
        session.add(row)
        session.flush()

        assert notification_destination(session, row) == (
            f"/incidents?focus_id={incident.id}#incident-{incident.id}"
        )
        assert row.source_type == "incident" and row.source_id == str(incident.id)


def test_unmatched_legacy_recovery_opens_resolved_incident_log():
    with _session() as session:
        row = UserNotification(
            user_id=1,
            kind="incident_recovered",
            title="Восстановлен: удалённый объект",
            body="Объект снова доступен.",
            link="/?focus_target_id=999#target-999",
            source_type="target",
            source_id="999",
        )
        session.add(row)
        session.flush()

        assert notification_destination(session, row) == "/incidents?status=resolved"
        assert row.source_type == "incident" and row.source_id is None


def test_linked_titles_and_edit():
    incidents = Path("src/monitoring/templates/incidents.html").read_text()
    dashboard = Path("src/monitoring/templates/dashboard.html").read_text()
    reports = Path("src/monitoring/templates/reports.html").read_text()
    targets = Path("src/monitoring/templates/targets.html").read_text()
    js = Path("src/monitoring/static/app.js").read_text()
    assert (
        "detail-title-link" in incidents
        and "focus_target_id" in incidents
        and "Изменить объект" in incidents
    )
    assert (
        "detail-title-link" in dashboard
        and 'id="target-{{ target.id }}"' in dashboard
        and "detail-title-link" in reports
    )
    assert "focus_target_id == target.id" in targets and "focusNavigationTarget" in js
    assert "data-navigation-focus" in js
