from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from monitoring.db import Base
from monitoring.models import AppSetting, ChatMessage, User, UserNotification, UserRole
from monitoring.services.auth import hash_password
from monitoring.services.communication import chat_contacts, create_incident_notifications


def _session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_notification_mobile_contract():
    css = Path("src/monitoring/static/app.css").read_text()
    notifications = Path("src/monitoring/templates/notifications.html").read_text()
    assert (
        ".notification-mobile-menu" in css and "notification-mobile-menu-popover" in notifications
    )
    assert "grid-template-columns: 1fr 1fr" in css and "max-height: 300px" in css


def test_contacts_are_sorted_by_latest_message():
    with _session() as session:
        me = User(username="me", password_hash=hash_password("password1"), role=UserRole.ADMIN)
        alice = User(
            username="alice", password_hash=hash_password("password2"), role=UserRole.VIEWER
        )
        bob = User(username="bob", password_hash=hash_password("password3"), role=UserRole.VIEWER)
        charlie = User(
            username="charlie", password_hash=hash_password("password4"), role=UserRole.VIEWER
        )
        session.add_all([me, alice, bob, charlie])
        session.flush()
        now = datetime.now(UTC)
        session.add_all(
            [
                ChatMessage(
                    sender_id=me.id,
                    recipient_id=alice.id,
                    body="older",
                    created_at=now - timedelta(minutes=10),
                ),
                ChatMessage(
                    sender_id=bob.id,
                    recipient_id=me.id,
                    body="newer",
                    created_at=now - timedelta(minutes=1),
                ),
            ]
        )
        session.flush()
        assert [x.user.username for x in chat_contacts(session, me.id)] == [
            "bob",
            "alice",
            "charlie",
        ]


def test_internal_incident_notifications_ignore_external_master_switch():
    with _session() as session:
        admin = User(
            username="admin", password_hash=hash_password("password1"), role=UserRole.ADMIN
        )
        viewer = User(
            username="viewer", password_hash=hash_password("password2"), role=UserRole.VIEWER
        )
        session.add_all(
            [
                admin,
                viewer,
                AppSetting(key="notifications_enabled", value="false", description="external"),
            ]
        )
        session.flush()
        ids = create_incident_notifications(
            session,
            incident_id=7,
            kind="opened",
            target_name="Сервер",
            site_name="Офис",
            message="timeout",
        )
        assert ids == [admin.id, viewer.id]
        rows = session.query(UserNotification).all()
        assert len(rows) == 2 and all(r.kind == "incident_opened" for r in rows)


def test_external_channels_are_gated_separately():
    push = Path("src/monitoring/services/push.py").read_text()
    smtp = Path("src/monitoring/services/smtp_settings.py").read_text()
    scheduler = Path("src/monitoring/services/scheduler.py").read_text()
    assert 'session.get(AppSetting, "notifications_enabled")' in push and "external_enabled" in push
    assert '_value(session, "notifications_enabled", "true")' in smtp
    assert '_value(session, "smtp_enabled", "true")' in smtp
    assert (
        "create_incident_notifications(" in scheduler
        and "if notifications_enabled:" not in scheduler
    )


def test_clean_install_enables_external_notifications_by_default():
    migration = Path("alembic/versions/0036_baseline_0_8_5.py").read_text()
    backups = Path("src/monitoring/services/backups.py").read_text()
    routes = Path("src/monitoring/web/routes.py").read_text()
    assert '("notifications_enabled", "true"' in migration
    assert (
        '"notifications_enabled": "true"' in backups
        and '"smtp_enabled": "true"' in backups
        and '"notifications_enabled": "включено"' in routes
    )


def test_clean_install_enables_smtp_channel_by_default():
    migration = Path("alembic/versions/0036_baseline_0_8_5.py").read_text()
    assert '("smtp_enabled", "true"' in migration


def test_snmp_sample_limit_baseline_defaults_to_one_thousand():
    migration = Path("alembic/versions/0036_baseline_0_8_5.py").read_text()
    assert '("snmp_sample_max_per_target", "1000"' in migration
