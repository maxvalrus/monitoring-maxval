from dataclasses import replace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from monitoring.config import Settings
from monitoring.db import Base
from monitoring.models import AppSetting
from monitoring.services.smtp_settings import (
    SMTP_SETTING_KEYS,
    SmtpForm,
    load_smtp_settings,
    update_smtp_settings,
)


def add_smtp_settings(session: Session) -> None:
    for key in SMTP_SETTING_KEYS:
        session.add(
            AppSetting(
                key=key,
                value=(
                    "587"
                    if key == "smtp_port"
                    else "true"
                    if key == "smtp_enabled"
                    else ""
                ),
                description=key,
            )
        )
    session.add(
        AppSetting(
            key="notifications_enabled",
            value="true",
            description="Почта",
        )
    )
    session.commit()


def test_smtp_password_is_encrypted_and_blank_value_preserves_it() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    app_settings = Settings(secret_key="test-secret-key", _env_file=None)
    with Session(engine) as session:
        add_smtp_settings(session)
        saved = update_smtp_settings(
            session,
            app_settings,
            SmtpForm(
                host=" smtp.example.test ",
                port=587,
                username="monitoring",
                password="private-password",
                sender="monitoring@example.test",
                recipient="admin@example.test",
                starttls=True,
            ),
        )
        session.commit()

        encrypted = session.get(AppSetting, "smtp_password")
        assert encrypted is not None
        assert encrypted.value != "private-password"
        assert "private-password" not in encrypted.value
        assert saved.password == "private-password"
        assert saved.enabled is True
        assert saved.channel_enabled is True
        assert saved.configured is True

        preserved = update_smtp_settings(
            session,
            app_settings,
            SmtpForm(
                host="smtp.example.test",
                port=2525,
                username="monitoring",
                password="",
                sender="monitoring@example.test",
                recipient="admin@example.test",
                starttls=False,
            ),
        )
        assert preserved.password == "private-password"
        assert preserved.port == 2525
        assert preserved.use_starttls is False


def test_smtp_channel_switch_is_independent_from_global_notifications() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    settings = Settings(secret_key="test-secret-key", _env_file=None)
    with Session(engine) as session:
        add_smtp_settings(session)
        form = SmtpForm(
            host="smtp.example.test",
            port=587,
            username="monitoring",
            password="",
            sender="monitoring@example.test",
            recipient="admin@example.test",
            starttls=True,
        )

        enabled = update_smtp_settings(session, settings, form)
        assert enabled.channel_enabled is True
        assert enabled.enabled is True

        disabled = update_smtp_settings(session, settings, replace(form, enabled=False))
        assert disabled.configured is True
        assert disabled.channel_enabled is False
        assert disabled.enabled is False
        stored = session.get(AppSetting, "smtp_enabled")
        assert stored is not None and stored.value == "false"

        session.get(AppSetting, "notifications_enabled").value = "false"
        globally_disabled = update_smtp_settings(
            session,
            settings,
            replace(form, enabled=True),
        )
        assert globally_disabled.channel_enabled is True
        assert globally_disabled.enabled is False


def test_smtp_password_can_be_cleared_and_rejects_changed_secret_key() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    original = Settings(secret_key="original-key", _env_file=None)
    with Session(engine) as session:
        add_smtp_settings(session)
        form = SmtpForm(
            host="smtp.example.test",
            port=587,
            username="monitoring",
            password="private-password",
            sender="monitoring@example.test",
            recipient="admin@example.test",
            starttls=True,
        )
        update_smtp_settings(session, original, form)
        session.commit()

        changed = Settings(secret_key="changed-key", _env_file=None)
        with pytest.raises(RuntimeError, match="MONITORING_SECRET_KEY"):
            load_smtp_settings(session, changed)

        cleared = update_smtp_settings(
            session,
            original,
            replace(form, password="", clear_password=True),
        )
        assert cleared.password == ""


def test_multiple_smtp_recipients_are_validated_and_normalized() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    settings = Settings(secret_key="test-secret-key", _env_file=None)
    with Session(engine) as session:
        add_smtp_settings(session)
        saved = update_smtp_settings(
            session,
            settings,
            SmtpForm(
                host="smtp.example.test",
                port=587,
                username="monitoring",
                password="",
                sender="monitoring@example.test",
                recipient=(
                    "first@example.test; second@example.test\nthird@example.test"
                ),
                starttls=True,
            ),
        )

        assert saved.recipient == (
            "first@example.test, second@example.test, third@example.test"
        )
        stored = session.get(AppSetting, "smtp_recipient")
        assert stored is not None and stored.value == saved.recipient

        too_many = ",".join(f"user{number}@example.test" for number in range(21))
        with pytest.raises(ValueError, match="не более 20"):
            update_smtp_settings(
                session,
                settings,
                SmtpForm(
                    host="smtp.example.test",
                    port=587,
                    username="monitoring",
                    password="",
                    sender="monitoring@example.test",
                    recipient=too_many,
                    starttls=True,
                ),
            )
