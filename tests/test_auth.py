from datetime import timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from monitoring.config import Settings
from monitoring.db import Base
from monitoring.models import FailedLoginAttempt, LoginBlock, UserRole
from monitoring.services.auth import (
    authenticate_user,
    create_server_session,
    create_user,
    hash_password,
    record_failed_login,
    resolve_server_session,
    utc_now,
    verify_password,
)


def make_session() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return Session(engine)


def test_passwords_use_argon2id() -> None:
    encoded = hash_password("a sufficiently long password")
    assert encoded.startswith("$argon2id$")
    assert verify_password(encoded, "a sufficiently long password")
    assert not verify_password(encoded, "wrong password")


def test_password_minimum_is_eight_characters_without_setting() -> None:
    with make_session() as session:
        with pytest.raises(ValueError, match="от 8 до 64"):
            create_user(session, "admin", "1234567", UserRole.ADMIN)

        user = create_user(session, "admin", "12345678", UserRole.ADMIN)
        assert user.username == "admin"


def test_server_session_expires_after_idle_limit() -> None:
    settings = Settings(_env_file=None)
    with make_session() as session:
        user = create_user(session, "admin", "a sufficiently long password", UserRole.ADMIN)
        raw_token, stored = create_server_session(session, user, settings, "127.0.0.1", "test")
        session.commit()
        assert resolve_server_session(session, raw_token, settings) is not None

        stored.last_seen_at = utc_now() - timedelta(hours=9)
        session.commit()
        assert resolve_server_session(session, raw_token, settings) is None


def test_server_session_never_outlives_absolute_limit() -> None:
    settings = Settings(_env_file=None)
    with make_session() as session:
        user = create_user(session, "admin", "a sufficiently long password", UserRole.ADMIN)
        raw_token, stored = create_server_session(session, user, settings, "127.0.0.1", "test")
        stored.expires_at = utc_now() - timedelta(seconds=1)
        stored.last_seen_at = utc_now()
        session.commit()
        assert resolve_server_session(session, raw_token, settings) is None


def test_five_failures_create_temporary_block() -> None:
    settings = Settings(_env_file=None)
    with make_session() as session:
        for _ in range(5):
            block = record_failed_login(session, "admin", "127.0.0.1", settings)
            session.commit()
        assert block is not None
        assert session.query(LoginBlock).count() == 1


def test_only_last_hundred_failed_attempts_are_retained() -> None:
    settings = Settings(_env_file=None)
    with make_session() as session:
        for index in range(105):
            record_failed_login(session, f"user{index}", "127.0.0.1", settings)
            session.commit()
        assert session.query(FailedLoginAttempt).count() == 100


def test_inactive_user_cannot_authenticate() -> None:
    with make_session() as session:
        user = create_user(session, "viewer", "a sufficiently long password", UserRole.VIEWER)
        user.active = False
        session.commit()
        assert authenticate_user(session, "viewer", "a sufficiently long password") is None
