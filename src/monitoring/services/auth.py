import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from monitoring.config import Settings
from monitoring.models import (
    AppSetting,
    FailedLoginAttempt,
    LoginBlock,
    User,
    UserRole,
    UserSession,
)
from monitoring.services.audit import write_audit

USERNAME_PATTERN = re.compile(r"^[\w.@+-]{3,64}$", re.UNICODE)
PASSWORD_HASHER = PasswordHasher(type=Type.ID)
DUMMY_PASSWORD_HASH = PASSWORD_HASHER.hash("timing-only-password")


@dataclass(frozen=True, slots=True)
class AuthContext:
    user: User
    user_session: UserSession


def utc_now() -> datetime:
    return datetime.now(UTC)


def ensure_aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def normalize_username(username: str) -> str:
    return username.strip().casefold()


def validate_username(username: str) -> str:
    normalized = normalize_username(username)
    if not USERNAME_PATTERN.fullmatch(normalized):
        raise ValueError("Логин: 3–64 символа; допустимы буквы, цифры, _, ., @, + и -")
    return normalized


def get_min_password_length(session: Session) -> int:
    value = session.get(AppSetting, "min_password_length")
    try:
        return max(3, min(64, int(value.value))) if value else 8
    except ValueError:
        return 8


def validate_password(session: Session, password: str) -> None:
    minimum = get_min_password_length(session)
    if len(password) < minimum or len(password) > 64:
        raise ValueError(f"Пароль должен содержать от {minimum} до 64 символов")


def hash_password(password: str) -> str:
    return PASSWORD_HASHER.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(password_hash, password)
    except (InvalidHashError, VerificationError, VerifyMismatchError):
        return False


def create_user(
    session: Session,
    username: str,
    password: str,
    role: str = UserRole.VIEWER,
) -> User:
    normalized = validate_username(username)
    validate_password(session, password)
    if role not in {UserRole.ADMIN, UserRole.VIEWER}:
        raise ValueError("Неизвестная роль")
    if session.scalar(select(User.id).where(User.username == normalized)) is not None:
        raise ValueError("Пользователь с таким логином уже существует")
    user = User(username=normalized, password_hash=hash_password(password), role=role)
    session.add(user)
    session.flush()
    return user


def authenticate_user(session: Session, username: str, password: str) -> User | None:
    normalized = normalize_username(username)
    user = session.scalar(select(User).where(User.username == normalized, User.active.is_(True)))
    password_hash = user.password_hash if user is not None else DUMMY_PASSWORD_HASH
    if not verify_password(password_hash, password) or user is None:
        return None
    if PASSWORD_HASHER.check_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    return user


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_server_session(
    session: Session,
    user: User,
    settings: Settings,
    ip_address: str,
    user_agent: str,
) -> tuple[str, UserSession]:
    now = utc_now()
    raw_token = secrets.token_urlsafe(32)
    stored = UserSession(
        user_id=user.id,
        token_hash=token_hash(raw_token),
        csrf_token=secrets.token_urlsafe(32),
        ip_address=ip_address,
        user_agent=user_agent[:300],
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(hours=settings.session_max_hours),
    )
    session.add(stored)
    session.flush()
    return raw_token, stored


def resolve_server_session(
    session: Session,
    raw_token: str | None,
    settings: Settings,
) -> AuthContext | None:
    if not raw_token:
        return None
    row = session.execute(
        select(UserSession, User)
        .join(User, User.id == UserSession.user_id)
        .where(UserSession.token_hash == token_hash(raw_token))
    ).one_or_none()
    if row is None:
        return None

    stored, user = row
    now = utc_now()
    idle_limit = now - timedelta(hours=settings.session_idle_hours)
    expired = ensure_aware(stored.expires_at) <= now
    idle = ensure_aware(stored.last_seen_at) <= idle_limit
    if expired or idle or not user.active:
        session.delete(stored)
        session.commit()
        return None

    if ensure_aware(stored.last_seen_at) <= now - timedelta(minutes=5):
        stored.last_seen_at = now
        session.commit()
    return AuthContext(user=user, user_session=stored)


def revoke_session(session: Session, raw_token: str | None) -> None:
    if raw_token:
        session.execute(delete(UserSession).where(UserSession.token_hash == token_hash(raw_token)))


def revoke_user_sessions(session: Session, user_id: int) -> None:
    session.execute(delete(UserSession).where(UserSession.user_id == user_id))


def get_active_block(
    session: Session, username: str, ip_address: str
) -> LoginBlock | None:
    normalized = normalize_username(username)
    block = session.scalar(
        select(LoginBlock).where(
            LoginBlock.username == normalized,
            LoginBlock.ip_address == ip_address,
        )
    )
    if block is not None and ensure_aware(block.blocked_until) <= utc_now():
        session.delete(block)
        session.commit()
        return None
    return block


def record_failed_login(
    session: Session,
    username: str,
    ip_address: str,
    settings: Settings,
) -> LoginBlock | None:
    normalized = normalize_username(username)[:64]
    now = utc_now()
    session.add(
        FailedLoginAttempt(username=normalized, ip_address=ip_address, occurred_at=now)
    )
    session.flush()

    window_start = now - timedelta(minutes=settings.login_block_minutes)
    count = session.scalar(
        select(func.count(FailedLoginAttempt.id)).where(
            FailedLoginAttempt.username == normalized,
            FailedLoginAttempt.ip_address == ip_address,
            FailedLoginAttempt.occurred_at >= window_start,
        )
    )
    block: LoginBlock | None = None
    if count is not None and count >= settings.login_max_attempts:
        block = session.scalar(
            select(LoginBlock).where(
                LoginBlock.username == normalized,
                LoginBlock.ip_address == ip_address,
            )
        )
        blocked_until = now + timedelta(minutes=settings.login_block_minutes)
        if block is None:
            block = LoginBlock(
                username=normalized,
                ip_address=ip_address,
                blocked_until=blocked_until,
            )
            session.add(block)
        else:
            block.blocked_until = blocked_until

    keep_ids = select(FailedLoginAttempt.id).order_by(FailedLoginAttempt.id.desc()).limit(100)
    session.execute(delete(FailedLoginAttempt).where(FailedLoginAttempt.id.not_in(keep_ids)))
    return block


def complete_login(
    session: Session, user: User, ip_address: str, username: str
) -> None:
    normalized = normalize_username(username)
    user.last_login_at = utc_now()
    user.last_login_ip = ip_address
    session.execute(
        delete(FailedLoginAttempt).where(
            FailedLoginAttempt.username == normalized,
            FailedLoginAttempt.ip_address == ip_address,
        )
    )
    session.execute(
        delete(LoginBlock).where(
            LoginBlock.username == normalized,
            LoginBlock.ip_address == ip_address,
        )
    )
    write_audit(
        session,
        "auth.login_success",
        user_id=user.id,
        entity_type="user",
        entity_id=user.id,
        entity_name=user.username,
        ip_address=ip_address,
    )
