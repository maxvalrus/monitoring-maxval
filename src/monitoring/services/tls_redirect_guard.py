"""Fail-open guard for an expiring portal TLS certificate."""

from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime

from sqlalchemy import select

from monitoring.config import Settings
from monitoring.db import SessionLocal
from monitoring.models import AppSetting, User, UserRole
from monitoring.services.audit import write_audit
from monitoring.services.communication import create_notification
from monitoring.services.tls import TlsManager, TlsManagerError, TlsStatus

logger = logging.getLogger(__name__)
CHECK_INTERVAL_SECONDS = 60 * 60


def should_disable_redirect(
    *, https_enabled: bool, redirect_enabled: bool, status: TlsStatus
) -> bool:
    return (
        https_enabled
        and redirect_enabled
        and status.available
        and not status.active_redirect_safe
    )


def disable_unsafe_redirect(settings: Settings) -> bool:
    with SessionLocal() as session:
        https = session.get(AppSetting, "https_enabled")
        redirect = session.get(AppSetting, "https_redirect_http")
        https_enabled = https is not None and https.value == "true"
        redirect_enabled = redirect is not None and redirect.value == "true"

    manager = TlsManager(settings)
    status = manager.status()
    if not should_disable_redirect(
        https_enabled=https_enabled,
        redirect_enabled=redirect_enabled,
        status=status,
    ):
        return False

    manager.disable_redirect()
    with SessionLocal() as session:
        redirect = session.get(AppSetting, "https_redirect_http")
        if redirect is None or redirect.value != "true":
            return False
        redirect.value = "false"
        admin_ids = session.scalars(
            select(User.id)
            .where(User.active.is_(True), User.role == UserRole.ADMIN)
            .order_by(User.id)
        ).all()
        for user_id in admin_ids:
            create_notification(
                session,
                user_id=user_id,
                kind="tls_certificate_expiring",
                title="HTTP → HTTPS перенаправление отключено",
                body=(
                    "Активный TLS-сертификат истекает в течение двух суток или уже истёк. "
                    "Прямой HTTP-доступ восстановлен: замените сертификат в настройках HTTPS."
                ),
                link="/settings",
                source_type="https",
                source_id=status.active_expires_at or "unknown",
            )
        write_audit(
            session,
            "https.redirect_disabled_expiring_certificate",
            entity_type="https",
            details={"expires_at": status.active_expires_at},
        )
        session.commit()
    return True


def warn_expiring_certificate(settings: Settings) -> bool:
    """Create one internal warning per active certificate expiry value."""
    manager = TlsManager(settings)
    status = manager.status()
    if not status.available or not status.active_valid or not status.active_expires_at:
        return False
    try:
        expires_at = parsedate_to_datetime(status.active_expires_at)
    except (TypeError, ValueError):
        return False
    with SessionLocal() as session:
        enabled = session.get(AppSetting, "tls_expiry_warning_enabled")
        days = session.get(AppSetting, "tls_expiry_warning_days")
        if enabled is None or enabled.value != "true" or days is None:
            return False
        try:
            warning_days = int(days.value)
        except ValueError:
            return False
        if expires_at - datetime.now(UTC) > timedelta(days=warning_days):
            return False
        source_id = status.active_expires_at
        previous = session.get(AppSetting, "tls_expiry_warning_last")
        if previous is not None and previous.value == source_id:
            return False
        if previous is None:
            session.add(AppSetting(key="tls_expiry_warning_last", value=source_id, description="Последнее предупреждение TLS"))
        else:
            previous.value = source_id
        for user_id in session.scalars(select(User.id).where(User.active.is_(True), User.role == UserRole.ADMIN)):
            create_notification(session, user_id=user_id, kind="tls_certificate_expiring", title="TLS-сертификат скоро истечёт", body=f"Активный TLS-сертификат действует до {status.active_expires_at}. Замените его в настройках HTTPS.", link="/settings", source_type="https", source_id=source_id)
        session.commit()
    return True


class TlsRedirectGuard:
    def __init__(self, settings: Settings, interval_seconds: int = CHECK_INTERVAL_SECONDS) -> None:
        self.settings = settings
        self.interval_seconds = interval_seconds
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="tls-redirect-guard")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            await self._task
            self._task = None

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                disabled = await asyncio.to_thread(disable_unsafe_redirect, self.settings)
                await asyncio.to_thread(warn_expiring_certificate, self.settings)
                if disabled:
                    logger.warning(
                        "Disabled HTTP to HTTPS redirect because the active TLS certificate "
                        "expires within two days or has expired"
                    )
            except TlsManagerError:
                logger.warning("TLS redirect guard could not reach tls-manager")
            except Exception:
                logger.exception("TLS redirect guard failed")
            with suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=self.interval_seconds)
