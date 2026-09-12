from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from monitoring.db import SessionLocal
from monitoring.models import AppSetting, PushSubscription, User
from monitoring.services.communication import create_notification, is_chat_visible

logger = logging.getLogger(__name__)

VAPID_PRIVATE_KEY = "push_vapid_private_key"
VAPID_PUBLIC_KEY = "push_vapid_public_key"
VAPID_SUBJECT = "push_vapid_subject"


@dataclass(frozen=True, slots=True)
class PushDeliveryResult:
    sent: int
    failed: int
    message: str | None = None


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _setting(session: Session, key: str) -> str:
    row = session.get(AppSetting, key)
    return row.value if row is not None else ""


def _save_setting(session: Session, key: str, value: str, description: str) -> None:
    row = session.get(AppSetting, key)
    if row is None:
        session.add(AppSetting(key=key, value=value, description=description))
    else:
        row.value = value
        row.description = description


def ensure_vapid_keys(session: Session) -> tuple[str, str]:
    private_key_value = _setting(session, VAPID_PRIVATE_KEY)
    public_key = _setting(session, VAPID_PUBLIC_KEY)
    if private_key_value and public_key:
        return private_key_value, public_key

    private_key = ec.generate_private_key(ec.SECP256R1())
    private_raw = private_key.private_numbers().private_value.to_bytes(32, "big")
    private_key_value = _b64url(private_raw)
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    public_key = _b64url(public_bytes)
    _save_setting(
        session,
        VAPID_PRIVATE_KEY,
        private_key_value,
        "Закрытый VAPID-ключ PWA Push. Не отображается в интерфейсе.",
    )
    _save_setting(
        session,
        VAPID_PUBLIC_KEY,
        public_key,
        "Открытый VAPID-ключ PWA Push.",
    )
    session.flush()
    return private_key_value, public_key


def set_vapid_subject(session: Session, origin: str) -> bool:
    """Store the portal's HTTPS origin as the VAPID contact subject.

    The browser supplies this origin only while it registers or tests a Push
    subscription.  Endpoint and browser-generated subscription keys remain
    untouched and are never exposed by this helper.
    """
    parsed = urlsplit(origin)
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    hostname = parsed.hostname
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    port = f":{parsed.port}" if parsed.port and parsed.port != 443 else ""
    _save_setting(
        session,
        VAPID_SUBJECT,
        f"https://{hostname}{port}",
        "HTTPS-адрес портала для подписи VAPID. Формируется автоматически.",
    )
    session.flush()
    return True


def vapid_subject(session: Session) -> str | None:
    subject = _setting(session, VAPID_SUBJECT)
    parsed = urlsplit(subject)
    return subject if parsed.scheme == "https" and parsed.hostname else None


def save_subscription(
    session: Session,
    *,
    user_id: int,
    endpoint: str,
    p256dh: str,
    auth: str,
    user_agent: str | None,
) -> PushSubscription:
    endpoint = endpoint.strip()
    p256dh = p256dh.strip()
    auth = auth.strip()
    if not endpoint or not p256dh or not auth:
        raise ValueError("Браузер передал неполную подписку Push")
    row = session.scalar(select(PushSubscription).where(PushSubscription.endpoint == endpoint))
    if row is None:
        row = PushSubscription(
            user_id=user_id,
            endpoint=endpoint,
            p256dh=p256dh,
            auth=auth,
            user_agent=(user_agent or "")[:300] or None,
        )
        session.add(row)
    else:
        row.user_id = user_id
        row.p256dh = p256dh
        row.auth = auth
        row.user_agent = (user_agent or "")[:300] or None
    session.flush()
    return row


def delete_subscription(session: Session, *, user_id: int, endpoint: str) -> int:
    result = session.execute(
        delete(PushSubscription).where(
            PushSubscription.user_id == user_id,
            PushSubscription.endpoint == endpoint,
        )
    )
    return int(result.rowcount or 0)


def delete_subscription_by_id(session: Session, subscription_id: int) -> PushSubscription | None:
    row = session.get(PushSubscription, subscription_id)
    if row is not None:
        session.delete(row)
    return row


def _remove_stale_subscriptions(user_id: int, endpoints: list[str]) -> None:
    """Forget rejected endpoints and leave a visible, non-Push recovery notice."""
    if not endpoints:
        return
    with SessionLocal() as session:
        result = session.execute(
            delete(PushSubscription).where(
                PushSubscription.user_id == user_id,
                PushSubscription.endpoint.in_(endpoints),
            )
        )
        if result.rowcount:
            create_notification(
                session,
                user_id=user_id,
                kind="push_subscription_invalid",
                title="Push на устройстве требует повторного подключения",
                body=(
                    "Push-сервис сообщил, что одна из подписок устройства больше не действует. "
                    "Откройте портал на этом устройстве по HTTPS и включите Push заново."
                ),
                link="/settings",
                source_type="push_subscription",
                source_id=f"stale-user-{user_id}",
            )
        session.commit()


def push_device_label(user_agent: str | None) -> str:
    value = (user_agent or "").casefold()
    if "iphone" in value:
        return "iPhone"
    if "ipad" in value:
        return "iPad"
    if "android" in value:
        return "Android"
    if "macintosh" in value or "mac os" in value:
        return "Mac"
    if "windows" in value:
        return "Windows"
    if "linux" in value:
        return "Linux"
    return "Неизвестное устройство"


def user_push_category_enabled(user: User, category: str) -> bool:
    if category == "chat":
        return bool(user.push_chat_enabled)
    if category == "incident_opened":
        return bool(user.push_incident_enabled)
    if category == "incident_recovered":
        return bool(user.push_recovery_enabled)
    return True


def send_push_to_user(
    user_id: int,
    *,
    category: str,
    title: str,
    body: str,
    url: str = "/",
) -> PushDeliveryResult:
    """Send Web Push outside request transactions. Delivery errors are non-fatal."""
    with SessionLocal() as session:
        global_setting = session.get(AppSetting, "notifications_enabled")
        external_enabled = global_setting is None or global_setting.value.casefold() == "true"
        if not external_enabled:
            return PushDeliveryResult(0, 0)
        user = session.get(User, user_id)
        if user is None or not user.active or not user_push_category_enabled(user, category):
            return PushDeliveryResult(0, 0)
        subscriptions = session.scalars(
            select(PushSubscription)
            .where(PushSubscription.user_id == user_id)
            .order_by(PushSubscription.id)
        ).all()
        if not subscriptions:
            return PushDeliveryResult(0, 0)
        private_key, _public_key = ensure_vapid_keys(session)
        subject = vapid_subject(session)
        session.commit()
        subscription_data = [
            (row.endpoint, row.p256dh, row.auth)
            for row in subscriptions
        ]

    if not subject:
        logger.warning("Web Push skipped for user %s: no HTTPS VAPID subject", user_id)
        return PushDeliveryResult(0, len(subscription_data))
    try:
        return _deliver_pushes(
            subscription_data,
            private_key=private_key,
            subject=subject,
            title=title,
            body=body,
            url=url,
            category=category,
            user_id=user_id,
        )
    except ImportError:
        logger.warning("pywebpush is unavailable; PWA Push delivery skipped")
        return PushDeliveryResult(0, 0)


def send_chat_push_if_unseen(
    recipient_id: int,
    *,
    sender_id: int,
    title: str,
    body: str,
    url: str,
) -> PushDeliveryResult:
    """Do not interrupt a recipient already viewing this exact dialogue."""
    with SessionLocal() as session:
        if is_chat_visible(session, user_id=recipient_id, peer_id=sender_id):
            return PushDeliveryResult(0, 0)
    return send_push_to_user(recipient_id, category="chat", title=title, body=body, url=url)


def send_test_push_to_subscription(subscription_id: int) -> PushDeliveryResult:
    """Send an explicit administrator test, independent of notification toggles."""
    try:
        from pywebpush import WebPushException, webpush
    except ImportError:
        logger.warning("pywebpush is unavailable; PWA Push test skipped")
        return PushDeliveryResult(0, 1, "Компонент Web Push недоступен")

    with SessionLocal() as session:
        row = session.get(PushSubscription, subscription_id)
        if row is None:
            return PushDeliveryResult(0, 1, "Подписка уже удалена")
        private_key, _public_key = ensure_vapid_keys(session)
        subject = vapid_subject(session)
        subscription_data = (row.endpoint, row.p256dh, row.auth)
        session.commit()

    if not subject:
        return PushDeliveryResult(
            0,
            1,
            "Откройте настройки по HTTPS, затем повторите отправку тестового Push",
        )
    endpoint, p256dh, auth = subscription_data
    payload = json.dumps(
        {
            "title": "Тестовое Push-уведомление",
            "body": "Подписка Monitoring Maxval работает.",
            "url": "/settings",
            "category": "test",
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    try:
        webpush(
            subscription_info={
                "endpoint": endpoint,
                "keys": {"p256dh": p256dh, "auth": auth},
            },
            data=payload,
            vapid_private_key=private_key,
            vapid_claims={"sub": subject},
            timeout=8,
        )
    except WebPushException as exc:
        status_code = getattr(getattr(exc, "response", None), "status_code", None)
        if status_code in {404, 410}:
            _remove_stale_subscriptions(row.user_id, [endpoint])
            return PushDeliveryResult(0, 1, "Подписка устарела и была удалена")
        logger.warning(
            "Web Push test failed for subscription %s: HTTP %s",
            subscription_id,
            status_code,
        )
        return PushDeliveryResult(0, 1, "Push-сервис отклонил тестовую отправку")
    except Exception:
        logger.exception("Unexpected Web Push test error for subscription %s", subscription_id)
        return PushDeliveryResult(0, 1, "Не удалось отправить тестовый Push")
    return PushDeliveryResult(1, 0)


def _deliver_pushes(
    subscription_data: list[tuple[str, str, str]],
    *,
    private_key: str,
    subject: str,
    title: str,
    body: str,
    url: str,
    category: str,
    user_id: int,
) -> PushDeliveryResult:
    from pywebpush import WebPushException, webpush

    payload = json.dumps(
        {"title": title, "body": body, "url": url, "category": category},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    sent = 0
    failed = 0
    stale_endpoints: list[str] = []
    for endpoint, p256dh, auth in subscription_data:
        try:
            webpush(
                subscription_info={
                    "endpoint": endpoint,
                    "keys": {"p256dh": p256dh, "auth": auth},
                },
                data=payload,
                vapid_private_key=private_key,
                vapid_claims={"sub": subject},
                timeout=8,
            )
            sent += 1
        except WebPushException as exc:
            failed += 1
            status_code = getattr(getattr(exc, "response", None), "status_code", None)
            if status_code in {404, 410}:
                stale_endpoints.append(endpoint)
            logger.warning("Web Push failed for user %s: %s", user_id, exc)
        except Exception:
            failed += 1
            logger.exception("Unexpected Web Push error for user %s", user_id)

    _remove_stale_subscriptions(user_id, stale_endpoints)
    return PushDeliveryResult(sent, failed)
