import asyncio
import smtplib
from collections.abc import Callable
from dataclasses import dataclass
from email.message import EmailMessage

from monitoring.notifications.base import Notification


@dataclass(frozen=True, slots=True)
class EmailSettings:
    enabled: bool = False
    channel_enabled: bool = True
    host: str = ""
    port: int = 587
    username: str = ""
    password: str = ""
    sender: str = ""
    recipient: str = ""
    use_starttls: bool = True

    @property
    def configured(self) -> bool:
        return bool(self.host and self.sender and self.recipient)


class EmailNotifier:
    """SMTP channel used for incident and test notifications."""

    name = "email"

    def __init__(self, settings: EmailSettings | Callable[[], EmailSettings]) -> None:
        self._settings = settings

    def _current_settings(self) -> EmailSettings:
        if callable(self._settings):
            return self._settings()
        return self._settings

    async def send(self, notification: Notification, *, force: bool = False) -> bool:
        settings = await asyncio.to_thread(self._current_settings)
        if not settings.enabled and not force:
            return False
        if not settings.configured:
            raise RuntimeError("SMTP не настроен: нужны сервер, отправитель и получатель")
        await asyncio.to_thread(self._send_sync, settings, notification)
        return True

    @staticmethod
    def _send_sync(settings: EmailSettings, notification: Notification) -> None:
        message = EmailMessage()
        message["Subject"] = notification.subject
        message["From"] = settings.sender
        message["To"] = settings.recipient
        message.set_content(notification.body)

        with smtplib.SMTP(settings.host, settings.port, timeout=15) as smtp:
            if settings.use_starttls:
                smtp.starttls()
            if settings.username:
                smtp.login(settings.username, settings.password)
            smtp.send_message(message)


def smtp_error_message(exc: Exception) -> str:
    """Return a useful SMTP error without echoing server payloads or credentials."""
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "SMTP-сервер отклонил логин или пароль"
    if isinstance(exc, smtplib.SMTPNotSupportedError):
        return "SMTP-сервер не поддерживает выбранный режим шифрования или авторизации"
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "SMTP-сервер отклонил адрес получателя"
    if isinstance(
        exc,
        (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, TimeoutError, OSError),
    ):
        return "Не удалось подключиться к SMTP-серверу"
    if isinstance(exc, smtplib.SMTPException):
        return "SMTP-сервер вернул ошибку при отправке"
    return f"Внутренняя ошибка отправки ({type(exc).__name__})"
