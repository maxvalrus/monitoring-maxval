import asyncio
import smtplib
from unittest.mock import MagicMock, patch

import pytest

from monitoring.notifications import (
    EmailNotifier,
    EmailSettings,
    Notification,
    smtp_error_message,
)


def test_email_notifier_uses_starttls_and_credentials() -> None:
    smtp = MagicMock()
    smtp.__enter__.return_value = smtp
    settings = EmailSettings(
        enabled=True,
        host="smtp.example.test",
        port=587,
        username="monitoring",
        password="test-only-password",
        sender="monitoring@example.test",
        recipient="admin@example.test",
        use_starttls=True,
    )

    with patch("monitoring.notifications.email.smtplib.SMTP", return_value=smtp) as factory:
        asyncio.run(EmailNotifier(settings).send(Notification("Тест", "Сообщение")))

    factory.assert_called_once_with("smtp.example.test", 587, timeout=15)
    smtp.starttls.assert_called_once_with()
    smtp.login.assert_called_once_with("monitoring", "test-only-password")
    smtp.send_message.assert_called_once()


def test_email_notifier_rejects_incomplete_configuration() -> None:
    notifier = EmailNotifier(EmailSettings(enabled=True))
    with pytest.raises(RuntimeError, match="SMTP не настроен"):
        asyncio.run(notifier.send(Notification("Тест", "Сообщение")))


def test_email_notifier_skips_automatic_email_when_channel_is_disabled() -> None:
    settings = EmailSettings(
        enabled=False,
        channel_enabled=False,
        host="smtp.example.test",
        sender="monitoring@example.test",
        recipient="admin@example.test",
    )

    with patch("monitoring.notifications.email.smtplib.SMTP") as smtp:
        sent = asyncio.run(EmailNotifier(settings).send(Notification("Тест", "Сообщение")))

    assert sent is False
    smtp.assert_not_called()


def test_email_notifier_can_force_a_test_while_notifications_are_disabled() -> None:
    smtp = MagicMock()
    smtp.__enter__.return_value = smtp
    settings = EmailSettings(
        enabled=False,
        host="smtp.example.test",
        port=587,
        sender="monitoring@example.test",
        recipient="admin@example.test",
        use_starttls=True,
    )

    with patch("monitoring.notifications.email.smtplib.SMTP", return_value=smtp):
        asyncio.run(EmailNotifier(settings).send(Notification("Тест", "Сообщение"), force=True))

    smtp.starttls.assert_called_once_with()
    smtp.send_message.assert_called_once()


def test_email_notifier_sends_to_multiple_recipients() -> None:
    smtp = MagicMock()
    smtp.__enter__.return_value = smtp
    settings = EmailSettings(
        enabled=True,
        host="smtp.example.test",
        sender="monitoring@example.test",
        recipient="first@example.test, second@example.test",
    )

    with patch("monitoring.notifications.email.smtplib.SMTP", return_value=smtp):
        asyncio.run(EmailNotifier(settings).send(Notification("Тест", "Сообщение")))

    message = smtp.send_message.call_args.args[0]
    assert message["To"] == "first@example.test, second@example.test"


def test_smtp_error_message_does_not_echo_server_payload() -> None:
    error = smtplib.SMTPAuthenticationError(535, b"secret server response")

    message = smtp_error_message(error)

    assert message == "SMTP-сервер отклонил логин или пароль"
    assert "secret" not in message
