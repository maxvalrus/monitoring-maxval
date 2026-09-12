import re
from dataclasses import dataclass

from sqlalchemy.orm import Session

from monitoring.config import Settings
from monitoring.models import AppSetting
from monitoring.notifications import EmailSettings
from monitoring.services.secrets import decrypt_secret, encrypt_secret

SMTP_SETTING_KEYS = frozenset(
    {
        "smtp_enabled",
        "smtp_host",
        "smtp_port",
        "smtp_username",
        "smtp_password",
        "smtp_sender",
        "smtp_recipient",
        "smtp_starttls",
    }
)
RECIPIENT_SPLITTER = re.compile(r"[,;\r\n]+")
MAX_RECIPIENTS = 20


@dataclass(frozen=True, slots=True)
class SmtpForm:
    host: str
    port: int
    username: str
    password: str
    sender: str
    recipient: str
    starttls: bool
    enabled: bool = True
    clear_password: bool = False


def _value(session: Session, key: str, default: str = "") -> str:
    setting = session.get(AppSetting, key)
    return setting.value if setting is not None else default


def _decrypt_password(settings: Settings, token: str) -> str:
    return decrypt_secret(settings, token, label="SMTP-пароль")




def encrypt_smtp_password(settings: Settings, password: str) -> str:
    """Encrypt a portable SMTP password using the current installation secret."""
    return encrypt_secret(settings, password)

def load_smtp_settings(session: Session, settings: Settings) -> EmailSettings:
    port_value = _value(session, "smtp_port", "587")
    try:
        port = int(port_value)
    except ValueError:
        port = 587
    host = _value(session, "smtp_host")
    sender = _value(session, "smtp_sender")
    recipient = _value(session, "smtp_recipient")
    globally_enabled = _value(session, "notifications_enabled", "true") == "true"
    channel_enabled = _value(session, "smtp_enabled", "true") == "true"
    return EmailSettings(
        enabled=globally_enabled and channel_enabled and bool(host and sender and recipient),
        channel_enabled=channel_enabled,
        host=host,
        port=port,
        username=_value(session, "smtp_username"),
        password=_decrypt_password(settings, _value(session, "smtp_password")),
        sender=sender,
        recipient=recipient,
        use_starttls=_value(session, "smtp_starttls", "true") == "true",
    )


def _validate(form: SmtpForm) -> SmtpForm:
    host = form.host.strip()
    username = form.username.strip()
    sender = form.sender.strip()
    recipients = [
        address.strip()
        for address in RECIPIENT_SPLITTER.split(form.recipient)
        if address.strip()
    ]
    recipient = ", ".join(recipients)
    if not 1 <= form.port <= 65535:
        raise ValueError("SMTP-порт должен быть от 1 до 65535")
    if len(host) > 255 or len(username) > 255:
        raise ValueError("Сервер или логин SMTP слишком длинный")
    if len(form.password) > 256:
        raise ValueError("SMTP-пароль не должен превышать 256 символов")
    if len(sender) > 255 or len(recipient) > 500:
        raise ValueError("Адрес электронной почты или список получателей слишком длинный")
    if len(recipients) > MAX_RECIPIENTS:
        raise ValueError(f"Можно указать не более {MAX_RECIPIENTS} получателей")
    if sender and ("@" not in sender or any(char.isspace() for char in sender)):
        raise ValueError("Некорректный адрес отправителя")
    for address in recipients:
        if "@" not in address or any(char.isspace() for char in address):
            raise ValueError(f"Некорректный адрес получателя: {address}")
    return SmtpForm(
        host=host,
        port=form.port,
        username=username,
        password=form.password,
        sender=sender,
        recipient=recipient,
        starttls=form.starttls,
        enabled=form.enabled,
        clear_password=form.clear_password,
    )


def update_smtp_settings(
    session: Session,
    settings: Settings,
    form: SmtpForm,
) -> EmailSettings:
    normalized = _validate(form)
    values = {
        "smtp_enabled": "true" if normalized.enabled else "false",
        "smtp_host": normalized.host,
        "smtp_port": str(normalized.port),
        "smtp_username": normalized.username,
        "smtp_sender": normalized.sender,
        "smtp_recipient": normalized.recipient,
        "smtp_starttls": "true" if normalized.starttls else "false",
    }
    for key, value in values.items():
        setting = session.get(AppSetting, key)
        if setting is None:
            raise ValueError(f"Настройка {key} не найдена")
        setting.value = value

    password_setting = session.get(AppSetting, "smtp_password")
    if password_setting is None:
        raise ValueError("Настройка smtp_password не найдена")
    if normalized.clear_password:
        password_setting.value = ""
    elif normalized.password:
        password_setting.value = encrypt_secret(settings, normalized.password)
    session.flush()
    return load_smtp_settings(session, settings)
