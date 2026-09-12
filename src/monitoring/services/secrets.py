import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from monitoring.config import Settings


def _cipher(settings: Settings) -> Fernet:
    digest = hashlib.sha256(settings.secret_key.get_secret_value().encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(settings: Settings, value: str) -> str:
    """Encrypt an application secret with the installation key."""
    return _cipher(settings).encrypt(value.encode()).decode() if value else ""


def decrypt_secret(settings: Settings, token: str, *, label: str) -> str:
    if not token:
        return ""
    try:
        return _cipher(settings).decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError(
            f"{label} не расшифрован: MONITORING_SECRET_KEY был изменён"
        ) from exc
