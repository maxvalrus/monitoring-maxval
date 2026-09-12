import hashlib
import hmac
import secrets

from fastapi import Request
from fastapi.responses import Response

from monitoring.config import Settings

LOGIN_CSRF_COOKIE = "monitoring_login_csrf"


def client_ip(request: Request) -> str:
    return request.client.host[:45] if request.client else "unknown"


def is_https_request(request: Request) -> bool:
    return request.url.scheme == "https"


def session_cookie_name(settings: Settings, request: Request) -> str:
    """Keep HTTP and HTTPS sessions independent while both listeners are active."""
    suffix = "_https" if is_https_request(request) else ""
    return f"{settings.session_cookie_name}{suffix}"


def session_token(request: Request, settings: Settings) -> str | None:
    token = request.cookies.get(session_cookie_name(settings, request))
    # Existing 0.6.x cookies remain usable over HTTPS once, so Settings can
    # migrate them to the HTTPS-specific name without breaking an active admin.
    if token is None and is_https_request(request):
        token = request.cookies.get(settings.session_cookie_name)
    return token


def login_csrf_cookie_name(request: Request) -> str:
    return f"{LOGIN_CSRF_COOKIE}{'_https' if is_https_request(request) else ''}"


def create_login_csrf(secret_key: str) -> str:
    nonce = secrets.token_urlsafe(24)
    signature = hmac.new(
        secret_key.encode("utf-8"), nonce.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"{nonce}.{signature}"


def verify_login_csrf(token: str, cookie: str | None, secret_key: str) -> bool:
    if not cookie or not hmac.compare_digest(token, cookie):
        return False
    try:
        nonce, signature = token.rsplit(".", 1)
    except ValueError:
        return False
    expected = hmac.new(
        secret_key.encode("utf-8"), nonce.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected)


def verify_session_csrf(expected: str, submitted: str) -> bool:
    return bool(submitted) and hmac.compare_digest(expected, submitted)


def set_session_cookie(
    response: Response,
    raw_token: str,
    settings: Settings,
    *,
    secure: bool | None = None,
    name: str | None = None,
) -> None:
    response.set_cookie(
        name or settings.session_cookie_name,
        raw_token,
        max_age=settings.session_max_hours * 3600,
        httponly=True,
        secure=settings.effective_cookie_secure if secure is None else secure,
        samesite="lax",
        path="/",
    )


def delete_session_cookie(
    response: Response,
    settings: Settings,
    *,
    name: str | None = None,
    secure: bool | None = None,
) -> None:
    response.delete_cookie(
        name or settings.session_cookie_name,
        httponly=True,
        secure=settings.effective_cookie_secure if secure is None else secure,
        samesite="lax",
        path="/",
    )
