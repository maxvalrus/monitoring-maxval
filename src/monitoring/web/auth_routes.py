from typing import Annotated

from fastapi import APIRouter, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from monitoring.config import get_settings
from monitoring.services.audit import write_audit
from monitoring.services.auth import (
    authenticate_user,
    complete_login,
    create_server_session,
    get_active_block,
    record_failed_login,
    resolve_server_session,
    revoke_session,
)
from monitoring.web.dependencies import CurrentAuth, DbSession
from monitoring.web.routes import templates
from monitoring.web.security import (
    client_ip,
    create_login_csrf,
    delete_session_cookie,
    is_https_request,
    login_csrf_cookie_name,
    session_cookie_name,
    session_token,
    set_session_cookie,
    verify_login_csrf,
    verify_session_csrf,
)

router = APIRouter()


def render_login(request: Request, error: str | None = None, status_code: int = 200):
    settings = get_settings()
    csrf = create_login_csrf(settings.secret_key.get_secret_value())
    response = templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"csrf_token": csrf, "error": error, "current_user": None},
        status_code=status_code,
    )
    response.set_cookie(
        login_csrf_cookie_name(request),
        csrf,
        max_age=600,
        httponly=True,
        secure=is_https_request(request) or settings.effective_cookie_secure,
        samesite="lax",
        path="/login",
    )
    return response


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, session: DbSession) -> HTMLResponse:
    settings = get_settings()
    existing = resolve_server_session(
        session,
        session_token(request, settings),
        settings,
    )
    if existing is not None:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return render_login(request)


@router.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    session: DbSession,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
) -> HTMLResponse:
    settings = get_settings()
    ip_address = client_ip(request)
    if not verify_login_csrf(
        csrf_token,
        request.cookies.get(login_csrf_cookie_name(request)),
        settings.secret_key.get_secret_value(),
    ):
        return render_login(request, "Форма устарела. Повторите вход.", 400)

    block = get_active_block(session, username, ip_address)
    if block is not None:
        write_audit(
            session,
            "auth.login_blocked",
            entity_type="username",
            entity_id=username.strip().casefold()[:64],
            entity_name=username.strip()[:64],
            ip_address=ip_address,
        )
        session.commit()
        return render_login(request, "Вход временно заблокирован. Попробуйте позже.", 429)

    user = authenticate_user(session, username, password)
    if user is None:
        new_block = record_failed_login(session, username, ip_address, settings)
        write_audit(
            session,
            "auth.login_failed",
            entity_type="username",
            entity_id=username.strip().casefold()[:64],
            entity_name=username.strip()[:64],
            ip_address=ip_address,
        )
        if new_block is not None:
            write_audit(
                session,
                "auth.block_created",
                entity_type="username",
                entity_id=username.strip().casefold()[:64],
                ip_address=ip_address,
            )
        session.commit()
        return render_login(request, "Неверный логин или пароль.", 401)

    complete_login(session, user, ip_address, username)
    raw_token, _ = create_server_session(
        session,
        user,
        settings,
        ip_address,
        request.headers.get("user-agent", ""),
    )
    session.commit()
    response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    set_session_cookie(
        response,
        raw_token,
        settings,
        secure=is_https_request(request),
        name=session_cookie_name(settings, request),
    )
    response.delete_cookie(login_csrf_cookie_name(request), path="/login")
    return response


@router.post("/logout")
def logout(
    request: Request,
    session: DbSession,
    auth: CurrentAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    if not verify_session_csrf(auth.user_session.csrf_token, csrf_token):
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    settings = get_settings()
    revoke_session(session, session_token(request, settings))
    write_audit(
        session,
        "auth.logout",
        user_id=auth.user.id,
        entity_type="user",
        entity_id=auth.user.id,
        entity_name=auth.user.username,
        ip_address=client_ip(request),
    )
    session.commit()
    response = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    delete_session_cookie(response, settings, name=session_cookie_name(settings, request))
    return response
