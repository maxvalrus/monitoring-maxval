from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from monitoring.config import get_settings
from monitoring.db import get_db
from monitoring.models import UserRole
from monitoring.services.auth import AuthContext, resolve_server_session
from monitoring.web.security import session_token

DbSession = Annotated[Session, Depends(get_db)]


def require_user(request: Request, session: DbSession) -> AuthContext:
    settings = get_settings()
    auth = resolve_server_session(
        session,
        session_token(request, settings),
        settings,
    )
    if auth is None:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login"},
        )
    # Authentication is a separate read/last_seen unit of work. Release its
    # connection before FastAPI queues the handler on the shared thread pool:
    # otherwise concurrent auth dependencies can pin every DB connection while
    # pool waiters consume all workers needed to run those handlers.
    # SessionLocal uses expire_on_commit=False: auth models stay loaded and
    # attached, so later preference edits still commit in the handler's unit.
    session.commit()
    return auth


CurrentAuth = Annotated[AuthContext, Depends(require_user)]


def require_admin(auth: CurrentAuth) -> AuthContext:
    if auth.user.role != UserRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Недостаточно прав")
    return auth


AdminAuth = Annotated[AuthContext, Depends(require_admin)]


def template_context(request: Request, auth: AuthContext, **values: Any) -> dict[str, Any]:
    return {
        "request": request,
        "current_user": auth.user,
        "csrf_token": auth.user_session.csrf_token,
        **values,
    }
