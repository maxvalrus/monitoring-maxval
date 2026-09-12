"""Regression: authenticated bursts must not pin all connections before handlers run."""

import asyncio
from collections.abc import Generator
from pathlib import Path

import anyio
import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session, sessionmaker
from starlette.requests import Request
from starlette.staticfiles import StaticFiles

from monitoring.config import Settings
from monitoring.db import Base, get_db
from monitoring.models import MonitorTarget, Site, User, UserRole
from monitoring.services.auth import create_server_session, create_user
from monitoring.web import dependencies
from monitoring.web.dependencies import CurrentAuth
from monitoring.web.security import session_cookie_name


def auth_database(tmp_path, monkeypatch):
    settings = Settings(_env_file=None, environment="development")
    monkeypatch.setattr(dependencies, "get_settings", lambda: settings)
    engine = create_engine(
        f"sqlite:///{tmp_path / 'concurrency.db'}",
        connect_args={"check_same_thread": False},
        pool_size=2,
        max_overflow=0,
        # Production waits for a transient read burst; a 0.25-second artificial
        # timeout turns normal SQLite scheduling into an unrelated 500. The global
        # 15-second deadline below still detects the auth/handler pool deadlock.
        pool_timeout=2,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as session:
        user = create_user(session, "operator", "synthetic test password", UserRole.ADMIN)
        session.add(MonitorTarget(site=Site(name="Test site"), name="Test target", address="192.0.2.1", port=80, layout_x=5000, layout_y=5000))
        token, _ = create_server_session(session, user, settings, "127.0.0.1", "test")
        session.commit()
    request = Request({"type": "http", "scheme": "https", "path": "/protected", "headers": []})
    cookie = f"{session_cookie_name(settings, request)}={token}"
    return engine, factory, cookie


def test_auth_releases_connection_and_keeps_attached_models(tmp_path, monkeypatch):
    engine, factory, cookie = auth_database(tmp_path, monkeypatch)
    try:
        request = Request({"type": "http", "scheme": "https", "path": "/protected", "headers": [(b"cookie", cookie.encode())]})
        with factory() as session:
            auth = dependencies.require_user(request, session)
            assert not session.in_transaction()
            assert engine.pool.checkedout() == 0
            assert inspect(auth.user).persistent
            assert inspect(auth.user_session).persistent
            # Existing notification preferences mutate the attached auth.user.
            auth.user.push_chat_enabled = False
            session.commit()
            user_id = auth.user.id
        with factory() as session:
            assert session.get(User, user_id).push_chat_enabled is False
    finally:
        engine.dispose()


@pytest.mark.parametrize("page_kind", ["small", "wallboard"])
def test_authenticated_burst_exceeding_thread_and_connection_pool(tmp_path, monkeypatch, page_kind):
    engine, factory, cookie = auth_database(tmp_path, monkeypatch)
    application = FastAPI()

    def database() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    application.dependency_overrides[get_db] = database

    @application.get("/protected")
    def protected(auth: CurrentAuth):
        return {"role": auth.user.role}

    if page_kind == "wallboard":
        from monitoring.web.routes import wallboard

        application.mount("/static", StaticFiles(directory=Path("src/monitoring/static")), name="static")
        application.add_api_route("/wallboard", wallboard, methods=["GET"])
    path = "/wallboard" if page_kind == "wallboard" else "/protected"

    async def run_burst():
        limiter = anyio.to_thread.current_default_thread_limiter()
        original = limiter.total_tokens
        limiter.total_tokens = 4
        try:
            transport = httpx.ASGITransport(app=application, raise_app_exceptions=True)
            async with httpx.AsyncClient(transport=transport, base_url="https://localhost", headers={"cookie": cookie}) as client:
                responses = await asyncio.wait_for(
                    asyncio.gather(*(client.get(path) for _ in range(24))), 15
                )
                failed = [
                    (response.status_code, response.text[:500])
                    for response in responses
                    if response.status_code != 200
                ]
                assert not failed, failed
                assert engine.pool.checkedout() == 0
        finally:
            limiter.total_tokens = original

    try:
        asyncio.run(run_burst())
    finally:
        engine.dispose()
