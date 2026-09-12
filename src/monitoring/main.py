import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from monitoring import __version__
from monitoring.checks import checker_registry
from monitoring.config import get_settings
from monitoring.db import SessionLocal, database_is_ready
from monitoring.notifications import EmailNotifier, EmailSettings
from monitoring.services.monitoring import MonitoringService
from monitoring.services.scheduler import CheckScheduler
from monitoring.services.smtp_settings import load_smtp_settings
from monitoring.services.snmp import SnmpService
from monitoring.services.snmp_client import PySnmpClient
from monitoring.services.tls_redirect_guard import TlsRedirectGuard
from monitoring.web.admin_routes import router as admin_router
from monitoring.web.auth_routes import router as auth_router
from monitoring.web.communication_routes import router as communication_router
from monitoring.web.routes import router as web_router
from monitoring.web.snmp_routes import router as snmp_router
from monitoring.web.target_check_routes import router as target_check_router

BASE_DIR = Path(__file__).resolve().parent
settings = get_settings()


def current_email_settings() -> EmailSettings:
    with SessionLocal() as session:
        return load_smtp_settings(session, settings)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings.validate_production()
    network_semaphore = asyncio.Semaphore(settings.max_parallel_checks)
    monitoring = MonitoringService(
        registry=checker_registry,
        timeout_seconds=settings.check_timeout_seconds,
        max_parallel_checks=settings.max_parallel_checks,
        network_semaphore=network_semaphore,
        settings=settings,
    )
    email_notifier = EmailNotifier(current_email_settings)
    scheduler = CheckScheduler(
        monitoring,
        settings.scheduler_poll_seconds,
        notifier=email_notifier,
        snmp_service=SnmpService(SessionLocal, settings, PySnmpClient(), network_semaphore),
    )
    if settings.scheduler_enabled:
        scheduler.start()
    app.state.scheduler = scheduler
    tls_redirect_guard = TlsRedirectGuard(settings)
    tls_redirect_guard.start()
    app.state.tls_redirect_guard = tls_redirect_guard
    yield
    await tls_redirect_guard.stop()
    await scheduler.stop()


app = FastAPI(
    title="Мониторинг Maxval",
    version=__version__,
    docs_url="/api/docs" if not settings.is_production else None,
    redoc_url=None,
    lifespan=lifespan,
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts_list)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.get("/service-worker.js", include_in_schema=False)
def service_worker() -> FileResponse:
    return FileResponse(
        BASE_DIR / "static" / "sw.js",
        media_type="application/javascript",
        headers={"Service-Worker-Allowed": "/"},
    )


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "script-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if not request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health/live", include_in_schema=False)
def health_live() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/health/ready", include_in_schema=False)
def health_ready() -> JSONResponse:
    ready = database_is_ready()
    return JSONResponse(
        status_code=200 if ready else 503,
        content={"status": "ready" if ready else "not_ready", "database": ready},
    )


app.include_router(auth_router)
app.include_router(web_router)
app.include_router(snmp_router)
app.include_router(target_check_router)
app.include_router(communication_router)
app.include_router(admin_router)
