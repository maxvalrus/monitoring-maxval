"""Isolated, deliberately narrow controller for Caddy TLS configuration."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel

TLS_ROOT = Path("/tls")
CA_ROOT = TLS_ROOT / "ca"
CA_CERTIFICATE = CA_ROOT / "root-ca.pem"
CA_PRIVATE_KEY = CA_ROOT / "root-ca-key.pem"
CERTIFICATE = TLS_ROOT / "fullchain.pem"
PRIVATE_KEY = TLS_ROOT / "privkey.pem"
CANDIDATE_CERTIFICATE = TLS_ROOT / "candidate-fullchain.pem"
CANDIDATE_PRIVATE_KEY = TLS_ROOT / "candidate-privkey.pem"
CADDYFILE = Path("/etc/caddy/Caddyfile")
APP_UPSTREAM = os.getenv("MONITORING_APP_UPSTREAM", "app:8000")
CADDY_ADMIN_URL = os.getenv("CADDY_ADMIN_URL", "http://caddy:2019/load")
SECRET = os.environ.get("MONITORING_SECRET_KEY", "")
REDIRECT_SAFETY_WINDOW_SECONDS = 2 * 24 * 60 * 60

app = FastAPI(docs_url=None, redoc_url=None)


def _expected_token() -> str:
    return hmac.new(
        SECRET.encode("utf-8"), b"monitoring-maxval-tls-manager", hashlib.sha256
    ).hexdigest()


def _authorize(token: str | None) -> None:
    if not SECRET or not token or not hmac.compare_digest(token, _expected_token()):
        raise HTTPException(403, "Недостаточно прав для управления HTTPS")


def _run(*command: str) -> str:
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode:
        message = (completed.stderr or completed.stdout or "Проверка TLS завершилась с ошибкой").strip()
        # OpenSSL writes key-generation progress to stderr. Keep the tail so a
        # real diagnostic printed after that progress is not hidden from the UI.
        raise ValueError(message[-500:])
    return completed.stdout


def _certificate_expiry(certificate: Path) -> str:
    _run("openssl", "x509", "-in", str(certificate), "-noout")
    _run("openssl", "x509", "-in", str(certificate), "-noout", "-checkend", "0")
    raw = _run("openssl", "x509", "-in", str(certificate), "-noout", "-enddate").strip()
    return raw.removeprefix("notAfter=")


def _validate_pair(certificate: Path, private_key: Path, *, caddyfile: Path | None = None) -> str:
    if not certificate.is_file() or not private_key.is_file():
        raise ValueError("Не найдены файл сертификата или приватного ключа")
    expiry = _certificate_expiry(certificate)
    _run("openssl", "pkey", "-in", str(private_key), "-noout")
    certificate_public = _run("openssl", "x509", "-in", str(certificate), "-pubkey", "-noout")
    key_public = _run("openssl", "pkey", "-in", str(private_key), "-pubout")
    if certificate_public != key_public:
        raise ValueError("Сертификат не соответствует приватному ключу")
    if caddyfile is not None:
        _run("caddy", "validate", "--config", str(caddyfile), "--adapter", "caddyfile")
    return expiry


def _caddyfile(
    *,
    https_enabled: bool,
    redirect_http: bool,
    certificate: Path = CERTIFICATE,
    private_key: Path = PRIVATE_KEY,
    revision: str | None = None,
) -> str:
    http_route = (
        "redir https://{host}{uri} 307"
        if https_enabled and redirect_http
        else f"reverse_proxy {APP_UPSTREAM}"
    )
    revision_comment = f"# tls-manager revision: {revision}\n" if revision else ""
    sections = [
        "{\n  auto_https off\n  admin 0.0.0.0:2019\n}\n",
        revision_comment,
        f":80 {{\n  {http_route}\n}}\n",
    ]
    if https_enabled:
        sections.append(
            f":443 {{\n  tls {certificate} {private_key}\n  reverse_proxy {APP_UPSTREAM}\n}}\n"
        )
    return "\n".join(sections)


def _write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False, encoding="utf-8") as temp:
        temp.write(data)
        temporary = Path(temp.name)
    os.replace(temporary, path)


def _reload_caddy(caddyfile: Path) -> None:
    config = _run("caddy", "adapt", "--config", str(caddyfile), "--adapter", "caddyfile")
    request = urllib.request.Request(
        CADDY_ADMIN_URL,
        data=config.encode("utf-8"),
        # The certificate paths remain unchanged when a new pair replaces the
        # active files.  Ask Caddy to reprovision TLS even when its adapted
        # JSON configuration is otherwise identical.
        headers={
            "Cache-Control": "must-revalidate",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            if response.status >= 300:
                raise ValueError(f"Caddy reload вернул HTTP {response.status}")
    except (OSError, urllib.error.URLError) as exc:
        raise ValueError(f"Caddy reload не выполнен: {exc}") from exc


def _candidate_config() -> Path:
    path = TLS_ROOT / "candidate.Caddyfile"
    _write(
        path,
        _caddyfile(
            https_enabled=True,
            redirect_http=False,
            certificate=CANDIDATE_CERTIFICATE,
            private_key=CANDIDATE_PRIVATE_KEY,
        ),
    )
    return path


def _active_status() -> tuple[bool, str | None]:
    try:
        return True, _validate_pair(CERTIFICATE, PRIVATE_KEY)
    except ValueError:
        return False, None


def _certificate_valid_for(certificate: Path, seconds: int) -> bool:
    try:
        _run("openssl", "x509", "-in", str(certificate), "-noout", "-checkend", str(seconds))
    except ValueError:
        return False
    return True


class ApplyRequest(BaseModel):
    https_enabled: bool
    redirect_http: bool


class InternalCertificateRequest(BaseModel):
    common_name: str
    dns_names: list[str] = []
    ip_addresses: list[str] = []


def _san_values(request: InternalCertificateRequest) -> list[str]:
    values: list[str] = []
    for name in request.dns_names:
        name = name.strip().casefold()
        if not name or len(name) > 253 or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for char in name):
            raise ValueError("Некорректное DNS-имя для сертификата")
        values.append(f"DNS:{name}")
    for address in request.ip_addresses:
        try:
            values.append(f"IP:{ipaddress.ip_address(address.strip())}")
        except ValueError as exc:
            raise ValueError("Некорректный IP-адрес для сертификата") from exc
    if not values:
        raise ValueError("Укажите хотя бы один DNS или IP SAN")
    return values


def _create_internal_candidate(request: InternalCertificateRequest) -> str:
    common_name = request.common_name.strip()
    if not common_name or len(common_name) > 253 or any(char in common_name for char in "\\n\\r/"):
        raise ValueError("Некорректное общее имя сертификата")
    san_values = _san_values(request)
    CA_ROOT.mkdir(parents=True, exist_ok=True)
    if not CA_CERTIFICATE.exists() or not CA_PRIVATE_KEY.exists():
        _run("openssl", "req", "-x509", "-new", "-nodes", "-newkey", "rsa:3072", "-sha256", "-days", "3650", "-quiet", "-keyout", str(CA_PRIVATE_KEY), "-out", str(CA_CERTIFICATE), "-subj", "/CN=Monitoring Maxval Internal CA")
        os.chmod(CA_PRIVATE_KEY, 0o600)
    config = TLS_ROOT / "internal-ca-openssl.cnf"
    _write(config, "[req]\\ndistinguished_name=req_dn\\nreq_extensions=v3_req\\nprompt=no\\n[req_dn]\\nCN=" + common_name + "\\n[v3_req]\\nsubjectAltName=" + ",".join(san_values) + "\\nkeyUsage=critical,digitalSignature,keyEncipherment\\nextendedKeyUsage=serverAuth\\n")
    try:
        _run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-quiet", "-keyout", str(CANDIDATE_PRIVATE_KEY), "-out", str(TLS_ROOT / "internal-server.csr"), "-config", str(config))
        _run("openssl", "x509", "-req", "-in", str(TLS_ROOT / "internal-server.csr"), "-CA", str(CA_CERTIFICATE), "-CAkey", str(CA_PRIVATE_KEY), "-CAcreateserial", "-out", str(CANDIDATE_CERTIFICATE), "-days", "825", "-sha256", "-extfile", str(config), "-extensions", "v3_req")
        os.chmod(CANDIDATE_PRIVATE_KEY, 0o600)
        return _validate_pair(CANDIDATE_CERTIFICATE, CANDIDATE_PRIVATE_KEY, caddyfile=_candidate_config())
    finally:
        config.unlink(missing_ok=True)
        (TLS_ROOT / "internal-server.csr").unlink(missing_ok=True)


@app.post("/internal-ca")
def internal_ca(request: InternalCertificateRequest, x_tls_manager_token: str | None = Header(default=None)) -> dict[str, object]:
    _authorize(x_tls_manager_token)
    try:
        expiry = _create_internal_candidate(request)
    except (OSError, ValueError) as exc:
        CANDIDATE_CERTIFICATE.unlink(missing_ok=True)
        CANDIDATE_PRIVATE_KEY.unlink(missing_ok=True)
        raise HTTPException(400, f"Внутренний TLS-кандидат не создан: {exc}") from exc
    return {"ok": True, "expires_at": expiry, "message": "Внутренний CA и TLS-кандидат готовы"}


@app.get("/internal-ca/certificate")
def internal_ca_certificate(x_tls_manager_token: str | None = Header(default=None)) -> FileResponse:
    _authorize(x_tls_manager_token)
    if not CA_CERTIFICATE.is_file():
        raise HTTPException(404, "Внутренний CA ещё не создан")
    return FileResponse(CA_CERTIFICATE, media_type="application/x-pem-file", filename="monitoring-maxval-internal-ca.pem")


@app.get("/status")
def status() -> dict[str, object]:
    active_valid, active_expires_at = _active_status()
    try:
        _validate_pair(
            CANDIDATE_CERTIFICATE,
            CANDIDATE_PRIVATE_KEY,
            caddyfile=_candidate_config(),
        )
        candidate_valid, candidate_message = True, "Кандидат проверен и готов к активации"
    except ValueError as exc:
        candidate_valid = False
        candidate_message = str(exc) if CANDIDATE_CERTIFICATE.exists() else None
    return {
        "active_valid": active_valid,
        "active_expires_at": active_expires_at,
        "active_redirect_safe": _certificate_valid_for(
            CERTIFICATE, REDIRECT_SAFETY_WINDOW_SECONDS
        ),
        "candidate_valid": candidate_valid,
        "candidate_message": candidate_message,
    }


@app.post("/candidate")
async def candidate(
    certificate: UploadFile = File(),  # noqa: B008
    private_key: UploadFile = File(),  # noqa: B008
    x_tls_manager_token: str | None = Header(default=None),
) -> dict[str, object]:
    _authorize(x_tls_manager_token)
    TLS_ROOT.mkdir(parents=True, exist_ok=True)
    try:
        for upload, destination in (
            (certificate, CANDIDATE_CERTIFICATE),
            (private_key, CANDIDATE_PRIVATE_KEY),
        ):
            with tempfile.NamedTemporaryFile("wb", dir=TLS_ROOT, delete=False) as temp:
                shutil.copyfileobj(upload.file, temp)
                temporary = Path(temp.name)
            os.chmod(temporary, 0o600)
            os.replace(temporary, destination)
        expiry = _validate_pair(
            CANDIDATE_CERTIFICATE,
            CANDIDATE_PRIVATE_KEY,
            caddyfile=_candidate_config(),
        )
    except (OSError, ValueError) as exc:
        CANDIDATE_CERTIFICATE.unlink(missing_ok=True)
        CANDIDATE_PRIVATE_KEY.unlink(missing_ok=True)
        raise HTTPException(400, f"TLS-кандидат не прошёл проверку: {exc}") from exc
    finally:
        await certificate.close()
        await private_key.close()
    return {"ok": True, "expires_at": expiry, "message": "TLS-кандидат проверен"}


@app.post("/apply")
def apply(
    payload: ApplyRequest,
    x_tls_manager_token: str | None = Header(default=None),
) -> dict[str, object]:
    _authorize(x_tls_manager_token)
    if payload.redirect_http and not payload.https_enabled:
        raise HTTPException(400, "Перенаправление HTTP доступно только при включённом HTTPS")
    previous_config = CADDYFILE.read_text(encoding="utf-8") if CADDYFILE.exists() else ""
    backup = TLS_ROOT / "rollback"
    had_active_pair = CERTIFICATE.exists() and PRIVATE_KEY.exists()
    if payload.https_enabled:
        try:
            _validate_pair(
                CANDIDATE_CERTIFICATE,
                CANDIDATE_PRIVATE_KEY,
                caddyfile=_candidate_config(),
            )
        except ValueError as exc:
            raise HTTPException(400, f"Нельзя включить HTTPS: {exc}") from exc
        # Preserve the last known working pair before atomically promoting the candidate.
        if had_active_pair:
            backup.mkdir(exist_ok=True)
            shutil.copy2(CERTIFICATE, backup / "fullchain.pem")
            shutil.copy2(PRIVATE_KEY, backup / "privkey.pem")
        shutil.copy2(CANDIDATE_CERTIFICATE, CERTIFICATE)
        shutil.copy2(CANDIDATE_PRIVATE_KEY, PRIVATE_KEY)
        os.chmod(PRIVATE_KEY, 0o600)
    config = _caddyfile(
        https_enabled=payload.https_enabled,
        redirect_http=payload.redirect_http,
        revision=datetime.now(UTC).isoformat(),
    )
    candidate_config = TLS_ROOT / "active.Caddyfile"
    _write(candidate_config, config)
    try:
        if payload.https_enabled:
            _validate_pair(CERTIFICATE, PRIVATE_KEY, caddyfile=candidate_config)
        else:
            _run("caddy", "validate", "--config", str(candidate_config), "--adapter", "caddyfile")
        # /tls and /etc/caddy are separate mounts. _write() creates its temporary
        # file beside CADDYFILE, so replacement remains atomic without EXDEV.
        _write(CADDYFILE, config)
        _reload_caddy(CADDYFILE)
    except (OSError, ValueError) as exc:
        if payload.https_enabled and had_active_pair:
            shutil.copy2(backup / "fullchain.pem", CERTIFICATE)
            shutil.copy2(backup / "privkey.pem", PRIVATE_KEY)
            os.chmod(PRIVATE_KEY, 0o600)
        if previous_config:
            _write(CADDYFILE, previous_config)
            with suppress(ValueError):
                _reload_caddy(CADDYFILE)
        candidate_config.unlink(missing_ok=True)
        raise HTTPException(400, f"Конфигурация Caddy не применена: {exc}") from exc
    return {
        "ok": True,
        "https_enabled": payload.https_enabled,
        "redirect_http": payload.redirect_http,
    }


@app.post("/disable-redirect")
def disable_redirect(x_tls_manager_token: str | None = Header(default=None)) -> dict[str, object]:
    """Fail open to direct HTTP when the active certificate is no longer safe."""
    _authorize(x_tls_manager_token)
    previous_config = CADDYFILE.read_text(encoding="utf-8") if CADDYFILE.exists() else ""
    config = _caddyfile(
        https_enabled=True,
        redirect_http=False,
        revision=datetime.now(UTC).isoformat(),
    )
    candidate_config = TLS_ROOT / "disable-redirect.Caddyfile"
    _write(candidate_config, config)
    try:
        _run("caddy", "validate", "--config", str(candidate_config), "--adapter", "caddyfile")
        _write(CADDYFILE, config)
        _reload_caddy(CADDYFILE)
    except (OSError, ValueError) as exc:
        if previous_config:
            _write(CADDYFILE, previous_config)
            with suppress(ValueError):
                _reload_caddy(CADDYFILE)
        raise HTTPException(400, f"Не удалось отключить перенаправление HTTP: {exc}") from exc
    return {"ok": True, "redirect_http": False}


@app.post("/rollback")
def rollback(x_tls_manager_token: str | None = Header(default=None)) -> dict[str, object]:
    _authorize(x_tls_manager_token)
    backup = TLS_ROOT / "rollback"
    backup_cert, backup_key = backup / "fullchain.pem", backup / "privkey.pem"
    try:
        _validate_pair(backup_cert, backup_key)
        shutil.copy2(backup_cert, CERTIFICATE)
        shutil.copy2(backup_key, PRIVATE_KEY)
        os.chmod(PRIVATE_KEY, 0o600)
        candidate_config = TLS_ROOT / "rollback.Caddyfile"
        config = _caddyfile(
            https_enabled=True,
            redirect_http=False,
            revision=datetime.now(UTC).isoformat(),
        )
        _write(candidate_config, config)
        _validate_pair(CERTIFICATE, PRIVATE_KEY, caddyfile=candidate_config)
        _write(CADDYFILE, config)
        _reload_caddy(CADDYFILE)
    except (OSError, ValueError) as exc:
        raise HTTPException(400, f"Откат TLS не выполнен: {exc}") from exc
    return {"ok": True, "message": "Восстановлена последняя рабочая TLS-конфигурация"}
