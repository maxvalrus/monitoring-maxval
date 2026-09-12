import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from monitoring.config import Settings

ROOT = Path(__file__).resolve().parents[1]


def _tls_manager_module():
    spec = importlib.util.spec_from_file_location(
        "tls_manager_app", ROOT / "tls-manager" / "app.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_http_is_default_and_https_settings_are_explicit() -> None:
    settings = Settings(_env_file=None)
    assert settings.http_public_port == 8000
    migration = (ROOT / "alembic/versions/0036_baseline_0_8_5.py").read_text(encoding="utf-8")
    assert '("https_enabled", "false"' in migration
    assert '("https_redirect_http", "false"' in migration


def test_caddy_keeps_http_separate_from_temporary_redirect() -> None:
    manager = _tls_manager_module()
    http_only = manager._caddyfile(https_enabled=False, redirect_http=False)
    https_without_redirect = manager._caddyfile(https_enabled=True, redirect_http=False)
    redirected = manager._caddyfile(https_enabled=True, redirect_http=True)
    assert ":80" in http_only and ":443" not in http_only
    assert "reverse_proxy app:8000" in https_without_redirect
    assert ":443" in https_without_redirect
    assert "redir https://{host}{uri} 307" in redirected
    assert "strict_transport_security" not in redirected.casefold()
    assert "admin 0.0.0.0:2019" in redirected
    assert "# tls-manager revision: qa" in manager._caddyfile(
        https_enabled=True, redirect_http=False, revision="qa"
    )
    source = (ROOT / "tls-manager/app.py").read_text(encoding="utf-8")
    assert "os.replace(candidate_config, CADDYFILE)" not in source
    assert "_write(CADDYFILE, config)" in source
    assert "_reload_caddy(CADDYFILE)" in source


def test_forces_caddy_to_reload_replaced_tls_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _tls_manager_module()
    requests = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(manager, "_run", lambda *_args: "{}")
    monkeypatch.setattr(
        manager.urllib.request,
        "urlopen",
        lambda request, timeout: requests.append((request, timeout)) or Response(),
    )

    manager._reload_caddy(Path("/tmp/Caddyfile"))

    request, timeout = requests[0]
    assert timeout == 5
    assert request.get_header("Cache-control") == "must-revalidate"


def test_tls_manager_reports_the_actual_tail_of_openssl_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _tls_manager_module()
    progress = "+" * 700
    monkeypatch.setattr(
        manager.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1,
            stderr=f"{progress}\nunable to load certificate\n",
            stdout="",
        ),
    )

    with pytest.raises(ValueError, match="unable to load certificate"):
        manager._run("openssl", "req")

    source = (ROOT / "tls-manager/app.py").read_text(encoding="utf-8")
    assert '"rsa:3072", "-sha256", "-days", "3650", "-quiet"' in source
    assert '"rsa:2048", "-nodes", "-quiet", "-keyout"' in source
    assert '"[req]\\ndistinguished_name=req_dn' in source
    assert '"[req]\\\\ndistinguished_name=req_dn' not in source


def test_pwa_manifest_and_cache_are_static_only() -> None:
    manifest = json.loads((ROOT / "src/monitoring/static/manifest.webmanifest").read_text())
    icons = {item["src"] for item in manifest["icons"]}
    assert manifest["name"] == "Мониторинг Maxval"
    assert manifest["display"] == "standalone"
    assert {"/static/icon-192.png", "/static/icon-512.png"}.issubset(icons)
    assert (ROOT / "src/monitoring/static/icon-192.png").read_bytes().startswith(b"\x89PNG")
    assert (ROOT / "src/monitoring/static/icon-512.png").read_bytes().startswith(b"\x89PNG")
    worker = (ROOT / "src/monitoring/static/sw.js").read_text(encoding="utf-8")
    assert 'event.request.mode === "navigate"' in worker
    assert '"/static/offline.html"' in worker
    assert "incidents" not in worker and "api/" not in worker
    offline = (ROOT / "src/monitoring/static/offline.html").read_text(encoding="utf-8")
    assert 'src="/static/offline-theme.js"' in offline
    assert 'data-theme="auto"' in offline
    offline_theme = (ROOT / "src/monitoring/static/offline-theme.js").read_text(encoding="utf-8")
    assert 'localStorage.getItem("monitoring-theme")' in offline_theme


def test_https_switch_uses_background_update() -> None:
    settings_template = (ROOT / "src/monitoring/templates/settings.html").read_text(
        encoding="utf-8"
    )
    form = 'action="/settings/https" class="stack-form tls-controls-form"'
    assert form in settings_template
    assert f"{form} data-no-async" not in settings_template
    assert "tls-candidate-status" in settings_template
    assert "Что означает статус TLS-кандидата" in settings_template


def test_keeps_parallel_http_and_https_sessions_separate() -> None:
    security = (ROOT / "src/monitoring/web/security.py").read_text(encoding="utf-8")
    assert 'return f"{settings.session_cookie_name}{suffix}"' in security
    expected = "return f\"{LOGIN_CSRF_COOKIE}{'_https' if is_https_request(request) else ''}\""
    assert expected in security
