from pathlib import Path

from monitoring.services.tls import TlsStatus
from monitoring.services.tls_redirect_guard import should_disable_redirect

ROOT = Path(__file__).resolve().parents[1]


def _status(*, available: bool = True, redirect_safe: bool = True) -> TlsStatus:
    return TlsStatus(
        available=available,
        active_valid=redirect_safe,
        active_expires_at="Nov 21 19:02:21 2026 GMT",
        active_redirect_safe=redirect_safe,
        candidate_valid=False,
        candidate_message=None,
    )


def test_expiring_active_certificate_disables_http_redirect() -> None:
    assert should_disable_redirect(
        https_enabled=True,
        redirect_enabled=True,
        status=_status(redirect_safe=False),
    )


def test_safe_certificate_or_disabled_setting_keeps_redirect() -> None:
    assert not should_disable_redirect(
        https_enabled=True,
        redirect_enabled=True,
        status=_status(redirect_safe=True),
    )
    assert not should_disable_redirect(
        https_enabled=False,
        redirect_enabled=True,
        status=_status(redirect_safe=False),
    )
    assert not should_disable_redirect(
        https_enabled=True,
        redirect_enabled=False,
        status=_status(redirect_safe=False),
    )
    assert not should_disable_redirect(
        https_enabled=True,
        redirect_enabled=True,
        status=_status(available=False, redirect_safe=False),
    )


def test_expiring_certificate_blocks_manual_redirect_and_notifies_admins() -> None:
    template = (ROOT / "src/monitoring/templates/settings.html").read_text(encoding="utf-8")
    routes = (ROOT / "src/monitoring/web/routes.py").read_text(encoding="utf-8")
    guard = (ROOT / "src/monitoring/services/tls_redirect_guard.py").read_text(encoding="utf-8")
    assert "tls_status.active_redirect_safe" in template
    assert "Сертификат истекает в течение двух суток" in template
    assert "status_info.active_redirect_safe" in routes
    assert "tls_certificate_expiring" in guard
    assert "create_notification(" in guard


def test_tls_warning_and_internal_ca_contract() -> None:
    template = (ROOT / "src/monitoring/templates/settings.html").read_text(encoding="utf-8")
    manager = (ROOT / "tls-manager/app.py").read_text(encoding="utf-8")
    assert "Активный сертификат действует до" in template
    assert "/settings/https/warnings" in template
    assert "/settings/https/internal-ca" in template
    assert "internal_ca_certificate" in manager
    assert "CA_PRIVATE_KEY" in manager
