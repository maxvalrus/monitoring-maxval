from pathlib import Path
from types import SimpleNamespace

from monitoring.services.audit import format_audit_entry_text
from monitoring.services.settings import validate_setting


def test_configuration_and_templates() -> None:
    assert validate_setting("min_password_length", "3") == "3"
    migration = Path("alembic/versions/0036_baseline_0_8_5.py").read_text(encoding="utf-8")
    assert '"username": "admin"' in migration
    assert '"must_change_default_password": True' in migration
    assert "admin" in migration
    users = Path("src/monitoring/templates/users.html").read_text(encoding="utf-8")
    assert "/delete" in users
    assert "min_password_length" in users
    base = Path("src/monitoring/templates/base.html").read_text(encoding="utf-8")
    javascript = Path("src/monitoring/static/app.js").read_text(encoding="utf-8")
    assert "must_change_default_password" in base
    assert "data-default-password-warning" in base
    assert "Используется стандартный пароль admin" in javascript


def test_ids_and_audit_popup_are_present() -> None:
    for filename in ("sites.html", "targets.html", "users.html"):
        text = Path("src/monitoring/templates", filename).read_text(encoding="utf-8")
        assert "entity-id" in text
    assert "ID инцидента" in Path("src/monitoring/templates/incidents.html").read_text(
        encoding="utf-8"
    )
    audit = Path("src/monitoring/templates/audit.html").read_text(encoding="utf-8")
    assert "data-audit-details" in audit
    js = Path("src/monitoring/static/app.js").read_text(encoding="utf-8")
    assert "dataset.auditDetails" in js


def test_audit_formatter_decodes_changes() -> None:
    entry = SimpleNamespace(
        action="site.updated",
        entity_type="site",
        entity_id="12",
        ip_address="192.0.2.10",
        created_at=None,
        details='{"schedule": {"old": {"id": 1, "name": "Круглосуточно"}, "new": {"id": 2, "name": "Магазин"}}}',
    )
    text = format_audit_entry_text(entry, "admin", lambda _: "17.08.2026 19:00")
    assert "Обновление площадки" in text
    assert "Круглосуточно (ID 1) → Магазин (ID 2)" in text
    assert "ID 12" in text


def test_pdf_is_portrait_and_minimal_margins() -> None:
    source = Path("src/monitoring/services/exports.py").read_text(encoding="utf-8")
    assert "pagesize=A4" in source
    assert "landscape(A4)" not in source
    assert "leftMargin=5 * mm" in source
    assert "rightMargin=5 * mm" in source
    css = Path("src/monitoring/static/app.css").read_text(encoding="utf-8")
    assert ".export-bar { justify-content: flex-end; }" in css
    assert "input[data-timezone-input]" in css
