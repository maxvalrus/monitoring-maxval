from pathlib import Path


def test_backup_design_uses_project_rows() -> None:
    settings = Path("src/monitoring/templates/settings.html").read_text(encoding="utf-8")
    assert settings.count("{% block title %}") == 1
    assert "backup-settings-panel" in settings
    assert settings.count("Бэкап конфигурации") >= 1
    assert "backup-setting-row" in settings
    assert "backup-security-note" in settings
    assert "backup-upload-form" in settings
    assert "Целостность базы данных" in settings


def test_incident_responsive_contract() -> None:
    template = Path("src/monitoring/templates/incidents.html").read_text(encoding="utf-8")
    css = Path("src/monitoring/static/app.css").read_text(encoding="utf-8")
    assert template.count("ID инцидента:") == 1
    # The ID is outside the heading copy so desktop can place it at the bottom.
    assert '<small class="entity-id incident-id">ID инцидента:' in template
    assert ".incident-id { display: block; margin-top: 10px; text-align: right; }" in css
    assert "position: absolute;" in css
    assert ".incident-card .badge-group { justify-content: flex-start;" in css
    assert ".incident-last-error { grid-column: 1 / -1; }" in css


def test_ios_time_input_has_strong_containment() -> None:
    css = Path("src/monitoring/static/app.css").read_text(encoding="utf-8")
    assert "@supports (-webkit-touch-callout: none)" in css
    assert "width: -webkit-fill-available;" in css
    assert 'input[type="time"]::-webkit-date-and-time-value' in css
    assert "min-inline-size: 0 !important;" in css


def test_existing_polish_contracts_remain() -> None:
    users = Path("src/monitoring/templates/users.html").read_text(encoding="utf-8")
    audit = Path("src/monitoring/templates/audit.html").read_text(encoding="utf-8")
    tools = Path("src/monitoring/templates/_target_tools.html").read_text(encoding="utf-8")
    seed = Path("scripts/seed_demo.py").read_text(encoding="utf-8")
    app_js = Path("src/monitoring/static/app.js").read_text(encoding="utf-8")
    assert "user-delete-slot" in users
    assert "Это действие нельзя отменить" in users
    assert "table_details" in audit
    assert "data-audit-details" in audit
    assert 'title="Проверить доступность сейчас"' in tools
    assert seed.count("comment=") >= 2
    assert "toast-warning-password" in app_js
