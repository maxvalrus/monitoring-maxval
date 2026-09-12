import importlib.util
import zipfile
from pathlib import Path

from monitoring import __version__

ROOT = Path(__file__).resolve().parents[1]


def _release_builder():
    path = ROOT / "scripts/build_release.py"
    spec = importlib.util.spec_from_file_location("release_builder", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_version_and_pwa_cache_contract() -> None:
    assert __version__ == "0.8.5"
    worker = (ROOT / "src/monitoring/static/sw.js").read_text(encoding="utf-8")
    offline = (ROOT / "src/monitoring/static/offline.html").read_text(encoding="utf-8")
    assert 'CACHE_NAME = "monitoring-maxval-0.8.5' in worker
    assert '"/static/app.css?v=0.8.5&r=' in worker
    assert '"/static/app.js?v=0.8.5&r=' in worker
    assert "/static/app.css?v=0.8.5" in offline


def test_current_version_and_anchor_are_documented() -> None:
    baseline = (ROOT / "docs/BASELINE.md").read_text(encoding="utf-8")
    project = (ROOT / "PROJECT.md").read_text(encoding="utf-8")
    assert "# Опорный релиз 0.8.5" in baseline
    assert "якор" in baseline.lower() or "опор" in baseline.lower()
    assert "Текущая рабочая версия: `0.8.5`" in project
    assert "Опорный (якорный) релиз: `0.8.5`" in project


def test_viewer_https_status_uses_only_the_header_badge() -> None:
    template = (ROOT / "src/monitoring/templates/settings.html").read_text(encoding="utf-8")
    assert "badge {{ 'badge-success' if https_enabled else 'badge-warning' }}" in template
    assert "HTTPS: {{ 'включён' if https_enabled else 'выключен' }}." not in template


def test_ca_installation_help_is_inside_download_action() -> None:
    template = (ROOT / "src/monitoring/templates/settings.html").read_text(encoding="utf-8")
    css = (ROOT / "src/monitoring/static/app.css").read_text(encoding="utf-8")
    assert '<span class="ca-download-action">' in template
    assert 'class="help-trigger ca-download-help"' in template
    assert ".ca-download-action .ca-download-help" in css


def test_site_order_and_backup_download_alignment() -> None:
    template = (ROOT / "src/monitoring/templates/sites.html").read_text(encoding="utf-8")
    css = (ROOT / "src/monitoring/static/app.css").read_text(encoding="utf-8")
    routes = (ROOT / "src/monitoring/web/routes.py").read_text(encoding="utf-8")
    admin_routes = (ROOT / "src/monitoring/web/admin_routes.py").read_text(encoding="utf-8")
    assert 'action="/sites/{{ site.id }}/move"' in template
    assert 'class="site-order-controls"' in template
    assert ".site-order-controls" in css
    assert ".backup-table .backup-actions > a.button" in css
    assert "place-items: center" in css
    assert "select(Site).order_by(Site.display_order, Site.id)" in routes
    assert "select(Site).order_by(Site.display_order, Site.id)" in admin_routes


def test_dependencies_are_locked_to_verified_versions() -> None:
    lock = (ROOT / "requirements.lock").read_text(encoding="utf-8")
    tls_lock = (ROOT / "tls-manager/requirements.lock").read_text(encoding="utf-8")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
    assert "fastapi==0.141.1" in lock
    assert "sqlalchemy==2.0.52" in lock.casefold()
    assert "fastapi==0.115.14" in tls_lock
    assert "FROM python:3.12.14-slim" in dockerfile
    assert "pip install --no-cache-dir -r requirements.lock" in dockerfile
    assert "pip install --no-cache-dir --no-deps ." in dockerfile
    assert "caddy:2.8.4-alpine" in compose
    assert "postgres:17.11-alpine" in compose


def test_archive_contains_only_current_instruction(tmp_path: Path) -> None:
    builder = _release_builder()
    prefix = "monitoring-maxval-0.8.5"
    staging = tmp_path / prefix
    staging.mkdir()
    builder.copy_release_tree(staging, "0.8.5")

    instructions = sorted(path.name for path in staging.glob("INSTRUCTION_*.txt"))
    assert instructions == ["INSTRUCTION_0.8.5.txt"]
    release_notes = sorted(path.name for path in (staging / "docs" / "releases").glob("*.md"))
    assert release_notes == ["0.8.5.md"]
    assert (staging / "requirements.lock").is_file()
    assert (staging / "tls-manager/requirements.lock").is_file()
    assert (staging / ".env").stat().st_mode & 0o777 == 0o600
    assert not (staging / "patchfromchat").exists()

    environment = dict(
        line.split("=", 1)
        for line in (staging / ".env").read_text(encoding="utf-8").splitlines()
        if line
    )
    assert environment["POSTGRES_PASSWORD"] in environment["MONITORING_DATABASE_URL"]
    assert environment["MONITORING_SECRET_KEY"] != "change-me-before-production"

    archive = tmp_path / f"{prefix}.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as package:
        for path in sorted(staging.rglob("*")):
            if path.is_file():
                package.write(path, path.relative_to(staging.parent))
    builder.validate_archive(archive, prefix, "0.8.5")
    with zipfile.ZipFile(archive) as package:
        assert not any("/patchfromchat/" in name for name in package.namelist())
        assert "monitoring-maxval-0.8.5/docs/releases/0.8.5.md" in package.namelist()
