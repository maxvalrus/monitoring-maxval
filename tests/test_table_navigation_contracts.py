from pathlib import Path


def test_sorting_and_pagination_refresh_in_place() -> None:
    javascript = Path("src/monitoring/static/app.js").read_text(encoding="utf-8")
    assert "const updateListPage = async (url)" in javascript
    assert '".sort-link, .pagination a.page-button"' in javascript
    assert 'form.matches(".page-size-form")' in javascript
    assert 'window.scrollTo({ top: scrollPosition' in javascript


def test_backup_headers_are_sortable_and_full_backup_is_neutral() -> None:
    settings = Path("src/monitoring/templates/settings.html").read_text(encoding="utf-8")
    routes = Path("src/monitoring/web/routes.py").read_text(encoding="utf-8")
    assert settings.count("sortable_header(request") >= 5
    for column in ("created_at", "backup_type", "creation_mode", "app_version", "size_bytes"):
        assert f"'{column}'" in settings
        assert f'"{column}"' in routes
    assert 'button button-primary" type="submit" aria-label="Создать полный бэкап"' not in settings
    assert 'button" type="submit" aria-label="Создать полный бэкап"' in settings


def test_incident_tablet_layout_and_mobile_target_tools() -> None:
    css = Path("src/monitoring/static/app.css").read_text(encoding="utf-8")
    dashboard = Path("src/monitoring/templates/dashboard.html").read_text(encoding="utf-8")
    assert "@media (max-width: 900px)" in css
    assert ".incident-card .entity-heading { display: grid;" in css
    assert ".incident-card .badge-group { width: 100%; justify-content: flex-start;" in css
    assert 'class="monitoring-object-row monitoring-objects-grid' in dashboard
    assert dashboard.count('class="monitoring-order-button"') == 2
    assert 'class="monitoring-object-menu"' not in dashboard
    assert "@media (max-width: 760px)" in css
    assert "grid-template-columns: repeat(3, minmax(0, 1fr)) 30px" in css
    assert ".monitoring-object-actions { grid-column: 4; grid-row: 1 / 5;" in css
    assert ".monitoring-object-latency { grid-column: 2 / 4; grid-row: 2; }" in css
    assert 'class="monitoring-object-latency-content"' in dashboard
    assert ".monitoring-object-latency-content { min-width: 0; display: flex;" in css
    assert "line-height: 1.15; text-align: center;" in css


def test_navigation_orders_schedules_before_sites() -> None:
    base = Path("src/monitoring/templates/base.html").read_text(encoding="utf-8")
    assert base.index('href="/schedules"') < base.index('href="/sites"')
