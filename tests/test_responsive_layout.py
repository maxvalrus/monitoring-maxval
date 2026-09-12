import re
from pathlib import Path

import pytest

CSS_PATH = Path(__file__).resolve().parents[1] / "src/monitoring/static/app.css"
TEMPLATES_PATH = Path(__file__).resolve().parents[1] / "src/monitoring/templates"


@pytest.mark.parametrize("viewport_width", [1440, 1024, 760, 390])
def test_target_edit_grid_fits_inside_container(viewport_width: int) -> None:
    container_width = min(1180, viewport_width * (0.94 if viewport_width <= 760 else 0.92))
    form_columns = 1 if viewport_width <= 760 else 2 if viewport_width <= 1050 else 4
    fields_width = container_width - (13 * (form_columns - 1))

    assert fields_width / form_columns > 0
    assert fields_width + (13 * (form_columns - 1)) <= container_width


def test_target_editor_uses_same_grid_as_target_creation() -> None:
    css = re.sub(r"\s+", " ", CSS_PATH.read_text(encoding="utf-8"))
    targets = (TEMPLATES_PATH / "targets.html").read_text(encoding="utf-8")

    assert 'class="form-grid target-form create-form"' in targets
    assert 'class="form-grid compact-form target-form target-edit-form"' in targets
    assert ".form-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));" in css
    assert "@media (max-width: 760px)" in css
    assert ".form-grid { grid-template-columns: 1fr; }" in css


def test_target_options_share_a_footer_and_submit_stays_at_the_edge() -> None:
    css = re.sub(r"\s+", " ", CSS_PATH.read_text(encoding="utf-8"))
    targets = (TEMPLATES_PATH / "targets.html").read_text(encoding="utf-8")

    assert targets.count('class="target-form-footer"') == 2
    assert targets.count('class="target-form-options"') == 2
    assert targets.count('class="form-actions"') == 2
    assert targets.count('class="button button-primary target-form-submit"') == 1
    assert targets.count('class="button target-form-submit"') == 1
    assert ".target-form-footer { grid-column: 1 / -1; display: flex;" in css
    assert ".target-form-submit { width: min(220px, 100%); }" in css
    assert ".target-form-options { align-items: flex-start; flex-direction: column;" in css
    assert ".target-form-submit { width: 100%; }" in css


def test_filter_and_create_form_actions_are_right_aligned_as_groups() -> None:
    css = re.sub(r"\s+", " ", CSS_PATH.read_text(encoding="utf-8"))
    dashboard = (TEMPLATES_PATH / "dashboard.html").read_text(encoding="utf-8")
    targets = (TEMPLATES_PATH / "targets.html").read_text(encoding="utf-8")
    audit = (TEMPLATES_PATH / "audit.html").read_text(encoding="utf-8")
    sites = (TEMPLATES_PATH / "sites.html").read_text(encoding="utf-8")
    users = (TEMPLATES_PATH / "users.html").read_text(encoding="utf-8")

    assert sum(item.count('class="filter-actions"') for item in (dashboard, targets, audit)) == 3
    assert 'class="inline-form create-form"' in sites
    assert 'class="inline-form create-form"' in users
    assert 'class="form-grid target-form create-form"' in targets
    assert sites.count('class="form-actions"') == 1
    assert users.count('class="form-actions"') == 1
    assert ".form-actions, .filter-actions { margin-left: auto; display: flex;" in css
    assert ".filter-actions { flex: 0 0 auto; align-self: flex-end; }" in css
    assert ".form-actions, .filter-actions { width: 100%; margin-left: 0;" in css


def test_smtp_grid_uses_shrinkable_columns_and_mobile_fallback() -> None:
    css = re.sub(r"\s+", " ", CSS_PATH.read_text(encoding="utf-8"))
    assert ".smtp-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr));" in css
    assert ".smtp-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }" in css
    assert ".smtp-grid { grid-template-columns: 1fr; }" in css


def test_filters_pagination_and_transfer_stack_on_mobile() -> None:
    css = re.sub(r"\s+", " ", CSS_PATH.read_text(encoding="utf-8"))
    assert ".filter-bar { align-items: stretch; flex-direction: column; }" in css
    assert ".filter-bar .grow { flex: 0 0 auto; min-height: 0; }" in css
    assert ".list-toolbar { align-items: stretch; flex-direction: column; }" in css
    assert ".pagination { justify-content: center; }" in css
    assert (
        ".transfer-panel, .transfer-actions, .import-form { align-items: stretch; "
        "flex-direction: column; }" in css
    )


def test_incident_filters_use_mobile_segments_and_type_select() -> None:
    css = re.sub(r"\s+", " ", CSS_PATH.read_text(encoding="utf-8"))
    incidents = (TEMPLATES_PATH / "incidents.html").read_text(encoding="utf-8")
    javascript = (
        Path(__file__).resolve().parents[1] / "src/monitoring/static/app.js"
    ).read_text(encoding="utf-8")

    assert 'class="incident-status-segments"' in incidents
    assert incidents.count('class="mobile-filter-segment') == 3
    assert 'id="incident-kind-mobile"' in incidents
    assert "Все типы" in incidents and "Показаны:" in incidents
    assert "Действия с журналом" not in incidents
    assert 'action="/incidents/delete-resolved"' in incidents
    assert 'action="/incidents/delete-all"' in incidents
    assert ".incident-mobile-filters { display: none; }" in css
    assert ".incident-desktop-filters { display: none; }" in css
    assert ".incident-mobile-filters { display: grid; gap: 15px; }" in css
    assert 'select[data-auto-submit]' in javascript
    assert "requestSubmit()" in javascript


@pytest.mark.parametrize("viewport_width", [320, 375, 390])
def test_mobile_backup_upload_cannot_widen_settings_page(viewport_width: int) -> None:
    css = re.sub(r"\s+", " ", CSS_PATH.read_text(encoding="utf-8"))
    settings = (TEMPLATES_PATH / "settings.html").read_text(encoding="utf-8")
    panel_width = viewport_width * 0.94

    assert panel_width <= viewport_width
    assert 'backup-upload-grid' in settings
    assert 'type="file" name="upload"' in settings
    assert ".backup-upload-grid { grid-template-columns: 1fr; }" in css
    assert 'input[type="file"] { min-width: 0; width: 100%; max-width: 100%;' in css


@pytest.mark.parametrize("viewport_width", [320, 375, 390, 430, 760])
def test_tls_expiry_warning_stacks_without_overflow_on_mobile(
    viewport_width: int,
) -> None:
    css = re.sub(r"\s+", " ", CSS_PATH.read_text(encoding="utf-8"))
    settings = (TEMPLATES_PATH / "settings.html").read_text(encoding="utf-8")
    panel_width = viewport_width * 0.94

    assert panel_width <= viewport_width
    assert 'class="tls-warning-form"' in settings
    assert 'class="tls-warning-days"' in settings
    assert ".tls-warning-form { grid-template-columns: 1fr; align-items: stretch; }" in css
    assert ".tls-warning-days { width: max-content; }" in css
    assert ".tls-warning-days input { width: 76px;" in css


def test_sites_and_targets_are_tables_and_target_tools_have_required_order() -> None:
    sites = (TEMPLATES_PATH / "sites.html").read_text(encoding="utf-8")
    targets = (TEMPLATES_PATH / "targets.html").read_text(encoding="utf-8")
    users = (TEMPLATES_PATH / "users.html").read_text(encoding="utf-8")

    assert 'class="entity-table sites-table responsive-table ' in sites
    assert 'class="entity-table targets-table responsive-table ' in targets
    assert 'targets-table-with-actions' in targets and 'targets-table-without-actions' in targets
    assert 'class="entity-table users-table responsive-table"' in users
    css = CSS_PATH.read_text(encoding="utf-8")
    assert ".targets-table-with-actions th:nth-child(3) { width: 11%; }" in css
    assert '.targets-table td[data-label="Тип"] { white-space: nowrap; }' in css
    settings = (TEMPLATES_PATH / "settings.html").read_text(encoding="utf-8")
    assert "Экспорт и импорт" not in targets
    assert "Резервное копирование" in settings
    assert "/settings/backups/create" in settings
    assert 'class="inline-form compact-form site-edit-form"' in sites
    assert 'class="edit-row"' in sites and 'class="edit-row"' in targets
    assert 'data-table-editor-toggle="site-{{ site.id }}-editor"' in sites
    assert 'data-site-edit-row' in sites
    assert "site-delete-targets-action" in sites
    assert "site-delete-site-action" in sites
    assert 'class="setting-toggle-control user-active-control"' in users
    assert 'class="inline-form compact-form user-update-form"' in users
    assert 'class="user-role-actions"' in users
    assert 'data-table-editor-toggle="user-{{ user.id }}-editor"' in users
    assert 'data-user-edit-row' in users


def test_spacing_and_destructive_controls_are_styled() -> None:
    css = re.sub(r"\s+", " ", CSS_PATH.read_text(encoding="utf-8"))
    targets = (TEMPLATES_PATH / "targets.html").read_text(encoding="utf-8")
    sites = (TEMPLATES_PATH / "sites.html").read_text(encoding="utf-8")
    users = (TEMPLATES_PATH / "users.html").read_text(encoding="utf-8")
    incidents = (TEMPLATES_PATH / "incidents.html").read_text(encoding="utf-8")
    settings = (TEMPLATES_PATH / "settings.html").read_text(encoding="utf-8")

    assert ".active-blocks-panel { margin-top: 28px; }" in css
    assert ".smtp-title-group { display: grid; gap: 12px; }" in css
    assert ".backup-panel { margin-top: 20px; overflow: visible; }" in css
    assert ".badge-success {" in css
    assert ".badge-danger {" in css
    assert ".badge-warning {" in css
    assert ".table-editor > summary {" in css and "color: var(--muted);" in css
    assert ".entity-table tbody td > strong {" in css
    assert ".button-favorite { color: var(--muted); }" in css
    assert ".button-favorite.is-active {" in css
    assert 'aria-pressed="{{ \'true\' if target.favorite else \'false\' }}"' in targets
    assert "badge-success" in targets and "badge-danger" in targets
    assert "badge-success" in sites and "badge-danger" in sites
    assert "badge-success" in users and "badge-danger" in users
    assert "badge-success" in incidents and "badge-danger" in incidents
    assert "badge-success" in settings and "badge-danger" in settings
    assert "/disable-target" in incidents and "Отключить объект" in incidents


def test_tables_never_use_horizontal_scrolling_and_stack_on_mobile() -> None:
    css = re.sub(r"\s+", " ", CSS_PATH.read_text(encoding="utf-8"))

    assert ".table-wrap { width: 100%; max-width: 100%; overflow-x: hidden; }" in css
    assert "table { width: 100%; table-layout: fixed;" in css
    assert ".entity-table { min-width:" not in css
    assert ".targets-table { min-width:" not in css
    assert "@media (max-width: 900px)" in css
    assert ".responsive-table tbody tr:not(.edit-row) {" in css
    assert "content: attr(data-label);" in css
    assert (
        ".responsive-table tbody tr:not(.edit-row) td.details-cell { width: 100%; "
        "max-width: none; }" in css
    )


def test_compact_badges_and_back_to_top_control_are_responsive() -> None:
    css = re.sub(r"\s+", " ", CSS_PATH.read_text(encoding="utf-8"))
    javascript = (
        Path(__file__).resolve().parents[1] / "src/monitoring/static/app.js"
    ).read_text(encoding="utf-8")
    base = (TEMPLATES_PATH / "base.html").read_text(encoding="utf-8")

    assert ".badge { width: max-content; max-width: 100%;" in css
    assert ".target-notification-badge { min-height: 25px; padding: 6px 10px;" in css
    assert "display: inline-flex; align-items: center;" in css
    assert ".back-to-top" in css
    assert "safe-area-inset-bottom" in css
    assert "data-back-to-top" in base
    assert "Вернуться к началу страницы" in base
    assert 'document.querySelector("[data-back-to-top]")' in javascript
    assert 'window.scrollTo({ top: 0, behavior: "smooth" })' in javascript


def test_every_data_header_uses_sortable_header_macro() -> None:
    expected_counts = {
        "sites.html": 6,
        "targets.html": 8,
        "audit.html": 6,
        "users.html": 8,
        "reports.html": 12,
        "target_history.html": 4,
    }

    for filename, expected in expected_counts.items():
        template = (TEMPLATES_PATH / filename).read_text(encoding="utf-8")
        assert template.count("sortable_header(request") == expected


def test_static_assets_are_cache_busted_by_application_version() -> None:
    base = (TEMPLATES_PATH / "base.html").read_text(encoding="utf-8")

    assert "app.css') }}?v={{ app_version }}" in base
    assert "app.js') }}?v={{ app_version }}" in base
    assert "static_asset_revision('app.css')" in base
    assert "static_asset_revision('app.js')" in base


def test_header_user_controls_remain_compact_and_accessible() -> None:
    css = re.sub(r"\s+", " ", CSS_PATH.read_text(encoding="utf-8"))
    base = (TEMPLATES_PATH / "base.html").read_text(encoding="utf-8")
    login = (TEMPLATES_PATH / "login.html").read_text(encoding="utf-8")
    javascript = (
        Path(__file__).resolve().parents[1] / "src/monitoring/static/app.js"
    ).read_text(encoding="utf-8")

    assert 'class="header-user-name">{{ current_user.username }}</span>' in base
    assert "header-user-role" in base and "{{ current_user.username }} ·" not in base
    assert 'class="link-button logout-button"' in base
    assert 'action="/logout"' in base and 'class="header-action-icon"' in base
    assert base.count('data-theme-toggle aria-label="Переключить тему"') == 1
    assert login.count('data-theme-toggle aria-label="Переключить тему"') == 1
    assert base.count('class="theme-toggle-icon"') == 2
    assert login.count('class="theme-toggle-icon"') == 2
    assert ".theme-toggle { position: relative; width: 44px; height: 24px;" in css
    assert ":root[data-theme=\"dark\"] .theme-toggle-thumb" in css
    assert ".theme-toggle:focus-visible" in css
    assert ".header-user { display: none; }" in css
    assert 'const next = current === "dark" ? "light" : "dark";' in javascript


def test_current_navigation_item_uses_a_small_underline() -> None:
    css = re.sub(r"\s+", " ", CSS_PATH.read_text(encoding="utf-8"))
    base = (TEMPLATES_PATH / "base.html").read_text(encoding="utf-8")

    assert base.count('class="nav-link {{ \'active\'') == 9
    assert base.count('aria-current="page"') == 9
    assert "nav .nav-link::after {" in css
    assert "nav .nav-link.active::after { width: min(26px, 70%); }" in css


def test_mobile_navigation_centers_the_active_section() -> None:
    javascript = Path("src/monitoring/static/app.js").read_text(encoding="utf-8")

    assert "const centerActiveNavigationItem = () =>" in javascript
    assert 'window.matchMedia("(max-width: 1050px)")' in javascript
    assert ".nav-link[aria-current=\"page\"]" in javascript
    assert "nav.scrollLeft = Math.max" in javascript


def test_dashboard_renders_the_monitoring_objects_table() -> None:
    dashboard = (TEMPLATES_PATH / "dashboard.html").read_text(encoding="utf-8")
    css = CSS_PATH.read_text(encoding="utf-8")

    assert 'class="panel monitoring-objects"' in dashboard
    assert 'class="monitoring-object-row monitoring-objects-grid' in dashboard
    assert "availability-good" in dashboard
    assert "availability-warning" in dashboard
    assert "availability-down" in dashboard
    assert 'action="/checks/run-now"' in dashboard
    assert "Опросить объекты" in dashboard
    assert "Автообновление страницы" in dashboard
    assert "data-state-auto-refresh" in dashboard
    assert '<label>Тип<select name="kind">' in dashboard
    assert '<label>Сортировка<select name="sort">' in dashboard
    assert 'href="/targets?focus_target_id={{ target.id }}&amp;return_to=/"' in dashboard
    assert 'aria-label="Изменить объект {{ target.name }}"' in dashboard
    assert 'class="monitoring-object-site-name"' in dashboard
    assert 'class="snmp-status-mobile">SNMP</span>' in dashboard
    assert 'Пороги: {{ target.snmp_threshold_count }}' in dashboard
    assert "<span>Инциденты</span><span>Уведом.</span>" in dashboard
    assert "monitoring-object-incidents-mobile" in dashboard
    assert 'href="/incidents?status=open&amp;target_id={{ target.id }}"' in dashboard
    assert ".monitoring-object-incidents-mobile { position: absolute; top: 50%; right: 0;" in css
    assert ".monitoring-object-tablet-meta { display: flex; align-items: center; gap: 5px; }" in css
    assert ".snmp-status-mobile { display: inline; }" in css
    assert (
        ".monitoring-objects-header { position: -webkit-sticky; position: sticky; "
        "top: 0; z-index: 5;"
    ) in css
    assert "overflow-x: clip;" in css


def test_availability_threshold_settings_have_help_and_mobile_layout() -> None:
    settings = Path("src/monitoring/templates/settings.html").read_text(encoding="utf-8")
    css = Path("src/monitoring/static/app.css").read_text(encoding="utf-8")
    migration = Path("alembic/versions/0036_baseline_0_8_5.py").read_text(encoding="utf-8")
    assert 'action="/settings/availability-thresholds"' in settings
    assert 'aria-label="Справка о порогах доступности"' in settings
    assert "availability_warning_threshold_percent" in migration
    assert "availability_good_threshold_percent" in migration
    assert ".availability-thresholds-form { grid-template-columns: 1fr;" in css
    assert 'class="availability-zone-label is-warning"' in settings
    assert 'class="availability-zone-label is-good"' in settings
    assert ".availability-thresholds-panel { margin-top: 20px; }" in css
    assert ".availability-thresholds-heading .eyebrow { margin-bottom: 8px; }" in css


def test_auto_refresh_is_local_and_does_not_trigger_checks() -> None:
    javascript = (
        Path(__file__).resolve().parents[1] / "src/monitoring/static/app.js"
    ).read_text(encoding="utf-8")

    assert '"monitoring-state-auto-refresh"' in javascript
    assert "window.setInterval(refreshPageContent, 60000)" in javascript
    assert 'fetch(window.location.href' in javascript
    assert 'document.querySelector(".portal-details")?.open === true' in javascript
    assert 'document.querySelector(".portal-details")?.setAttribute("open", "")' in javascript
    assert "60000" in javascript
    assert 'fetch("/checks/run-now"' not in javascript


def test_forms_use_background_submission_with_toasts_and_fallback() -> None:
    javascript = (
        Path(__file__).resolve().parents[1] / "src/monitoring/static/app.js"
    ).read_text(encoding="utf-8")
    base = (TEMPLATES_PATH / "base.html").read_text(encoding="utf-8")

    assert 'document.addEventListener("submit"' in javascript
    assert 'body: new FormData(form)' in javascript
    assert 'cleanUrl.pathname === previousPath ? scrollPosition : 0' in javascript
    assert 'syncDocumentShell(documentCopy)' in javascript
    assert 'nextMain.querySelectorAll(".alert")' in javascript
    assert "data-toast-region" in base


def test_pwa_manifest_and_service_worker_are_connected() -> None:
    root = Path(__file__).resolve().parents[1]
    base = (TEMPLATES_PATH / "base.html").read_text(encoding="utf-8")
    javascript = (root / "src/monitoring/static/app.js").read_text(encoding="utf-8")
    manifest = (root / "src/monitoring/static/manifest.webmanifest").read_text(
        encoding="utf-8"
    )

    assert 'rel="manifest"' in base
    assert 'navigator.serviceWorker.register("/service-worker.js")' in javascript
    assert '"display": "standalone"' in manifest
