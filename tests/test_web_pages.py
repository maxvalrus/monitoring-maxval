import re
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from monitoring.db import Base, get_db
from monitoring.main import app
from monitoring.models import (
    CheckResult,
    Incident,
    MonitorTarget,
    Site,
    SnmpConfig,
    SnmpInterface,
    SnmpMetric,
    SnmpSample,
    SnmpSupply,
    SnmpThreshold,
    SnmpUpsLine,
    SnmpUpsState,
    UserRole,
)
from monitoring.services.auth import create_user


def csrf_from(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def test_reports_history_dashboard_and_pwa_routes_render() -> None:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with factory() as session:
            create_user(session, "admin", "administrator password", UserRole.ADMIN)
            site = Site(name="Офис")
            target = MonitorTarget(
                site=site,
                name="RTSP камера",
                kind="camera",
                address="cam/stream",
                port=554,
            )
            session.add(target)
            session.flush()
            session.add(
                CheckResult(
                    target_id=target.id,
                    status="up",
                    latency_ms=8,
                    checked_at=datetime.now(UTC),
                )
            )
            metric = SnmpMetric(
                target_id=target.id,
                name="Температура",
                oid="1.3.6.1.4.1.1.0",
                unit="°C",
                display_order=1,
            )
            session.add(metric)
            session.flush()
            session.add_all(
                [
                    SnmpSample(metric_id=metric.id, value=10),
                    SnmpSample(metric_id=metric.id, value=20),
                    SnmpSample(metric_id=metric.id, value=30),
                ]
            )
            session.add_all(
                [
                    SnmpConfig(target_id=target.id, enabled=True, ups_enabled=True),
                    SnmpSupply(
                        target_id=target.id,
                        hr_device_index=1,
                        supply_index=1,
                        description="Чёрный тонер",
                        percent_remaining=72,
                        level_state="ok",
                    ),
                    SnmpUpsState(
                        target_id=target.id,
                        manufacturer="APC",
                        model="Smart-UPS",
                        battery_status=2,
                        output_source=3,
                        battery_charge_percent=96,
                        estimated_runtime_minutes=42,
                        battery_voltage=55,
                        battery_temperature=24,
                        last_polled_at=datetime.now(UTC),
                    ),
                ]
            )
            session.add_all(
                [
                    SnmpUpsLine(
                        target_id=target.id,
                        direction="input",
                        line_index=1,
                        voltage=228,
                        current=1,
                    ),
                    SnmpUpsLine(
                        target_id=target.id,
                        direction="output",
                        line_index=1,
                        voltage=230,
                        current=2,
                        load_percent=37,
                    ),
                ]
            )
            session.commit()
            target_id = target.id

        with TestClient(app, base_url="https://localhost") as client:
            login_page = client.get("/login")
            response = client.post(
                "/login",
                data={
                    "username": "admin",
                    "password": "administrator password",
                    "csrf_token": csrf_from(login_page.text),
                },
                follow_redirects=False,
            )
            assert response.status_code == 303
            dashboard = client.get("/")
            dashboard_by_kind = client.get("/?kind=camera")
            dashboard_by_incidents = client.get("/?sort=open_incidents")
            report = client.get("/reports?hours=24")
            history = client.get(f"/targets/{target_id}/history?hours=24")
            ups = client.get(f"/targets/{target_id}/snmp/ups?hours=24&per_page=20")
            ups_history = client.get(
                f"/targets/{target_id}/snmp/ups/history?hours=24&per_page=20",
                follow_redirects=False,
            )
            snmp_default = client.get(f"/targets/{target_id}/snmp")
            snmp = client.get(
                f"/targets/{target_id}/snmp?metric_sort=name&metric_direction=asc"
                "&sample_sort=value&sample_direction=asc&per_page=2&page=2"
            )
            worker = client.get("/service-worker.js")

        assert (
            dashboard.status_code
            == report.status_code
            == history.status_code
            == snmp_default.status_code
            == snmp.status_code
            == ups.status_code
            == 200
        )
        assert "Сервер портала" in dashboard.text
        assert "RTSP камера" in dashboard_by_kind.text
        assert 'option value="camera" selected' in dashboard_by_kind.text
        assert 'option value="open_incidents" selected' in dashboard_by_incidents.text
        assert "Доступность" in report.text
        assert "Задержка ответа" in history.text
        assert "Расходники" in history.text
        assert "Чёрный тонер" in history.text
        assert "Последние данные UPS-MIB" in history.text
        assert "Smart-UPS" in history.text
        assert "История значений" in ups.text
        assert "Заряд батареи" in ups.text
        assert "Автономность" in ups.text
        assert "Напряжение батареи" in ups.text
        assert "Температура батареи" in ups.text
        assert "Напряжение входа / выхода" in ups.text
        assert "Ток входа / выхода" in ups.text
        assert "Нагрузка выхода" in ups.text
        assert 'id="ups-history"' in ups.text
        assert "Строк на странице" in ups.text
        assert ups_history.status_code == 307
        assert ups_history.headers["location"] == (
            f"/targets/{target_id}/snmp/ups?hours=24&per_page=20#ups-history"
        )
        assert "Страница <strong>2</strong> из <strong>2</strong>" in snmp.text
        assert "metric_sort=name" in snmp.text
        assert "sample_sort=value" in snmp.text
        assert 'id="snmp-map-title"' in snmp_default.text
        assert "Карта SNMP" in snmp_default.text
        assert 'href="#snmp-settings"' in snmp_default.text
        assert 'data-navigation-focus="snmp-settings"' in snmp_default.text
        assert 'id="snmp-settings"' in snmp_default.text
        assert 'name="version"' in snmp_default.text
        assert 'option value="v1"' in snmp_default.text
        assert 'option value="v2c" selected' in snmp_default.text
        assert "OID Discovery" in snmp_default.text
        assert "SNMP выполняется только после успешной основной проверки объекта" in snmp_default.text
        assert ">30<" in snmp.text
        assert 'name="per_page" value="20"' in snmp_default.text
        assert worker.headers["service-worker-allowed"] == "/"
    finally:
        app.dependency_overrides.clear()


def test_dashboard_renders_255_targets_without_n_plus_one_queries() -> None:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        now = datetime.now(UTC)
        with factory() as session:
            create_user(session, "admin", "administrator password", UserRole.ADMIN)
            site = Site(name="Нагрузочная площадка")
            targets = [
                MonitorTarget(
                    site=site,
                    name=f"Объект {index:03d}",
                    kind="printer",
                    checker_type="icmp",
                    address=f"192.0.2.{index % 254 + 1}",
                    port=1,
                    display_order=index,
                )
                for index in range(255)
            ]
            session.add_all(targets)
            session.flush()
            supplies = [
                SnmpSupply(
                    target_id=target.id,
                    hr_device_index=1,
                    supply_index=1,
                    supply_class=3,
                    supply_type=21,
                    description="Black Toner",
                    percent_remaining=72,
                    level_state="ok",
                    present=True,
                )
                for target in targets
            ]
            session.add_all(supplies)
            session.flush()
            session.add_all(
                CheckResult(
                    target_id=target.id,
                    status="up",
                    latency_ms=float(index % 20 + 1),
                    checked_at=now,
                )
                for index, target in enumerate(targets)
            )
            first = targets[0]
            second = targets[1]
            session.add_all(
                (
                    CheckResult(
                        target_id=first.id,
                        status="up",
                        latency_ms=3,
                        checked_at=now - timedelta(minutes=1),
                    ),
                    CheckResult(
                        target_id=first.id,
                        status="down",
                        latency_ms=999,
                        checked_at=now + timedelta(seconds=1),
                    ),
                    SnmpConfig(
                        target_id=first.id,
                        enabled=True,
                        community_encrypted="test-only",
                        last_status="error",
                    ),
                    SnmpMetric(target_id=first.id, name="Температура", oid="1.2.3.1"),
                    SnmpMetric(target_id=first.id, name="Напряжение", oid="1.2.3.2"),
                    SnmpInterface(
                        target_id=first.id,
                        if_index=1,
                        if_name="ether1",
                        monitor_enabled=True,
                    ),
                    SnmpThreshold(
                        target_id=first.id,
                        source_kind="supply",
                        supply_id=supplies[0].id,
                        field="percent",
                        operator="lt",
                        warning_value=80,
                        critical_value=50,
                        enabled=True,
                    ),
                    Incident(
                        target_id=first.id,
                        status="open",
                        failure_count=2,
                        opened_at=now,
                        last_failure_at=now,
                    ),
                    Incident(
                        target_id=second.id,
                        status="open",
                        failure_count=2,
                        opened_at=now,
                        last_failure_at=now,
                    ),
                    Incident(
                        target_id=second.id,
                        status="open",
                        failure_count=2,
                        opened_at=now,
                        last_failure_at=now,
                    ),
                )
            )
            session.commit()
            first_id = first.id
            second_id = second.id

        with TestClient(app, base_url="https://localhost") as client:
            login_page = client.get("/login")
            login = client.post(
                "/login",
                data={
                    "username": "admin",
                    "password": "administrator password",
                    "csrf_token": csrf_from(login_page.text),
                },
                follow_redirects=False,
            )
            assert login.status_code == 303
            select_statements: list[str] = []

            def count_selects(_conn, _cursor, statement, _parameters, _context, _many):
                if statement.lstrip().upper().startswith("SELECT"):
                    select_statements.append(statement)

            event.listen(engine, "before_cursor_execute", count_selects)
            try:
                response = client.get("/?per_page=255")
            finally:
                event.remove(engine, "before_cursor_execute", count_selects)
            response_sorted = client.get("/?per_page=255&sort=open_incidents")

        assert response.status_code == 200
        assert response_sorted.status_code == 200
        assert response.text.count('class="monitoring-object-row monitoring-objects-grid') == 255
        # Site-entry gates add one batched lookup.  The count remains constant for 255 rows.
        assert len(select_statements) <= 21
        assert "66.67%" in response.text
        first_row = re.search(
            rf'<article id="target-{first_id}".*?</article>', response.text, re.DOTALL
        )
        assert first_row is not None
        assert "Оффлайн" in first_row.group(0)
        assert 'class="monitoring-object-latency-content"><strong>—</strong>' in first_row.group(0)
        assert (
            'title="Последний SNMP polling завершился ошибкой">'
            '<span class="snmp-status-desktop">Ошибка</span>'
        ) in first_row.group(0)
        assert "OID: 2" in first_row.group(0)
        assert "Интерф.: 1" in first_row.group(0)
        assert "Пороги: 1" in first_row.group(0)
        assert 'aria-label="Открыть незакрытые инциденты объекта Объект 000: 1"' in first_row.group(0)
        assert f'href="/incidents?status=open&amp;target_id={first_id}"' in first_row.group(0)
        assert 'class="monitoring-supply-level supply-level-warning"' in first_row.group(0)
        assert "<b>K</b> 72%" in first_row.group(0)
        first_sorted_row = re.search(
            r'<article id="target-(\d+)".*?</article>', response_sorted.text, re.DOTALL
        )
        assert first_sorted_row is not None
        assert int(first_sorted_row.group(1)) == second_id
    finally:
        app.dependency_overrides.clear()


def test_snmp_header_actions_use_compact_icon_buttons() -> None:
    root = Path("src/monitoring")
    snmp = (root / "templates/target_snmp.html").read_text(encoding="utf-8")
    interfaces = (root / "templates/target_snmp_interfaces.html").read_text(encoding="utf-8")
    discovery = (root / "templates/target_snmp_discovery.html").read_text(encoding="utf-8")
    thresholds = (root / "templates/target_snmp_thresholds.html").read_text(encoding="utf-8")
    supplies = (root / "templates/target_snmp_supplies.html").read_text(encoding="utf-8")
    css = (root / "static/app.css").read_text(encoding="utf-8")

    for template in (snmp, interfaces, discovery, thresholds, supplies):
        assert 'class="snmp-page' in template
        assert 'class="page-heading snmp-heading"' in template
        assert 'class="snmp-header-icon-actions"' in template
        assert 'class="icon-action snmp-header-icon-action"' in template
        assert 'class="snmp-title-row"' in template
        assert 'class="snmp-title-icon"' in template
    assert snmp.count('href="/targets/{{ target.id }}/snmp/interfaces"') >= 1
    assert snmp.count('href="/targets/{{ target.id }}/history"') >= 1
    assert 'href="/targets/{{ target.id }}/snmp/discovery"' in snmp
    assert 'href="/targets/{{ target.id }}/snmp/thresholds"' in interfaces
    assert 'href="/targets/{{ target.id }}/snmp/supplies"' in interfaces
    assert 'href="/targets/{{ target.id }}/history"' in interfaces
    assert 'href="/targets/{{ target.id }}/snmp/interfaces"' in discovery
    assert 'href="/targets/{{ target.id }}/snmp/thresholds"' in discovery
    assert 'href="/targets/{{ target.id }}/snmp/supplies"' in discovery
    assert 'href="/targets/{{ target.id }}/history"' in discovery
    assert 'href="/targets/{{ target.id }}/snmp/supplies"' in thresholds
    assert 'href="/targets/{{ target.id }}/snmp/discovery"' in thresholds
    assert 'href="/targets/{{ target.id }}/history"' in thresholds
    assert 'href="/targets/{{ target.id }}/snmp/interfaces"' in supplies
    assert 'href="/targets/{{ target.id }}/snmp/thresholds"' in supplies
    assert "Состояние и трафик выбранных интерфейсов обновляются при SNMP polling." in interfaces
    assert '.snmp-header-icon-actions { display: flex;' in css
    assert '.snmp-map-grid { display: grid;' in css
    assert '.snmp-map-card { min-width: 0;' in css
    assert '.snmp-title-row { min-width: 0; display: flex;' in css
    assert '.snmp-page > .page-heading { margin-bottom: 0; }' in css
    assert '.snmp-heading { align-items: flex-start; gap: 16px; }' in css
    assert '.snmp-heading-actions { flex: 0 0 auto; align-self: flex-start; padding-top: 21px; }' in css
    assert 'href="/targets/{{ target.id }}/snmp/discovery"' in interfaces
    assert 'class="form-actions snmp-interface-filter-actions"' in interfaces
    assert 'title="Сбросить фильтры"' in interfaces
    assert interfaces.count('class="snmp-interface-readings"') == 2
    assert '.snmp-interface-filters { display: grid;' in css
    assert '.snmp-interface-readings { min-width: 0; display: grid; gap: 3px; }' in css
    assert 'padding: 18px 24px;' in css


def test_snmp_metric_creation_uses_separate_responsive_cards() -> None:
    root = Path("src/monitoring")
    template = (root / "templates/target_snmp.html").read_text(encoding="utf-8")
    css = (root / "static/app.css").read_text(encoding="utf-8")

    assert 'class="panel snmp-metrics-panel"' in template
    assert 'class="snmp-metric-create-grid"' in template
    assert template.count('class="panel snmp-metric-create-card"') == 2
    assert "Добавить OID" in template
    assert "Добавить формулу" in template
    assert "Список ручных метрик" in template
    assert 'class="snmp-metric-list"' in template
    assert 'class="snmp-metric-list-actions"' in template
    assert 'action="/checks/targets/{{ target.id }}/run-now"' in template
    assert "Обновить ручные метрики" in template
    assert "Всего: {{ metrics|length }} из 32" in template
    assert "Ручные метрики ещё не добавлены." in template
    assert 'class="snmp-metric-source"' in template
    assert '.snmp-metric-create-grid { display: grid;' in css
    assert '.snmp-metric-create-footer { margin-top: auto;' in css
    assert '.snmp-metric-poll-button { width: 30px;' in css
    assert '.snmp-metric-create-grid { grid-template-columns: 1fr; gap: 16px; padding: 18px 16px; }' in css


def test_site_layout_and_wallboard_use_existing_visual_primitives() -> None:
    root = Path("src/monitoring")
    wallboard = (root / "templates/wallboard.html").read_text(encoding="utf-8")
    dashboard = (root / "templates/dashboard.html").read_text(encoding="utf-8")
    layout = (root / "templates/site_layout.html").read_text(encoding="utf-8")
    routes = (root / "web/routes.py").read_text(encoding="utf-8")
    admin = (root / "web/admin_routes.py").read_text(encoding="utf-8")
    css = (root / "static/app.css").read_text(encoding="utf-8")
    wallboard_css = (root / "static/wallboard.css").read_text(encoding="utf-8")

    assert '@router.get("/wallboard"' in routes
    assert "get_targets_health(session, states)" in routes
    assert '"health_counts": health_counts' in routes
    assert 'data-wallboard-sites' in wallboard
    assert 'wallboard-telemetry' in wallboard
    assert 'wallboard_telemetry_icon' in wallboard
    assert 'data-wallboard-server-clock' in wallboard
    assert 'Wallboard · {{ app_version }}' in wallboard
    assert '"label": "Объекты"' in routes
    assert 'f"Запас {scheduler.headroom_percent:.0f}%"' in routes
    assert "wallboard-server-clock" in wallboard_css
    assert 'wallboard-site-stamp' in wallboard
    assert '.wallboard { grid-template-rows: auto auto minmax(0, 1fr) !important; }' in css
    assert 'grid-template-columns: 1.25fr repeat(8, minmax(0, 1fr));' in css
    assert 'wallboard-telemetry-{{ wallboard_portal[\'items\']|length }}' in wallboard
    assert '--hud-instruments' not in wallboard
    assert '.wallboard-page .wallboard-telemetry-8' in wallboard_css
    assert 'telemetry-sparkline' in wallboard
    assert '.wallboard-events > div > span { border-radius: 2px; font-size: 1em; }' in css
    assert "path='/favicon.svg'" in wallboard
    assert 'wallboard-site-heading' in wallboard
    assert 'data-wallboard-sites-menu-toggle' in wallboard
    assert 'data-wallboard-actions-menu-toggle' in wallboard
    assert 'data-wallboard-actions-menu' in wallboard
    assert 'data-wallboard-refresh-all' in wallboard
    assert 'data-wallboard-critical-test' in wallboard
    assert 'data-wallboard-critical-burst-test' in wallboard
    assert 'data-wallboard-tests-menu' in wallboard
    assert 'action="/checks/run-now"' in wallboard
    assert 'data-wallboard-site-toggle' in wallboard
    assert 'data-wallboard-preview-target' in wallboard
    assert 'data-wallboard-rotation' in wallboard
    assert 'data-wallboard-site-focus' in wallboard
    assert 'data-wallboard-site-center' in wallboard
    assert 'data-wallboard-site-scale' in wallboard
    assert 'data-wallboard-site-scale-toggle' in wallboard
    assert 'wallboard-site-summary' in wallboard
    assert 'wallboard-target-state' in wallboard
    assert 'wallboard-target-services' in wallboard
    assert 'data-target-services=' in wallboard
    assert 'data-target-health=' in wallboard
    assert 'data-wallboard-detail-services' in wallboard
    assert 'data-wallboard-detail-health-status' in wallboard
    assert 'site-layout-target-services' in layout
    assert 'item["services"]' in routes
    assert 'item["service_details"]' in routes
    assert 'item["health"]' in routes
    assert 'wallboard_portal' in routes
    assert 'portal_dashboard(session, scheduler=scheduler_snapshot)' in routes
    assert 'target_services_by_target=target_services_by_target' in admin
    assert 'if not service["is_primary"]' in routes
    assert 'min="10" max="200"' in wallboard
    assert 'data-wallboard-status-toggle' in wallboard
    assert 'data-wallboard-status-dialog' in wallboard
    assert 'data-critical-alert' in wallboard
    assert 'data-critical-alert-grid' in wallboard
    assert 'wallboard-critical-alert-card-close' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'data-critical-target' in wallboard
    assert 'data-critical-alert' in dashboard
    assert 'data-critical-source="/wallboard"' in dashboard
    assert 'critical_alert_targets' in dashboard
    assert 'role="menu"' in wallboard
    assert 'wallboard-site-edit-link' in wallboard
    assert 'data-wallboard-events' in wallboard
    assert 'class="wallboard-events-title"><strong>EVENT STREAM // LAST HOUR</strong>' in wallboard
    assert 'data-wallboard-events-drag' in wallboard
    assert 'data-wallboard-events-reset' in wallboard
    assert "Сбросить размеры окна событий" in wallboard
    assert 'data-wallboard-events-close' in wallboard
    assert 'data-wallboard-events-font' in wallboard
    assert 'data-wallboard-events-collapse' in wallboard
    assert 'min="50" max="200"' in wallboard
    assert 'data-wallboard-sites-size-reset' in wallboard
    assert 'data-wallboard-site-resize' in wallboard
    assert '@router.get("/sites/{site_id}/layout"' in admin
    assert '@router.post("/sites/{site_id}/layout")' in admin
    assert 'data-site-layout-canvas' in layout
    assert 'site-layout-stamp' in layout
    assert 'data-site-layout-palette' in layout
    assert 'data-layout-palette-target' in layout
    assert 'data-layout-x="{{ target.layout_x }}"' in layout
    assert 'data-site-layout-clear' in layout
    assert 'data-site-layout-switch' in layout
    assert 'data-site-layout-form data-no-async' in layout
    assert 'name="layout_scale"' in layout
    assert 'min="50" max="200"' in layout
    assert 'Math.max(50, Math.min(200' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'site-layout-palette-list' in css
    assert 'scale(var(--site-layout-target-scale,1))' in css
    assert 'data-layout-scale="{{ site.layout_scale / 100 }}"' in wallboard
    assert 'node.dataset.layoutScale' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'containsPoint(palette, event)' in (
        root / "static/app.js"
    ).read_text(encoding="utf-8")
    assert '.wallboard-sites { width:100%; height:100%; min-height:0; display:grid;' in css
    assert '--wallboard-site-columns' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'monitoring-wallboard-visible-sites' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'monitoring-wallboard-site-scale-overrides' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'setActionsMenuOpen' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'data-wallboard-status-list' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'monitoring-wallboard-critical-alerted' in wallboard
    assert 'initCriticalAlerts' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'wallboard-critical-alert-card' in (root / "static/app.js").read_text(encoding="utf-8")
    assert '--critical-alert-delay' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'cascadeCentre' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'wallboard-critical-test' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'wallboard-critical-burst-test' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'setTestsMenuOpen' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'wallboard-critical-alert' in css
    assert 'renderTargetServices' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'renderTargetHealth' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'wallboard-warning-pulse' in css
    assert 'prefers-reduced-motion: reduce' in css
    assert 'wallboard-cyber-scan' in css
    assert 'getBoundingClientRect' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'monitoring-wallboard-events-layout' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'setEventsCollapsed' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'version: 2' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'monitoring-wallboard-site-pan-offsets' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'centerSiteObjects' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'constrainedPan' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'health_counts.disabled' in wallboard
    assert 'monitoring-wallboard-site-grid-sizes' in (root / "static/app.js").read_text(encoding="utf-8")
    assert '((x / 100) - 50) * screenScale' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'setInterval' in (root / "static/app.js").read_text(encoding="utf-8")
    assert 'focusedSiteId' in (root / "static/app.js").read_text(encoding="utf-8")
    assert '@router.post("/sites/{site_id}/layout-scale")' in admin
    assert 'wallboard-site-layout-link' in wallboard
    assert 'Выйти из полноэкранного режима' in (
        root / "static/app.js"
    ).read_text(encoding="utf-8")


def test_site_layout_scale_is_persisted_and_rendered_on_wallboard() -> None:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    def override_db() -> Generator[Session, None, None]:
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with factory() as session:
            create_user(session, "admin", "administrator password", UserRole.ADMIN)
            site = Site(name="Схема")
            target = MonitorTarget(site=site, name="Объект", address="192.0.2.10", port=80)
            second_site = Site(name="Вторая схема")
            second_target = MonitorTarget(
                site=second_site,
                name="Другой объект",
                address="192.0.2.11",
                port=80,
                layout_x=5000,
                layout_y=5000,
            )
            session.add_all([target, second_target])
            session.commit()
            site_id, target_id = site.id, target.id

        with TestClient(app, base_url="https://localhost") as client:
            login_page = client.get("/login")
            login_response = client.post(
                "/login",
                data={
                    "username": "admin",
                    "password": "administrator password",
                    "csrf_token": csrf_from(login_page.text),
                },
                follow_redirects=False,
            )
            assert login_response.status_code == 303
            editor = client.get(f"/sites/{site_id}/layout")
            saved = client.post(
                f"/sites/{site_id}/layout",
                data={
                    "csrf_token": csrf_from(editor.text),
                    "layout_scale": "140",
                    "positions": f'[{{"id":{target_id},"x":5000,"y":5000}}]',
                },
                follow_redirects=False,
            )
            assert saved.status_code == 303
            scale_saved = client.post(
                f"/sites/{site_id}/layout-scale",
                data={"csrf_token": csrf_from(editor.text), "layout_scale": "200"},
            )
            assert scale_saved.status_code == 200
            assert scale_saved.json() == {"layout_scale": 200}
            scale_too_small = client.post(
                f"/sites/{site_id}/layout-scale",
                data={"csrf_token": csrf_from(editor.text), "layout_scale": "40"},
            )
            assert scale_too_small.status_code == 422
            editor_after_save = client.get(f"/sites/{site_id}/layout")
            wallboard = client.get("/wallboard")

        assert 'value="200" data-site-layout-scale' in editor_after_save.text
        assert 'data-layout-scale="2.0"' in wallboard.text
        assert wallboard.text.count('data-wallboard-site=') == 2
        assert "Вторая схема" in wallboard.text
        assert "wallboard-site-content" in wallboard.text
    finally:
        app.dependency_overrides.clear()


def test_async_form_handler_preserves_scroll_for_rendered_validation_page() -> None:
    javascript = Path("src/monitoring/static/app.js").read_text(encoding="utf-8")

    assert 'response.headers.get("X-Monitoring-Page-Path")' in javascript
    assert 'cleanUrl.pathname = renderedPagePath' in javascript
