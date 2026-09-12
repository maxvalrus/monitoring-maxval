"""Optional TV browser smoke on synthetic SQLite data; never uses the working DB.

Run with Playwright + Chromium installed in the development venv:
  python scripts/check_wallboard_browser.py
Screenshots go to the printed temporary directory. No production login required.
"""

from __future__ import annotations

import re
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from monitoring.db import Base, get_db
from monitoring.main import app
from monitoring.models import (
    CheckResult,
    Incident,
    MonitorTarget,
    PortalMetric,
    Site,
    TargetCheck,
    TargetCheckResult,
    UserRole,
)
from monitoring.services.auth import create_user
from monitoring.services.scheduler_metrics import SchedulerRuntimeMetrics


def main() -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    def database():
        with factory() as session:
            yield session

    app.dependency_overrides[get_db] = database
    metrics = SchedulerRuntimeMetrics(poll_seconds=15, parallel_limit=10)
    app.state.scheduler = SimpleNamespace(
        health_snapshot=lambda: metrics.snapshot(running=True, manual_running=False)
    )
    now = datetime.now(UTC)
    with factory() as session:
        create_user(session, "visual-admin", "synthetic-browser-password", UserRole.ADMIN)
        for si, name in enumerate(("Центральный офис", "Серверная", "Удалённая площадка", "Лаборатория")):
            site = Site(name=name, layout_scale=125)
            session.add(site)
            for ti, kind in enumerate(("server", "computer", "network", "camera", "printer", "ups")):
                target = MonitorTarget(
                    site=site, name=f"{('Atlas', 'Рабочая станция', 'Gateway', 'Камера', 'LaserJet', 'Smart UPS')[ti]} {si + 1}",
                    address=f"192.0.2.{si * 10 + ti + 1}", port=80,
                    kind=kind, layout_x=2000 + ti % 3 * 3000, layout_y=3000 + ti // 3 * 3700,
                    enabled=not (si == 3 and ti == 1),
                )
                session.add(target)
                session.flush()
                session.add(CheckResult(target_id=target.id, status="down" if (si, ti) == (0, 1) else "up", latency_ms=12, checked_at=now))
                if ti == 0:
                    for service in ("SSH", "Web", "Backup"):
                        check = TargetCheck(target_id=target.id, name=service, checker_type="tcp", port=22)
                        session.add(check)
                        session.flush()
                        session.add(TargetCheckResult(check_id=check.id, status="up", latency_ms=10, checked_at=now))
                if (si, ti) == (1, 5):
                    session.add(Incident(target_id=target.id, status="open", source_kind="snmp", source_key="ups_output", severity="warning", opened_at=now, last_message="ИБП работает от батареи"))
        for index in range(30):
            session.add(PortalMetric(cpu_percent=12 + index % 7 * 3, memory_percent=48 + index % 4, disk_percent=32, uptime_seconds=86000, bytes_received=1_000_000 + index * 14000, bytes_sent=500000 + index * 8000, packets_received=10000 + index * 70, packets_sent=5000 + index * 50, collected_at=now - timedelta(seconds=(30 - index) * 30)))
        session.commit()
    # Deliberately do not enter TestClient lifespan: no scheduler, TLS or network jobs.
    client = TestClient(app, base_url="https://localhost")
    login = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', login.text)[1]
    assert client.post("/login", data={"username": "visual-admin", "password": "synthetic-browser-password", "csrf_token": token}).status_code == 200
    initial = client.get("/wallboard")
    assert initial.status_code == 200
    output = Path(tempfile.mkdtemp(prefix="maxval-wallboard-smoke-"))
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 1920, "height": 1080}, service_workers="block")
        page.clock.install()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        snapshot = {"html": initial.text, "fail": False}

        def respond(route):
            path = route.request.url.split("localhost", 1)[-1]
            if path == "/wallboard":
                route.fulfill(status=503 if snapshot["fail"] else 200, content_type="text/html", body=snapshot["html"])
            elif path.startswith(("/static/", "/favicon", "/sites/")):
                response = client.request(route.request.method, path, content=route.request.post_data_buffer, headers={"content-type": route.request.headers.get("content-type", "application/octet-stream")})
                route.fulfill(status=response.status_code, content_type=response.headers.get("content-type", "text/plain"), body=response.content)
            else:
                route.fulfill(status=200, content_type="application/json", body="{}")

        page.route("https://localhost/**", respond)
        page.goto("https://localhost/wallboard")
        page.wait_for_function("document.querySelector('[data-wallboard]')._updateSnapshot !== undefined")
        assert page.locator('[data-wallboard-server-clock]').count() == 1
        assert page.locator('.wallboard-telemetry').get_by_text('Объекты', exact=True).count() == 1
        initial_clock = page.locator('[data-wallboard-server-clock] strong').text_content()
        page.clock.fast_forward(1_000)
        assert page.locator('[data-wallboard-server-clock] strong').text_content() != initial_clock
        symbol = page.locator(".wallboard-target.state-ok .target-kind-icon").first
        assert symbol.evaluate("n => getComputedStyle(n).animationName") == "hud-symbol-breathe"
        before = symbol.evaluate("n => getComputedStyle(n).transform")
        page.clock.run_for(500)
        assert symbol.evaluate("n => getComputedStyle(n).transform") != before
        assert page.locator(".telemetry-item .telemetry-icon").first.evaluate("n => getComputedStyle(n).animationName") == "telemetry-icon-pulse"
        assert page.locator(".wallboard-canvas").first.evaluate("n => getComputedStyle(n, '::after').animationName") == "hud-site-sweep"
        for width, height in ((2560, 1440), (1920, 1080), (1440, 900), (1080, 720), (390, 844)):
            page.set_viewport_size({"width": width, "height": height})
            page.wait_for_timeout(300)
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (width, "overflow")
            if width >= 1080:
                telemetry_rows = page.locator(".wallboard-telemetry > *").evaluate_all(
                    "nodes => [...new Set(nodes.map(node => Math.round(node.getBoundingClientRect().top)))]"
                )
                assert len(telemetry_rows) == 1, (width, "telemetry wraps", telemetry_rows)
                status_clock_gap = page.evaluate("""() => {
                    const counts = document.querySelector('.wallboard-counts').getBoundingClientRect();
                    const clock = document.querySelector('[data-wallboard-server-clock]').getBoundingClientRect();
                    return Math.round(clock.left - counts.right);
                }""")
                assert 0 <= status_clock_gap <= 32, (width, "status/clock gap", status_clock_gap)
            overlaps = page.locator(".telemetry-item.has-sparkline").evaluate_all("nodes => nodes.some(n => n.querySelector('.telemetry-copy').getBoundingClientRect().bottom > n.querySelector('svg.telemetry-sparkline').getBoundingClientRect().top)")
            assert not overlaps, (width, "plot overlaps label")
            page.screenshot(path=str(output / f"wallboard-{width}.png"))
        page.set_viewport_size({"width": 1920, "height": 1080})
        page.locator("[data-wallboard-target]").first.click()
        assert page.locator("[data-wallboard-detail-services] li").count() >= 3
        page.keyboard.press("Escape")
        assert page.locator("[data-wallboard-detail]").is_hidden()
        page.locator("[data-wallboard-site-scale-toggle]").first.click()
        scale = page.locator("[data-wallboard-site-scale]").first
        scale.fill("150")
        scale.dispatch_event("input")
        scale.dispatch_event("change")
        page.locator("[data-wallboard-site-scale-toggle]").first.click()
        event_text = page.locator("[data-wallboard-events] > div > span").first
        initial_font = event_text.evaluate("node => parseFloat(getComputedStyle(node).fontSize)")
        page.locator("[data-wallboard-events-font]").fill("180")
        page.locator("[data-wallboard-events-font]").dispatch_event("input")
        assert event_text.evaluate("node => parseFloat(getComputedStyle(node).fontSize)") > initial_font * 1.7
        geometry = page.locator("[data-wallboard-target]").first.get_attribute("style")
        panel = page.locator("[data-wallboard-events]").bounding_box()
        with factory() as session:
            session.add(CheckResult(target_id=2, status="up", latency_ms=3, checked_at=now + timedelta(seconds=1)))
            session.commit()
        snapshot["html"] = client.get("/wallboard").text
        page.evaluate("html => document.querySelector('[data-wallboard]')._updateSnapshot(new DOMParser().parseFromString(html, 'text/html'))", snapshot["html"])
        assert page.locator('[data-wallboard-target][data-target-id="2"]').get_attribute("class").find("is-recovered") >= 0
        assert page.locator("[data-wallboard-target]").first.get_attribute("style") == geometry
        assert page.locator("[data-wallboard-events]").bounding_box() == panel
        assert scale.input_value() == "150"
        assert page.locator("[data-wallboard-events-font]").input_value() == "180"
        assert event_text.evaluate("node => parseFloat(getComputedStyle(node).fontSize)") > initial_font * 1.7
        page.locator("[data-wallboard-site-focus]").first.click()
        assert page.locator("[data-wallboard-site]:visible").count() == 1
        page.locator("[data-wallboard-site-focus]").first.click()
        first_site = page.locator('[data-wallboard-site="1"]')
        second_site = page.locator('[data-wallboard-site="2"]')
        source = first_site.locator('[data-wallboard-site-drag]')
        destination = second_site.locator('[data-wallboard-site-drag]')
        source_box = source.bounding_box()
        destination_box = destination.bounding_box()
        page.mouse.move(source_box['x'] + 20, source_box['y'] + 16)
        page.mouse.down()
        page.mouse.move(destination_box['x'] + 20, destination_box['y'] + 16, steps=10)
        assert second_site.evaluate("node => node.classList.contains('is-site-drop-target')")
        page.mouse.up()
        assert first_site.evaluate("node => getComputedStyle(node).order") == "1"
        assert second_site.evaluate("node => getComputedStyle(node).order") == "0"
        page.reload()
        page.wait_for_function("document.querySelector('[data-wallboard]').dataset.ready === 'true'")
        assert page.locator('[data-wallboard-site="1"]').evaluate("node => getComputedStyle(node).order") == "1"
        assert page.locator('[data-wallboard-site="2"]').evaluate("node => getComputedStyle(node).order") == "0"
        page.locator("[data-wallboard-actions-menu-toggle]").click()
        page.locator("[data-wallboard-tests-menu-toggle]").click()
        page.locator("[data-wallboard-critical-burst-test]").click()
        assert page.locator(".wallboard-critical-alert-card").count() == 10
        page.wait_for_timeout(1600)
        page.screenshot(path=str(output / "critical-cascade.png"))
        page.keyboard.press("Escape")
        assert page.locator("[data-critical-alert]").is_hidden()
        snapshot["fail"] = True
        page.clock.fast_forward(16_000)
        page.wait_for_function("document.querySelector('[data-wallboard]').classList.contains('is-stale')")
        snapshot["fail"] = False
        page.clock.fast_forward(16_000)
        page.wait_for_function("!document.querySelector('[data-wallboard]').classList.contains('is-stale')")
        page.emulate_media(reduced_motion="reduce", color_scheme="light")
        assert page.locator(".wallboard-canvas").first.evaluate("n => getComputedStyle(n, '::after').animationName") == "none"
        assert symbol.evaluate("n => getComputedStyle(n).animationName") == "none"
        page.goto("https://localhost/sites/1/layout")
        page.wait_for_function("document.querySelector('[data-site-layout-form]').dataset.ready === 'true'")
        for width, height in ((1440, 900), (1024, 768), (390, 844), (844, 390)):
            page.set_viewport_size({"width": width, "height": height})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (width, "editor overflow")
            page.screenshot(path=str(output / f"editor-{width}.png"))
        page.set_viewport_size({"width": 1440, "height": 900})
        canvas = page.locator('[data-site-layout-canvas]')
        target = page.locator('[data-layout-target]').first
        target_id = target.get_attribute('data-target-id')
        target.scroll_into_view_if_needed()
        start = target.bounding_box()
        field = canvas.bounding_box()
        page.mouse.move(start['x'] + start['width'] / 2, start['y'] + start['height'] / 2)
        page.mouse.down()
        page.mouse.move(field['x'] + field['width'] * .6, field['y'] + field['height'] * .5, steps=10)
        page.mouse.up()
        coords = [target.get_attribute('data-layout-x'), target.get_attribute('data-layout-y')]
        with page.expect_response(lambda response: response.request.method == 'POST' and '/layout' in response.url):
            page.get_by_role('button', name='Сохранить расположение', exact=True).click()
        page.reload()
        target = page.locator(f'[data-layout-target][data-target-id="{target_id}"]')
        assert [target.get_attribute('data-layout-x'), target.get_attribute('data-layout-y')] == coords
        assert target.locator('.site-layout-target-icon').count() == 1

        # Обычный клик выбирает первый объект, Ctrl-клик добавляет второй. При drag
        # выбранного объекта оба должны сместиться на одну и ту же величину.
        second_target = page.locator('[data-layout-target]').nth(1)
        second_id = second_target.get_attribute('data-target-id')
        target.click()
        page.keyboard.down('Control')
        second_target.click()
        page.keyboard.up('Control')
        assert 'is-selected' in (target.get_attribute('class') or '')
        assert 'is-selected' in (second_target.get_attribute('class') or '')
        first_before = [int(target.get_attribute('data-layout-x')), int(target.get_attribute('data-layout-y'))]
        second_before = [int(second_target.get_attribute('data-layout-x')), int(second_target.get_attribute('data-layout-y'))]
        start = target.bounding_box()
        field = canvas.bounding_box()
        page.mouse.move(start['x'] + start['width'] / 2, start['y'] + start['height'] / 2)
        page.mouse.down()
        page.mouse.move(field['x'] + field['width'] * .7, field['y'] + field['height'] * .6, steps=10)
        page.mouse.up()
        first_after = [int(target.get_attribute('data-layout-x')), int(target.get_attribute('data-layout-y'))]
        second_after = [int(second_target.get_attribute('data-layout-x')), int(second_target.get_attribute('data-layout-y'))]
        assert [second_after[0] - second_before[0], second_after[1] - second_before[1]] == [
            first_after[0] - first_before[0], first_after[1] - first_before[1]
        ]
        with page.expect_response(lambda response: response.request.method == 'POST' and '/layout' in response.url):
            page.get_by_role('button', name='Сохранить расположение', exact=True).click()
        page.reload()
        target = page.locator(f'[data-layout-target][data-target-id="{target_id}"]')
        second_target = page.locator(f'[data-layout-target][data-target-id="{second_id}"]')
        assert [target.get_attribute('data-layout-x'), target.get_attribute('data-layout-y')] == [str(value) for value in first_after]
        assert [second_target.get_attribute('data-layout-x'), second_target.get_attribute('data-layout-y')] == [str(value) for value in second_after]
        canvas.click(position={"x": 5, "y": 5})
        assert 'is-selected' not in (target.get_attribute('class') or '')
        assert 'is-selected' not in (second_target.get_attribute('class') or '')
        for value in ('50', '200'):
            page.locator('[data-site-layout-scale]').fill(value)
            page.locator('[data-site-layout-scale]').dispatch_event('input')
            assert float(canvas.evaluate("n => getComputedStyle(n).getPropertyValue('--site-layout-target-scale')")) == int(value) / 100
        assert not errors, errors
        browser.close()
    client.close()
    app.dependency_overrides.clear()
    engine.dispose()
    print(f"PASS: layouts, multi-select, plots, services, Escape, scale, refresh/recovery, focus, cascade, reduced motion. Screenshots: {output}")


if __name__ == "__main__":
    main()
