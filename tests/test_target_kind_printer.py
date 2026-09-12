import re
from collections.abc import Generator
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from monitoring.db import Base, get_db
from monitoring.main import app
from monitoring.models import (
    AuditLog,
    MonitorTarget,
    Site,
    SnmpSupply,
    SnmpThreshold,
    TargetKind,
    UserRole,
)
from monitoring.services.auth import create_user


def csrf_from(html: str) -> str:
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match is not None
    return match.group(1)


def test_printer_target_kind_can_be_created_and_rendered() -> None:
    assert TargetKind.PRINTER.value == "printer"

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
            session.add(site)
            session.commit()
            site_id = site.id

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

            targets_page = client.get("/targets")
            create = client.post(
                "/targets",
                data={
                    "csrf_token": csrf_from(targets_page.text),
                    "site_id": str(site_id),
                    "name": "Принтер бухгалтерии",
                    "kind": "printer",
                    "checker_type": "tcp",
                    "address": "192.0.2.55",
                    "port": "9100",
                    "interval_seconds": "300",
                    "return_to": "/targets",
                },
                follow_redirects=False,
            )
            assert create.status_code == 303

            dashboard = client.get("/")
            reports = client.get("/reports?kind=printer&hours=24")
            targets = client.get("/targets?kind=printer")

        with factory() as session:
            target = session.scalar(
                select(MonitorTarget).where(MonitorTarget.name == "Принтер бухгалтерии")
            )
            assert target is not None
            target_id = target.id
            assert target.kind == "printer"
            black = SnmpSupply(
                target_id=target.id,
                hr_device_index=1,
                supply_index=1,
                supply_class=3,
                supply_type=21,
                description="0xd0a7d0b5d180d0bdd18bd0b920d0bad0b0d180d182d180d0b8d0b4d0b4d0b6",
                percent_remaining=72,
                level_state="ok",
                present=True,
            )
            magenta = SnmpSupply(
                target_id=target.id,
                hr_device_index=1,
                supply_index=2,
                supply_class=3,
                supply_type=21,
                description="Magenta Toner",
                percent_remaining=18,
                level_state="ok",
                present=True,
            )
            yellow = SnmpSupply(
                target_id=target.id,
                hr_device_index=1,
                supply_index=3,
                supply_class=3,
                supply_type=21,
                description="Yellow Toner",
                percent_remaining=8,
                level_state="ok",
                present=True,
            )
            cyan = SnmpSupply(
                target_id=target.id,
                hr_device_index=1,
                supply_index=4,
                supply_class=3,
                supply_type=21,
                description="Cyan Toner",
                percent_remaining=None,
                level_state="unknown",
                present=True,
            )
            session.add_all((black, magenta, yellow, cyan))
            session.flush()
            black_id = black.id
            session.add_all(
                (
                    SnmpThreshold(
                        target_id=target.id,
                        source_kind="supply",
                        supply_id=magenta.id,
                        field="percent",
                        operator="lt",
                        warning_value=20,
                        critical_value=10,
                        enabled=True,
                    ),
                    SnmpThreshold(
                        target_id=target.id,
                        source_kind="supply",
                        supply_id=yellow.id,
                        field="percent",
                        operator="lt",
                        warning_value=20,
                        critical_value=10,
                        enabled=True,
                    ),
                )
            )
            session.commit()

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
            supplies_page = client.get(f"/targets/{target_id}/snmp/supplies")
            assert "Изменить имя расходника" in supplies_page.text
            rename = client.post(
                f"/targets/{target_id}/snmp/supplies/{black_id}/name",
                data={
                    "csrf_token": csrf_from(supplies_page.text),
                    "custom_name": "Чёрный картридж HP 37A",
                },
                follow_redirects=False,
            )
            assert rename.status_code == 303
            dashboard = client.get("/")
            history = client.get(f"/targets/{target_id}/history?hours=24")

        assert '<option value="printer" selected>printer</option>' in targets.text
        assert "Принтер бухгалтерии" in dashboard.text
        assert ">Принтер<" in dashboard.text
        assert "Принтеры" in reports.text
        assert "Принтеры" in history.text
        assert "Чёрный картридж HP 37A" in history.text
        assert "Расходники" in history.text
        assert (
            'class="monitoring-supply-level supply-level-normal" '
            'title="Чёрный картридж HP 37A: 72%"' in dashboard.text
        )
        assert (
            'class="monitoring-supply-level supply-level-warning" '
            'title="Magenta Toner: 18%"' in dashboard.text
        )
        assert (
            'class="monitoring-supply-level supply-level-critical" '
            'title="Yellow Toner: 8%"' in dashboard.text
        )
        assert (
            'class="monitoring-supply-level supply-level-unknown" '
            'title="Cyan Toner: точный процент недоступен"' in dashboard.text
        )
        assert "<b>K</b> 72%" in dashboard.text
        assert "<b>M</b> 18%" in dashboard.text
        assert "<b>Y</b> 8%" in dashboard.text
        assert "<b>C</b> без %" in dashboard.text
        assert f'href="/targets/{target_id}/snmp/supplies"' in dashboard.text
        with factory() as session:
            renamed = session.get(SnmpSupply, black_id)
            assert renamed is not None
            assert renamed.custom_name == "Чёрный картридж HP 37A"
            audit = session.scalar(
                select(AuditLog).where(AuditLog.action == "snmp.supply_name_updated")
            )
            assert audit is not None
    finally:
        app.dependency_overrides.clear()


def test_dashboard_declares_an_icon_for_each_target_kind() -> None:
    icons = Path("src/monitoring/templates/_target_kind_icon.html").read_text(encoding="utf-8")
    dashboard = Path("src/monitoring/templates/dashboard.html").read_text(encoding="utf-8")

    assert TargetKind.UPS.value == "ups"
    for kind in ("server", "computer", "network", "printer", "ups", "camera", "website"):
        assert f"kind == '{kind}'" in icons
    assert "{% else %}" in icons
    assert "target-kind-icon-{{ kind }}" in icons
    assert 'from "_target_kind_icon.html" import target_kind_icon' in dashboard
    assert dashboard.count("target_kind_icon(target.kind)") == 2
    assert '<option value="ups"' in dashboard
    assert "'ups':'ИБП'" in dashboard
