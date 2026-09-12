from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

from monitoring.services.exports import availability_pdf_bytes, xlsx_sheets_bytes

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "src/monitoring/templates"
CSS = (ROOT / "src/monitoring/static/app.css").read_text(encoding="utf-8")
ADMIN = (ROOT / "src/monitoring/web/admin_routes.py").read_text(encoding="utf-8")
ROUTES = (ROOT / "src/monitoring/web/routes.py").read_text(encoding="utf-8")


@dataclass
class SiteRow:
    site_name: str
    up_count: int
    down_count: int
    unknown_count: int
    availability: float | None


@dataclass
class TargetRow:
    target_id: int
    site_name: str
    target_name: str
    kind: str
    up_count: int
    down_count: int
    unknown_count: int
    availability: float | None


def test_sites_schedule_column_is_sortable() -> None:
    template = (TEMPLATES / "sites.html").read_text(encoding="utf-8")
    assert "sortable_header(request, 'График', 'schedule'" in template
    assert '"display_order", "name", "description", "target_count", "schedule", "enabled"' in ADMIN
    assert '"schedule": func.lower(func.coalesce(WorkSchedule.name, "Круглосуточно"))' in ADMIN


def test_timezone_and_schedule_mobile_controls_are_bounded() -> None:
    settings = (TEMPLATES / "settings.html").read_text(encoding="utf-8")
    detect = settings.index("data-detect-timezone")
    input_position = settings.index("data-timezone-input")
    assert detect < input_position
    assert ".timezone-setting-control input {" in CSS
    assert "flex: 0 0 auto;" in CSS
    assert '.schedule-day input[type="time"] {' in CSS
    assert "min-inline-size: 0;" in CSS


def test_audit_and_report_exports_have_expected_controls() -> None:
    audit = (TEMPLATES / "audit.html").read_text(encoding="utf-8")
    reports = (TEMPLATES / "reports.html").read_text(encoding="utf-8")
    assert "/audit/export/xlsx?scope=current" in audit
    assert "/audit/export/json?scope=current" in audit
    assert "/audit/export/xlsx?scope=all" in audit
    assert "/audit/export/json?scope=all" in audit
    assert "/reports/export/xlsx?" in reports
    assert "/reports/export/pdf?" in reports
    assert "def audit_export(" in ADMIN
    assert "def reports_export(" in ROUTES


def test_single_target_manual_check_is_available_as_compact_tool() -> None:
    tools = (TEMPLATES / "_target_tools.html").read_text(encoding="utf-8")
    assert "/checks/targets/{{ target.id }}/run-now" in tools
    assert 'title="Проверить доступность сейчас"' in tools
    assert "async def target_check_run_now(" in ADMIN
    assert "async def run_target_now(" in (ROOT / "src/monitoring/services/scheduler.py").read_text(
        encoding="utf-8"
    )


def test_xlsx_export_supports_multiple_sheets() -> None:
    data = xlsx_sheets_bytes(
        (
            ("Площадки", ("Площадка", "Доступность"), (("Филиал Юг", 99.5),)),
            ("Объекты", ("Объект", "Ошибки"), (("Сервер", 1),)),
        )
    )
    with ZipFile(BytesIO(data)) as archive:
        names = set(archive.namelist())
        assert "xl/worksheets/sheet1.xml" in names
        assert "xl/worksheets/sheet2.xml" in names
        workbook = archive.read("xl/workbook.xml").decode("utf-8")
        assert "Площадки" in workbook
        assert "Объекты" in workbook


def test_pdf_export_contains_a_valid_pdf_document() -> None:
    sites = [SiteRow("Филиал Юг", 100, 1, 0, 99.01)]
    targets = [TargetRow(1, "Филиал Юг", "Основной сервер", "server", 100, 1, 0, 99.01)]
    data = availability_pdf_bytes(
        period_label="7 дней",
        site_label="Все площадки",
        kind_label="Все типы",
        site_rows=sites,
        target_rows=targets,
        kind_labels={"server": "Серверы"},
    )
    assert data.startswith(b"%PDF-")
    assert len(data) > 2000
