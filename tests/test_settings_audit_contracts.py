import re
from pathlib import Path

from monitoring.models import WorkSchedule
from monitoring.services.audit import audit_changes
from monitoring.services.work_schedules import schedule_summary
from monitoring.web.routes import SETTING_HELP, SMTP_HELP

ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "src/monitoring/static/app.css").read_text(encoding="utf-8")
JS = (ROOT / "src/monitoring/static/app.js").read_text(encoding="utf-8")
TEMPLATES = ROOT / "src/monitoring/templates"


def test_schedule_summary_uses_normative_russian_abbreviations() -> None:
    schedule = WorkSchedule(
        name="Офис",
        monday_start="09:00",
        monday_end="18:00",
        tuesday_start="09:00",
        tuesday_end="18:00",
        wednesday_start="09:00",
        wednesday_end="18:00",
        thursday_start="09:00",
        thursday_end="18:00",
        friday_start="09:00",
        friday_end="18:00",
        saturday_start="10:00",
        saturday_end="16:00",
        sunday_start="10:00",
        sunday_end="16:00",
    )
    summary = schedule_summary(schedule)
    for abbreviation in ("пн.", "вт.", "ср.", "чт.", "пт.", "сб.", "вс."):
        assert abbreviation in summary
    assert "По " not in summary and "Вт " not in summary


def test_sites_table_allocates_all_seven_admin_columns_and_protects_actions() -> None:
    normalized = re.sub(r"\s+", " ", CSS)
    widths = [7, 16, 17, 8, 11, 10, 31]
    for index, width in enumerate(widths, start=1):
        assert (
            f".sites-table-with-actions th:nth-child({index}) {{ width: {width}%; }}" in normalized
        )
    assert sum(widths) == 100
    assert (
        ".sites-table .table-actions .button { white-space: nowrap; overflow-wrap: normal; }"
        in normalized
    )


def test_schedule_edit_actions_share_one_row() -> None:
    template = (TEMPLATES / "schedules.html").read_text(encoding="utf-8")
    normalized = re.sub(r"\s+", " ", CSS)
    assert 'class="schedule-editor-actions"' in template
    assert 'form="schedule-edit-{{ row.schedule.id }}"' in template
    assert template.index("Удалить график") < template.index(
        "Сохранить", template.index("schedule-editor-actions")
    )
    assert ".schedule-editor-actions { margin-top: 14px; display: flex;" in normalized


def test_settings_help_contains_defaults_and_timezone_examples() -> None:
    assert all("По умолчанию:" in text for text in SETTING_HELP.values())
    timezone_help = SETTING_HELP["display_timezone"]
    for example in (
        "Europe/Moscow",
        "Europe/Kaliningrad",
        "Asia/Yekaterinburg",
        "Asia/Novosibirsk",
        "Asia/Irkutsk",
        "Asia/Vladivostok",
    ):
        assert example in timezone_help
    assert all("По умолчанию:" in text for text in SMTP_HELP.values())


def test_timezone_can_be_detected_by_browser_without_auto_saving() -> None:
    template = (TEMPLATES / "settings.html").read_text(encoding="utf-8")
    assert "data-detect-timezone" in template
    assert "data-timezone-input" in template
    assert "Intl.DateTimeFormat().resolvedOptions().timeZone" in JS
    assert "Нажмите «Сохранить»" in JS


def test_object_comment_and_graph_use_compact_tool_buttons() -> None:
    tools = (TEMPLATES / "_target_tools.html").read_text(encoding="utf-8")
    dashboard = (TEMPLATES / "dashboard.html").read_text(encoding="utf-8")
    targets = (TEMPLATES / "targets.html").read_text(encoding="utf-8")
    assert "{% if target.comment %}" in tools
    assert 'class="icon-action comment-action"' in tools
    assert 'class="icon-action" href="/targets/{{ target.id }}/history"' in tools
    assert 'class="monitoring-object-quick-actions"' in dashboard
    assert 'class="icon-action comment-action"' in dashboard
    assert "target_tools(target, True," in targets
    assert '<details class="target-comment">' not in dashboard
    assert ">График</a>" not in targets


def test_audit_changes_keeps_only_old_and_new_values() -> None:
    before = {
        "name": "Филиал Юг",
        "schedule": {"id": 0, "name": "Круглосуточно"},
        "description": "",
    }
    after = {
        "name": "Филиал Юг",
        "schedule": {"id": 2, "name": "Магазины"},
        "description": "Рабочие дни",
    }
    assert audit_changes(before, after) == {
        "description": {"old": "", "new": "Рабочие дни"},
        "schedule": {
            "old": {"id": 0, "name": "Круглосуточно"},
            "new": {"id": 2, "name": "Магазины"},
        },
    }


def test_site_and_schedule_updates_write_change_sets_to_audit() -> None:
    source = (ROOT / "src/monitoring/web/admin_routes.py").read_text(encoding="utf-8")
    assert '"schedule.updated"' in source
    assert '"site.updated"' in source
    assert source.count('details=audit_changes(before, after) or {"unchanged": True}') >= 2
    assert 'return {"id": schedule.id, "name": schedule.name}' in source
