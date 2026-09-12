#!/usr/bin/env python3
"""Запуск тестов Monitoring Maxval по функциональным профилям.

Использование:
    python scripts/test_suite.py smoke
    python scripts/test_suite.py module communication
    python scripts/test_suite.py module web
    python scripts/test_suite.py full
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Критические сценарии запуска, безопасности и основных подсистем.
SMOKE = [
    "tests/test_health.py",
    "tests/test_config.py",
    "tests/test_auth.py",
    "tests/test_registry.py",
    "tests/test_monitoring_service.py",
    "tests/test_reports.py",
    "tests/test_web_auth.py",
    "tests/test_web_concurrency.py",
    "tests/test_backup_workflows.py::test_backup_roundtrip_configuration_and_full",
    "tests/test_communication_foundation.py::test_chat_and_unread_counters",
    "tests/test_communication_lifecycle.py::test_delete_request_hides_then_physically_deletes_old_history_only",
    "tests/test_deleted_user_communication.py::test_deleting_one_user_preserves_chat_for_live_peer",
    "tests/test_https_pwa.py",
    "tests/test_notification_channels.py::test_internal_incident_notifications_ignore_external_master_switch",
    "tests/test_communication_navigation.py::test_notification_links",
]

MODULES = {
    "auth": [
        "tests/test_auth.py",
        "tests/test_web_auth.py",
        "tests/test_web_concurrency.py",
        "tests/test_settings_service.py",
    ],
    "checks": [
        "tests/test_http_checker.py",
        "tests/test_icmp_checker.py",
        "tests/test_rtsp_checker.py",
        "tests/test_tcp_checker.py",
        "tests/test_registry.py",
    ],
    "monitoring": [
        "tests/test_monitoring_service.py",
        "tests/test_incidents.py",
        "tests/test_scheduler.py",
        "tests/test_maintenance.py",
        "tests/test_system_metrics.py",
        "tests/test_monitoring_reporting_ordering.py",
        "tests/test_target_health.py",
        "tests/test_work_schedules_and_transfer.py",
    ],
    "snmp": [
        "tests/test_snmp_core.py",
        "tests/test_snmp_discovery.py",
        "tests/test_snmp_discovery_web.py",
        "tests/test_snmp_graphs.py",
        "tests/test_snmp_interfaces.py",
        "tests/test_snmp_supplies.py",
        "tests/test_snmp_thresholds.py",
        "tests/test_scheduler.py",
        "tests/test_backup_workflows.py",
        "tests/test_web_auth.py",
    ],
    "reports": [
        "tests/test_reports.py",
        "tests/test_exports_and_manual_checks.py",
        "tests/test_web_exports_and_checks.py",
        "tests/test_monitoring_reporting_ordering.py::test_target_history_uses_configured_result_limit_for_statistics",
        "tests/test_monitoring_reporting_ordering.py::test_report_kind_filter_applies_to_targets_and_site_summary",
        "tests/test_target_history_and_chat.py::test_history_manual_check_allows_same_history_return",
        "tests/test_target_history_and_chat.py::test_current_status_uses_latest_result_outside_selected_period",
    ],
    "backups": [
        "tests/test_backup_workflows.py",
        "tests/test_audit_backup_contracts.py",
        "tests/test_communication_foundation.py::test_full_backup_contains_communication_but_configuration_does_not",
        "tests/test_communication_lifecycle.py::test_full_backup_contains_chat_deletion_requests",
    ],
    "communication": [
        "tests/test_communication_foundation.py",
        "tests/test_communication_layout.py",
        "tests/test_communication_lifecycle.py",
        "tests/test_communication_ui_contracts.py",
        "tests/test_notification_channels.py",
        "tests/test_communication_navigation.py",
        "tests/test_chat_settings_ui.py",
        "tests/test_chat_deletion_workflows.py",
        "tests/test_deleted_user_communication.py",
    ],
    "https": [
        "tests/test_https_pwa.py",
        "tests/test_tls_redirect_guard.py",
        "tests/test_push_subscription_management.py",
    ],
    "web": [
        "tests/test_web_pages.py",
        "tests/test_web_admin_actions.py",
        "tests/test_web_auth.py",
        "tests/test_web_incident_filters.py",
        "tests/test_web_pagination.py",
        "tests/test_web_exports_and_checks.py",
        "tests/test_web_user_administration.py",
        "tests/test_target_history_and_chat.py",
        "tests/test_deleted_user_communication.py",
    ],
    "ui": [
        "tests/test_responsive_layout.py",
        "tests/test_responsive_incident_regressions.py",
        "tests/test_mobile_object_regressions.py",
        "tests/test_table_navigation_contracts.py",
        "tests/test_settings_audit_contracts.py",
        "tests/test_communication_layout.py",
        "tests/test_communication_ui_contracts.py",
        "tests/test_chat_settings_ui.py",
        "tests/test_target_history_and_chat.py",
    ],
    "release": [
        "tests/test_packaging.py",
        "tests/test_health.py",
        "tests/test_config.py",
    ],
}


def _run(targets: list[str]) -> int:
    command = [sys.executable, "-m", "pytest", "-q", *targets]
    print("Запуск:", " ".join(command), flush=True)
    return subprocess.call(command, cwd=ROOT)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__.strip())
        return 2

    profile = sys.argv[1].casefold()
    if profile == "smoke":
        return _run(SMOKE)
    if profile == "full":
        return _run([])
    if profile == "module":
        if len(sys.argv) != 3 or sys.argv[2] not in MODULES:
            print("Модули:", ", ".join(sorted(MODULES)))
            return 2
        return _run(MODULES[sys.argv[2]])

    print(f"Неизвестный профиль: {profile}")
    print("Доступно: smoke, module <имя>, full")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
