import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from monitoring.checks.directory import DirectoryFile, evaluate_files
from monitoring.checks.registry import CheckerRegistry
from monitoring.db import Base
from monitoring.models import CheckStatus, MonitorTarget, Site, TargetCheck
from monitoring.services.directory_monitoring import normalize_directory_fields
from monitoring.services.monitoring import MonitoringService
from monitoring.services.target_health import _service_status

NOW = datetime(2026, 9, 1, 23, 0, tzinfo=UTC)


def _file(name: str, hours_ago: float, size: int = 100) -> DirectoryFile:
    return DirectoryFile(name, NOW - timedelta(hours=hours_ago), size)


def test_directory_defaults_and_unc_username() -> None:
    config = normalize_directory_fields(
        checker_type="directory",
        path=r"\\SERVER\Backup",
        pattern="",
        period_hours=None,
        show_last=None,
        username=" user ",
    )
    assert config is not None
    assert (config.pattern, config.period_hours, config.show_last, config.username) == (
        "*", 24, 0, "user"
    )


def test_directory_rejects_windows_local_drive_path() -> None:
    with pytest.raises(ValueError, match="UNC"):
        normalize_directory_fields(
            checker_type="directory", path=r"D:\Backup", pattern="*",
            period_hours=24, show_last=0, username=None,
        )


def test_directory_freshness_and_display_limit_are_independent() -> None:
    result = evaluate_files(
        (_file("old.bak", 30), _file("fresh.bak", 2), _file("ignore.txt", 1)),
        pattern="*.bak", period_hours=24, show_last=1, now=NOW, latency_ms=5,
    )
    assert result.outcome.status == CheckStatus.UP
    assert result.recent_count == 1
    assert [item.name for item in result.files_for_ui] == ["fresh.bak"]


def test_directory_no_fresh_file_keeps_old_metadata_for_ui() -> None:
    result = evaluate_files(
        (_file("old1.bak", 25), _file("old2.bak", 48)),
        pattern="*.bak", period_hours=24, show_last=0, now=NOW, latency_ms=5,
    )
    assert result.outcome.status == CheckStatus.DOWN
    assert result.recent_count == 0
    assert len(result.files_for_ui) == 2


def test_directory_check_reuses_secondary_result_and_runtime(tmp_path) -> None:
    (tmp_path / "backup.bak").write_text("metadata only")
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        target = MonitorTarget(site=Site(name="Site"), name="Server", address="127.0.0.1", port=80)
        check = TargetCheck(
            target=target, name="Backup", checker_type="directory", port=1,
            directory_path=str(tmp_path), directory_pattern="*.bak",
            directory_period_hours=24, directory_show_last=0,
        )
        session.add_all((target, check))
        session.commit()
        outcome = asyncio.run(
            MonitoringService(CheckerRegistry(), timeout_seconds=2, max_parallel_checks=1)
            .check_target_check(target, check)
        )
        assert outcome.status == CheckStatus.UP
        MonitoringService(CheckerRegistry(), 2, 1).save_target_check_result(
            session, target.id, check.id, outcome, expected_config_version=check.config_version
        )
        session.refresh(check)
        assert check.directory_recent_count == 1
        assert check.directory_last_files and check.directory_last_files[0]["name"] == "backup.bak"


@pytest.mark.parametrize(
    ("message", "label"),
    [
        ("Каталог недоступен", "Каталог недоступен"),
        ("За последние 24 ч новые файлы не обнаружены", "Нет свежих файлов"),
    ],
)
def test_directory_down_labels_distinguish_access_and_freshness(message: str, label: str) -> None:
    target = MonitorTarget(name="Server", address="127.0.0.1", port=80, enabled=True)
    check = TargetCheck(
        target=target,
        name="Backup",
        checker_type="directory",
        port=1,
        enabled=True,
        config_version=1,
    )
    from monitoring.models import TargetCheckResult

    result = TargetCheckResult(check=check, status="down", config_version=1, message=message)
    service = _service_status(
        check=check, target=target, availability="up", primary_result=None,
        secondary_result=result, open_check_incident=False,
    )
    assert service.label == label
