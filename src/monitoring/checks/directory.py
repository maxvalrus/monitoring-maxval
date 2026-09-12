"""Read-only local/SMB directory freshness check."""

from __future__ import annotations

import asyncio
import fnmatch
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter

from monitoring.checks.base import CheckOutcome
from monitoring.models import CheckStatus


@dataclass(frozen=True, slots=True)
class DirectoryFile:
    name: str
    modified_at: datetime
    size_bytes: int

    def as_json(self) -> dict[str, object]:
        return {"name": self.name, "modified_at": self.modified_at.astimezone(UTC).isoformat(), "size_bytes": self.size_bytes}


@dataclass(frozen=True, slots=True)
class DirectoryScanResult:
    outcome: CheckOutcome
    accessible: bool
    recent_count: int
    latest_file_at: datetime | None
    files_for_ui: tuple[DirectoryFile, ...]

    @property
    def ok(self) -> bool:
        return self.outcome.status == CheckStatus.UP


def _local_files(path: str) -> tuple[DirectoryFile, ...]:
    if not Path(path).is_dir():
        raise FileNotFoundError(path)
    result = []
    with os.scandir(path) as entries:
        for entry in entries:
            if entry.is_file(follow_symlinks=False):
                stat = entry.stat(follow_symlinks=False)
                result.append(DirectoryFile(entry.name, datetime.fromtimestamp(stat.st_mtime, UTC), int(stat.st_size)))
    return tuple(result)


def evaluate_files(files: tuple[DirectoryFile, ...], *, pattern: str, period_hours: float, show_last: int, now: datetime, latency_ms: float) -> DirectoryScanResult:
    matching = [item for item in files if fnmatch.fnmatchcase(item.name.casefold(), pattern.casefold())]
    matching.sort(key=lambda item: item.modified_at, reverse=True)
    cutoff = now - timedelta(hours=period_hours)
    count = sum(item.modified_at >= cutoff for item in matching)
    shown = tuple(matching if show_last == 0 else matching[:show_last])
    latest = matching[0].modified_at if matching else None
    runtime = {
        "directory_accessible": True,
        "directory_files": tuple(item.as_json() for item in shown),
        "directory_recent_count": count,
        "directory_latest_file_at": latest,
    }
    if count:
        message = f"За последние {period_hours:g} ч: {count}; последний файл: {matching[0].name}"
        return DirectoryScanResult(CheckOutcome(CheckStatus.UP, latency_ms, message, **runtime), True, count, latest, shown)
    return DirectoryScanResult(CheckOutcome(CheckStatus.DOWN, latency_ms, f"За последние {period_hours:g} ч новые файлы не обнаружены", **runtime), True, 0, latest, shown)


# Kept as a small testable pure entry point; scanning itself stays separate.
_filter_and_evaluate = evaluate_files


async def scan_directory(*, path: str, pattern: str, period_hours: float, show_last: int, timeout_seconds: float, username: str | None = None, password: str = "") -> DirectoryScanResult:
    started = perf_counter()
    try:
        if path.startswith("\\\\"):
            files = await asyncio.wait_for(asyncio.to_thread(_smb_files, path, username, password), timeout_seconds)
        else:
            files = await asyncio.wait_for(asyncio.to_thread(_local_files, path), timeout_seconds)
    except TimeoutError:
        return DirectoryScanResult(CheckOutcome(CheckStatus.DOWN, (perf_counter() - started) * 1000, "Каталог недоступен: превышено время ожидания"), False, 0, None, ())
    except Exception:  # noqa: BLE001 - SMB client raises several transport-specific types.
        return DirectoryScanResult(CheckOutcome(CheckStatus.DOWN, (perf_counter() - started) * 1000, "Каталог недоступен"), False, 0, None, ())
    return evaluate_files(files, pattern=pattern, period_hours=period_hours, show_last=show_last, now=datetime.now(UTC), latency_ms=(perf_counter() - started) * 1000)


def _smb_files(path: str, username: str | None, password: str) -> tuple[DirectoryFile, ...]:
    """Use smbclient only for directory metadata; no file is opened or read."""
    import smbclient  # type: ignore[import-not-found]

    server = path[2:].split("\\", 1)[0]
    if not server:
        raise OSError("invalid UNC path")
    smbclient.register_session(server, username=username or "", password=password)
    result = []
    for name in smbclient.listdir(path):
        candidate = path.rstrip("\\") + "\\" + name
        item_stat = smbclient.stat(candidate)
        if stat.S_ISREG(item_stat.st_mode):
            result.append(DirectoryFile(name, datetime.fromtimestamp(item_stat.st_mtime, UTC), int(item_stat.st_size)))
    return tuple(result)
