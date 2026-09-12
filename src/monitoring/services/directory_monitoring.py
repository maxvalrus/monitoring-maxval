"""Validation and runtime helpers for the secondary Directory check."""

from __future__ import annotations

from dataclasses import dataclass

DIRECTORY_CHECKER_TYPE = "directory"


@dataclass(frozen=True, slots=True)
class DirectoryCheckConfig:
    path: str
    pattern: str
    period_hours: float
    show_last: int
    username: str | None


def normalize_directory_fields(
    *, checker_type: str, path: str | None, pattern: str | None,
    period_hours: float | None, show_last: int | None, username: str | None,
) -> DirectoryCheckConfig | None:
    if checker_type != DIRECTORY_CHECKER_TYPE:
        return None
    clean_path = (path or "").strip()
    if not clean_path:
        raise ValueError("Для проверки каталога укажите путь")
    if not (clean_path.startswith("/") or clean_path.startswith("\\\\")):
        raise ValueError("Используйте локальный путь /... или SMB UNC-путь \\SERVER\\Share\\...")
    clean_pattern = (pattern or "*").strip() or "*"
    if len(clean_pattern) > 255 or "/" in clean_pattern or "\\" in clean_pattern:
        raise ValueError("Маска должна быть именем файла без пути и не длиннее 255 символов")
    hours = 24.0 if period_hours is None else float(period_hours)
    if hours <= 0:
        raise ValueError("Контрольный период должен быть больше 0 часов")
    limit = 0 if show_last is None else int(show_last)
    if limit < 0:
        raise ValueError("Количество отображаемых файлов не может быть отрицательным")
    if len(clean_path) > 1024:
        raise ValueError("Путь к каталогу не должен превышать 1024 символа")
    clean_username = (username or "").strip() or None
    if clean_username is not None and len(clean_username) > 255:
        raise ValueError("Имя SMB-пользователя не должно превышать 255 символов")
    return DirectoryCheckConfig(
        clean_path, clean_pattern, hours, limit,
        clean_username if clean_path.startswith("\\\\") else None,
    )


def clear_directory_runtime(check) -> None:
    check.directory_last_files = None
    check.directory_recent_count = None
    check.directory_latest_file_at = None
    check.directory_scanned_at = None


def clear_directory_fields(check) -> None:
    check.directory_path = None
    check.directory_pattern = None
    check.directory_period_hours = None
    check.directory_show_last = None
    check.directory_username = None
    check.directory_password_encrypted = ""
    clear_directory_runtime(check)
