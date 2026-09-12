from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

from sqlalchemy import DateTime, delete, func, inspect, select, text
from sqlalchemy.orm import Session

from monitoring import __version__
from monitoring.config import Settings
from monitoring.db import Base
from monitoring.models import (
    AppSetting,
    ChatDeletionRequest,
    ChatMessage,
    MonitorTarget,
    PushSubscription,
    Site,
    SnmpConfig,
    User,
    UserNotification,
    UserRole,
    WorkSchedule,
)
from monitoring.services.secrets import decrypt_secret, encrypt_secret
from monitoring.services.smtp_settings import encrypt_smtp_password, load_smtp_settings
from monitoring.services.target_checks import ensure_primary_check

BACKUP_FORMAT_VERSION = 1
BACKUP_EXTENSION = ".mxbak"
EXPECTED_ALEMBIC_REVISION = "0036"

CONFIGURATION_TABLES = (
    "work_schedules",
    "sites",
    "app_settings",
    "users",
    "monitor_targets",
    "target_checks",
    "snmp_configs",
    "snmp_metrics",
    "snmp_interfaces",
    "snmp_supplies",
    "snmp_thresholds",
)
FULL_TABLES = CONFIGURATION_TABLES + (
    "snmp_samples",
    "snmp_interface_samples",
    "snmp_ups_states",
    "snmp_ups_lines",
    "snmp_ups_samples",
    "snmp_ups_events",
    "check_results",
    "target_check_results",
    "incidents",
    "audit_log",
    "portal_metrics",
    "chat_messages",
    "chat_deletion_requests",
    "user_notifications",
    "push_subscriptions",
)
TRANSIENT_TABLES = ("user_sessions", "failed_login_attempts", "login_blocks")
CLEAR_ORDER = (
    "push_subscriptions",
    "user_notifications",
    "chat_deletion_requests",
    "chat_messages",
    "user_sessions",
    "failed_login_attempts",
    "login_blocks",
    "audit_log",
    "snmp_samples",
    "snmp_interface_samples",
    "snmp_ups_samples",
    "snmp_ups_events",
    "snmp_thresholds",
    "snmp_ups_lines",
    "snmp_ups_states",
    "snmp_supplies",
    "snmp_interfaces",
    "snmp_metrics",
    "snmp_configs",
    "incidents",
    "target_check_results",
    "check_results",
    "target_checks",
    "portal_metrics",
    "monitor_targets",
    "sites",
    "work_schedules",
    "users",
    "app_settings",
)
INSERT_ORDER = (
    "work_schedules",
    "sites",
    "app_settings",
    "users",
    "monitor_targets",
    "target_checks",
    "snmp_configs",
    "snmp_metrics",
    "snmp_interfaces",
    "snmp_supplies",
    "snmp_ups_states",
    "snmp_ups_lines",
    "snmp_thresholds",
    "snmp_samples",
    "snmp_interface_samples",
    "snmp_ups_samples",
    "snmp_ups_events",
    "chat_messages",
    "chat_deletion_requests",
    "user_notifications",
    "push_subscriptions",
    "check_results",
    "target_check_results",
    "incidents",
    "audit_log",
    "portal_metrics",
)

DEFAULT_SETTING_VALUES = {
    "default_check_interval_seconds": "300",
    "failures_before_incident": "2",
    "history_retention_days": "90",
    "notifications_enabled": "true",
    "smtp_enabled": "true",
    "smtp_host": "",
    "smtp_port": "587",
    "smtp_username": "",
    "smtp_password": "",
    "smtp_sender": "",
    "smtp_recipient": "",
    "smtp_starttls": "true",
    "display_timezone": "Europe/Moscow",
    "portal_metric_interval_seconds": "60",
    "portal_metric_retention_hours": "168",
    "target_history_max_results": "1000",
    "audit_retention_days": "7",
    "notification_retention_days": "30",
    "snmp_sample_retention_days": "30",
    "snmp_sample_max_per_target": "1000",
    "availability_warning_threshold_percent": "1",
    "availability_good_threshold_percent": "100",
    "min_password_length": "8",
}


@dataclass(frozen=True, slots=True)
class BackupInfo:
    filename: str
    path: Path
    backup_type: str
    creation_mode: str
    app_version: str
    format_version: int
    created_at: datetime
    size_bytes: int
    compatible: bool
    integrity_ok: bool | None = None
    message: str = ""

    @property
    def backup_type_label(self) -> str:
        return "Конфигурация" if self.backup_type == "configuration" else "Полная"

    @property
    def creation_mode_label(self) -> str:
        return "Ручная" if self.creation_mode == "manual" else "Автоматическая"


@dataclass(frozen=True, slots=True)
class IntegrityResult:
    ok: bool
    issues: tuple[str, ...]
    checks_count: int


class BackupError(ValueError):
    pass


def backup_directory(settings: Settings) -> Path:
    path = Path(settings.backup_dir).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    path.mkdir(parents=True, exist_ok=True)
    (path / ".staging").mkdir(parents=True, exist_ok=True)
    return path


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return (
            value.astimezone(UTC).isoformat()
            if value.tzinfo
            else value.replace(tzinfo=UTC).isoformat()
        )
    if isinstance(value, Decimal):
        return str(value)
    return value


def _deserialize_row(table, payload: dict[str, Any], settings: Settings) -> dict[str, Any]:
    row: dict[str, Any] = {}
    for column in table.columns:
        if column.name not in payload:
            continue
        value = payload[column.name]
        if (
            table.name == "app_settings"
            and payload.get("key") == "smtp_password"
            and column.name == "value"
        ):
            value = encrypt_smtp_password(settings, str(value or ""))
        if table.name == "snmp_configs" and column.name == "community_encrypted":
            value = encrypt_secret(settings, str(value or ""))
        if table.name == "target_checks" and column.name == "directory_password_encrypted":
            value = encrypt_secret(settings, str(value or ""))
        if value is not None and isinstance(column.type, DateTime):
            value = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        row[column.name] = value
    return row


def _table_rows(
    session: Session, table_name: str, *, include_deleted_users: bool = True
) -> Iterable[dict[str, Any]]:
    table = Base.metadata.tables[table_name]
    order_columns = list(table.primary_key.columns)
    statement = select(table)
    if table_name == "users" and not include_deleted_users:
        statement = statement.where(table.c.deleted_at.is_(None))
    if order_columns:
        statement = statement.order_by(*order_columns)
    result = session.execute(statement.execution_options(yield_per=1000)).mappings()
    for row in result:
        yield {key: _json_value(value) for key, value in row.items()}


def _manifest_from_zip(path: Path) -> dict[str, Any]:
    try:
        with zipfile.ZipFile(path, "r") as archive:
            return json.loads(archive.read("manifest.json").decode("utf-8"))
    except (OSError, zipfile.BadZipFile, KeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise BackupError("Файл не является корректной резервной копией Мониторинг Maxval") from exc


def _manifest_info(
    path: Path, manifest: dict[str, Any], *, integrity_ok: bool | None = None, message: str = ""
) -> BackupInfo:
    try:
        created_at = datetime.fromisoformat(str(manifest["created_at"]).replace("Z", "+00:00"))
        backup_type = str(manifest["backup_type"])
        creation_mode = str(manifest["creation_mode"])
        app_version = str(manifest["app_version"])
        format_version = int(manifest["format_version"])
    except (KeyError, TypeError, ValueError) as exc:
        raise BackupError("В резервной копии отсутствуют обязательные служебные данные") from exc
    if manifest.get("product") != "monitoring-maxval":
        raise BackupError("Файл создан не системой Мониторинг Maxval")
    if backup_type not in {"configuration", "full"}:
        raise BackupError("Неизвестный тип резервной копии")
    if creation_mode not in {"manual", "automatic"}:
        raise BackupError("Неизвестный способ создания резервной копии")
    compatible_version = app_version == __version__
    compatible = compatible_version and format_version == BACKUP_FORMAT_VERSION
    if not message:
        if format_version != BACKUP_FORMAT_VERSION:
            message = f"Формат бэкапа {format_version}, текущий формат {BACKUP_FORMAT_VERSION}. Восстановление не поддерживается."
        elif not compatible_version:
            message = (
                f"Бэкап создан в версии {app_version}, текущая версия {__version__}. "
                "Восстановление другой версии не поддерживается."
            )
        else:
            message = (
                f"Конфигурационный бэкап версии {app_version} поддерживается."
                if backup_type == "configuration"
                else f"Версия {app_version} совпадает с текущей. Восстановление поддерживается."
            )
    return BackupInfo(
        filename=path.name,
        path=path,
        backup_type=backup_type,
        creation_mode=creation_mode,
        app_version=app_version,
        format_version=format_version,
        created_at=created_at,
        size_bytes=path.stat().st_size,
        compatible=compatible,
        integrity_ok=integrity_ok,
        message=message,
    )


def inspect_backup(path: Path, *, verify_integrity: bool = True) -> BackupInfo:
    manifest = _manifest_from_zip(path)
    info = _manifest_info(path, manifest)
    if not verify_integrity:
        return info
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise BackupError("В резервной копии нет описания данных")
    try:
        with zipfile.ZipFile(path, "r") as archive:
            archive_names = set(archive.namelist())
            if "manifest.sha256" not in archive_names:
                raise BackupError(
                    "В резервной копии отсутствует контрольная сумма служебных данных"
                )
            manifest_bytes = archive.read("manifest.json")
            expected_manifest = archive.read("manifest.sha256").decode("ascii").strip()
            if hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest:
                raise BackupError("Контрольная сумма служебных данных резервной копии не совпадает")
            for item in entries:
                name = str(item["name"])
                expected = str(item["sha256"])
                if name not in archive_names:
                    raise BackupError(f"В резервной копии отсутствует раздел {name}")
                digest = hashlib.sha256()
                with archive.open(name, "r") as source:
                    while chunk := source.read(1024 * 1024):
                        digest.update(chunk)
                if digest.hexdigest() != expected:
                    raise BackupError(f"Контрольная сумма раздела {name} не совпадает")
    except (zipfile.BadZipFile, KeyError, OSError) as exc:
        raise BackupError("Не удалось проверить целостность резервной копии") from exc
    return _manifest_info(path, manifest, integrity_ok=True, message=info.message)


def create_backup(
    session: Session,
    settings: Settings,
    *,
    backup_type: str,
    creation_mode: str = "manual",
) -> BackupInfo:
    if backup_type not in {"configuration", "full"}:
        raise BackupError("Неизвестный тип резервной копии")
    if creation_mode not in {"manual", "automatic"}:
        raise BackupError("Неизвестный способ создания резервной копии")
    root = backup_directory(settings)
    now = datetime.now(UTC)
    short_type = "config" if backup_type == "configuration" else "full"
    filename = f"monitoring-maxval-{short_type}-{now.strftime('%Y%m%d-%H%M%S')}-{creation_mode}{BACKUP_EXTENSION}"
    destination = root / filename
    temporary = root / f".{filename}.{secrets.token_hex(4)}.tmp"
    table_names = CONFIGURATION_TABLES if backup_type == "configuration" else FULL_TABLES
    smtp = load_smtp_settings(session, settings)
    entries: list[dict[str, Any]] = []

    try:
        with zipfile.ZipFile(
            temporary, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True
        ) as archive:
            for table_name in table_names:
                entry_name = f"data/{table_name}.jsonl"
                digest = hashlib.sha256()
                count = 0
                with archive.open(entry_name, "w", force_zip64=True) as target:
                    for row in _table_rows(
                        session,
                        table_name,
                        include_deleted_users=backup_type == "full",
                    ):
                        if table_name == "app_settings" and row.get("key") == "smtp_password":
                            row["value"] = smtp.password
                        if table_name == "target_checks" and row.get(
                            "directory_password_encrypted"
                        ):
                            row["directory_password_encrypted"] = decrypt_secret(
                                settings,
                                str(row["directory_password_encrypted"]),
                                label="Пароль SMB",
                            )
                        if backup_type == "configuration" and table_name in {
                            "monitor_targets",
                            "target_checks",
                        }:
                            row.update(
                                {
                                    "unstable_pending_down": False,
                                    "unstable_until": None,
                                    "directory_last_files": None,
                                    "directory_recent_count": None,
                                    "directory_latest_file_at": None,
                                    "directory_scanned_at": None,
                                }
                            )
                        elif table_name == "snmp_configs":
                            row["community_encrypted"] = decrypt_secret(
                                settings,
                                str(row.get("community_encrypted") or ""),
                                label="Community SNMP",
                            )
                            if backup_type == "configuration":
                                row.update(
                                    {
                                        "last_status": "never",
                                        "last_attempt_at": None,
                                        "last_success_at": None,
                                        "last_error": None,
                                        "sys_name": None,
                                        "sys_descr": None,
                                        "sys_object_id": None,
                                        "sys_uptime_ticks": None,
                                        "system_data_at": None,
                                    }
                                )
                        elif table_name == "snmp_metrics" and backup_type == "configuration":
                            row.update(
                                {
                                    "detected_type": None,
                                    "last_value": None,
                                    "last_numeric_value": None,
                                    "last_collected_at": None,
                                    "last_error": None,
                                }
                            )
                        elif table_name == "snmp_supplies" and backup_type == "configuration":
                            row.update(
                                {
                                    "max_capacity": None,
                                    "level": None,
                                    "percent_remaining": None,
                                    "level_state": "never",
                                    "present": False,
                                    "last_seen_at": None,
                                    "last_polled_at": None,
                                    "last_error": None,
                                }
                            )
                        elif table_name == "snmp_thresholds" and backup_type == "configuration":
                            row.update(
                                {
                                    "current_level": "normal",
                                    "last_value": None,
                                    "last_evaluated_at": None,
                                }
                            )
                        elif table_name == "snmp_interfaces" and backup_type == "configuration":
                            row.update(
                                {
                                    "admin_status": None,
                                    "oper_status": None,
                                    "present": False,
                                    "last_seen_at": None,
                                    "last_polled_at": None,
                                    "last_error": None,
                                    "traffic_counter_mode": None,
                                    "in_octets": None,
                                    "out_octets": None,
                                    "traffic_at": None,
                                    "traffic_uptime_ticks": None,
                                    "rx_bps": None,
                                    "tx_bps": None,
                                    "in_errors": None,
                                    "out_errors": None,
                                    "in_discards": None,
                                    "out_discards": None,
                                    "traffic_error": None,
                                }
                            )
                        line = (
                            json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
                        ).encode("utf-8")
                        target.write(line)
                        digest.update(line)
                        count += 1
                entries.append(
                    {
                        "name": entry_name,
                        "table": table_name,
                        "rows": count,
                        "sha256": digest.hexdigest(),
                    }
                )
            manifest = {
                "product": "monitoring-maxval",
                "format_version": BACKUP_FORMAT_VERSION,
                "app_version": __version__,
                "backup_type": backup_type,
                "creation_mode": creation_mode,
                "created_at": now.isoformat(),
                "portable_smtp_password": True,
                "portable_snmp_community": True,
                "contains_sensitive_data": True,
                "excluded_transient_tables": list(TRANSIENT_TABLES),
                "entries": entries,
            }
            manifest_bytes = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
            archive.writestr("manifest.json", manifest_bytes)
            archive.writestr(
                "manifest.sha256", hashlib.sha256(manifest_bytes).hexdigest().encode("ascii")
            )
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return inspect_backup(destination, verify_integrity=True)


def list_backups(settings: Settings) -> list[BackupInfo]:
    root = backup_directory(settings)
    rows: list[BackupInfo] = []
    for path in root.glob(f"*{BACKUP_EXTENSION}"):
        if not path.is_file():
            continue
        try:
            rows.append(inspect_backup(path, verify_integrity=False))
        except BackupError:
            rows.append(
                BackupInfo(
                    filename=path.name,
                    path=path,
                    backup_type="full",
                    creation_mode="manual",
                    app_version="?",
                    format_version=0,
                    created_at=datetime.fromtimestamp(path.stat().st_mtime, UTC),
                    size_bytes=path.stat().st_size,
                    compatible=False,
                    integrity_ok=False,
                    message="Файл повреждён или имеет неизвестный формат",
                )
            )
    return sorted(rows, key=lambda item: (item.created_at, item.filename), reverse=True)


def save_uploaded_backup(upload_file, settings: Settings) -> tuple[str, BackupInfo]:
    root = backup_directory(settings) / ".staging"
    cleanup_staged_backups(settings)
    token = secrets.token_urlsafe(18).replace("-", "").replace("_", "")
    path = root / f"{token}{BACKUP_EXTENSION}"
    with path.open("wb") as target:
        shutil.copyfileobj(upload_file, target, length=1024 * 1024)
    try:
        info = inspect_backup(path, verify_integrity=True)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return token, info


def staged_backup_path(settings: Settings, token: str) -> Path:
    if not token or not token.isalnum() or len(token) > 80:
        raise BackupError("Некорректный идентификатор загруженной резервной копии")
    path = backup_directory(settings) / ".staging" / f"{token}{BACKUP_EXTENSION}"
    if not path.is_file():
        raise BackupError("Загруженная резервная копия больше недоступна. Загрузите файл снова.")
    return path


def cleanup_staged_backups(settings: Settings) -> None:
    staging = backup_directory(settings) / ".staging"
    threshold = datetime.now(UTC) - timedelta(hours=24)
    for path in staging.glob(f"*{BACKUP_EXTENSION}"):
        try:
            modified = datetime.fromtimestamp(path.stat().st_mtime, UTC)
        except OSError:
            continue
        if modified < threshold:
            path.unlink(missing_ok=True)


def safe_stored_backup_path(settings: Settings, filename: str) -> Path:
    if Path(filename).name != filename or not filename.endswith(BACKUP_EXTENSION):
        raise BackupError("Некорректное имя резервной копии")
    path = backup_directory(settings) / filename
    if not path.is_file():
        raise BackupError("Резервная копия не найдена")
    return path


def delete_backup_file(settings: Settings, filename: str) -> None:
    safe_stored_backup_path(settings, filename).unlink()


def _iter_archive_rows(archive: zipfile.ZipFile, entry_name: str) -> Iterable[dict[str, Any]]:
    with archive.open(entry_name, "r") as source:
        for raw_line in source:
            if not raw_line.strip():
                continue
            payload = json.loads(raw_line.decode("utf-8"))
            if not isinstance(payload, dict):
                raise BackupError(f"Некорректная строка данных в {entry_name}")
            yield payload


def _reset_postgres_sequences(session: Session, table_names: Iterable[str]) -> None:
    bind = session.get_bind()
    if bind.dialect.name != "postgresql":
        return
    for table_name in table_names:
        table = Base.metadata.tables[table_name]
        if "id" not in table.c or not table.c.id.primary_key:
            continue
        session.execute(
            text(
                f"SELECT setval(pg_get_serial_sequence('{table_name}', 'id'), "
                f"CASE WHEN MAX(id) IS NULL OR MAX(id) < 1 THEN 1 ELSE MAX(id) END, "
                f"MAX(id) IS NOT NULL AND MAX(id) >= 1) FROM {table_name}"
            )
        )


def restore_backup(session: Session, settings: Settings, path: Path) -> BackupInfo:
    info = inspect_backup(path, verify_integrity=True)
    if not info.compatible:
        raise BackupError(info.message)
    manifest = _manifest_from_zip(path)
    expected_tables = CONFIGURATION_TABLES if info.backup_type == "configuration" else FULL_TABLES
    entries = {
        str(item.get("table")): str(item.get("name")) for item in manifest.get("entries", [])
    }
    missing = [
        name
        for name in expected_tables
        if name not in entries
    ]
    if missing:
        raise BackupError(
            "В резервной копии отсутствуют обязательные разделы: " + ", ".join(missing)
        )

    # Restore is a full replacement operation. Detach ORM objects loaded by the current
    # request so relationship cascades cannot silently reinsert data that has just been cleared.
    session.flush()
    session.expunge_all()
    for table_name in CLEAR_ORDER:
        session.execute(delete(Base.metadata.tables[table_name]))
    session.flush()

    with zipfile.ZipFile(path, "r") as archive:
        for table_name in INSERT_ORDER:
            entry_name = entries.get(table_name)
            if entry_name is None:
                continue
            table = Base.metadata.tables[table_name]
            batch: list[dict[str, Any]] = []
            for payload in _iter_archive_rows(archive, entry_name):
                batch.append(_deserialize_row(table, payload, settings))
                if len(batch) >= 1000:
                    session.execute(table.insert(), batch)
                    batch.clear()
            if batch:
                session.execute(table.insert(), batch)
    for target in session.scalars(select(MonitorTarget).order_by(MonitorTarget.id)).all():
        ensure_primary_check(session, target)
    existing_setting_keys = set(session.scalars(select(AppSetting.key)).all())
    for key, value in DEFAULT_SETTING_VALUES.items():
        if key not in existing_setting_keys:
            session.add(
                AppSetting(
                    key=key,
                    value=value,
                    description="Восстановлено со значением по умолчанию",
                )
            )
    _reset_postgres_sequences(session, [name for name in INSERT_ORDER if name in entries])
    session.flush()
    integrity = check_database_integrity(session)
    if not integrity.ok:
        raise BackupError(
            "Восстановленные данные не прошли проверку целостности: " + "; ".join(integrity.issues)
        )
    return info


def database_has_meaningful_data(session: Session) -> bool:
    if (session.scalar(select(func.count(Site.id))) or 0) > 0:
        return True
    if (session.scalar(select(func.count(MonitorTarget.id))) or 0) > 0:
        return True
    if (session.scalar(select(func.count(WorkSchedule.id)).where(WorkSchedule.id != 0)) or 0) > 0:
        return True
    if (session.scalar(select(func.count(ChatMessage.id))) or 0) > 0:
        return True
    if (session.scalar(select(func.count(ChatDeletionRequest.id))) or 0) > 0:
        return True
    if (session.scalar(select(func.count(UserNotification.id))) or 0) > 0:
        return True
    if (session.scalar(select(func.count(PushSubscription.id))) or 0) > 0:
        return True
    if (session.scalar(select(func.count(SnmpConfig.target_id))) or 0) > 0:
        return True
    users = session.scalars(select(User).order_by(User.id)).all()
    if len(users) != 1:
        return True
    if users:
        user = users[0]
        if (
            user.username != "admin"
            or user.role != UserRole.ADMIN
            or not user.active
            or not user.must_change_default_password
        ):
            return True
    settings_rows = {item.key: item.value for item in session.scalars(select(AppSetting)).all()}
    for key, expected in DEFAULT_SETTING_VALUES.items():
        actual = settings_rows.get(key)
        if key == "smtp_password":
            if actual:
                return True
        elif actual != expected:
            return True
    return False


def check_database_integrity(session: Session) -> IntegrityResult:
    issues: list[str] = []
    checks = 0
    inspector = inspect(session.connection())
    tables = set(inspector.get_table_names())
    required = set(Base.metadata.tables)
    missing_tables = sorted(required - tables)
    checks += 1
    if missing_tables:
        issues.append("Отсутствуют таблицы: " + ", ".join(missing_tables))
        return IntegrityResult(False, tuple(issues), checks)

    checks += 1
    revision = (
        session.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()
        if "alembic_version" in tables
        else None
    )
    if revision != EXPECTED_ALEMBIC_REVISION:
        issues.append(
            "Версия схемы базы: "
            f"{revision or 'не определена'}, ожидается {EXPECTED_ALEMBIC_REVISION}"
        )

    for table_name, table in Base.metadata.tables.items():
        checks += 1
        actual_columns = {column["name"] for column in inspector.get_columns(table_name)}
        expected_columns = {column.name for column in table.columns}
        missing_columns = sorted(expected_columns - actual_columns)
        if missing_columns:
            issues.append(f"Таблица {table_name}: отсутствуют поля {', '.join(missing_columns)}")

    checks += 1
    admin_count = (
        session.scalar(
            select(func.count(User.id)).where(User.active.is_(True), User.role == UserRole.ADMIN)
        )
        or 0
    )
    if admin_count < 1:
        issues.append("Нет ни одного активного администратора")

    checks += 1
    always = session.get(WorkSchedule, 0)
    if always is None or not always.built_in or not always.is_24x7:
        issues.append("Встроенный график «Круглосуточно» отсутствует или повреждён")

    checks += 1
    missing_settings = sorted(
        set(DEFAULT_SETTING_VALUES)
        - {item.key for item in session.scalars(select(AppSetting)).all()}
    )
    if missing_settings:
        issues.append("Отсутствуют системные настройки: " + ", ".join(missing_settings))

    orphan_queries = (
        (
            "Площадки с отсутствующим графиком",
            "SELECT COUNT(*) FROM sites s LEFT JOIN work_schedules w ON w.id=s.schedule_id WHERE w.id IS NULL",
        ),
        (
            "Объекты с отсутствующей площадкой",
            "SELECT COUNT(*) FROM monitor_targets t LEFT JOIN sites s ON s.id=t.site_id WHERE s.id IS NULL",
        ),
        (
            "Результаты с отсутствующим объектом",
            "SELECT COUNT(*) FROM check_results r LEFT JOIN monitor_targets t ON t.id=r.target_id WHERE t.id IS NULL",
        ),
        (
            "Проверки с отсутствующим объектом",
            "SELECT COUNT(*) FROM target_checks c LEFT JOIN monitor_targets t ON t.id=c.target_id WHERE t.id IS NULL",
        ),
        (
            "Результаты проверок без проверки",
            "SELECT COUNT(*) FROM target_check_results r LEFT JOIN target_checks c ON c.id=r.check_id WHERE c.id IS NULL",
        ),
        (
            "Инциденты с отсутствующим объектом",
            "SELECT COUNT(*) FROM incidents i LEFT JOIN monitor_targets t ON t.id=i.target_id WHERE t.id IS NULL",
        ),
        (
            "Инциденты со ссылкой на отсутствующую проверку",
            "SELECT COUNT(*) FROM incidents i LEFT JOIN target_checks c ON c.id=i.check_id WHERE i.check_id IS NOT NULL AND c.id IS NULL",
        ),
        (
            "SNMP-конфигурации с отсутствующим объектом",
            "SELECT COUNT(*) FROM snmp_configs c LEFT JOIN monitor_targets t ON t.id=c.target_id WHERE t.id IS NULL",
        ),
        (
            "SNMP-метрики с отсутствующим объектом",
            "SELECT COUNT(*) FROM snmp_metrics m LEFT JOIN monitor_targets t ON t.id=m.target_id WHERE t.id IS NULL",
        ),
        (
            "SNMP-интерфейсы с отсутствующим объектом",
            "SELECT COUNT(*) FROM snmp_interfaces i LEFT JOIN monitor_targets t ON t.id=i.target_id WHERE t.id IS NULL",
        ),
        (
            "SNMP-расходники с отсутствующим объектом",
            "SELECT COUNT(*) FROM snmp_supplies s LEFT JOIN monitor_targets t ON t.id=s.target_id WHERE t.id IS NULL",
        ),
        (
            "UPS-state с отсутствующим объектом",
            "SELECT COUNT(*) FROM snmp_ups_states s LEFT JOIN monitor_targets t ON t.id=s.target_id WHERE t.id IS NULL",
        ),
        (
            "UPS-линии без состояния ИБП",
            "SELECT COUNT(*) FROM snmp_ups_lines l LEFT JOIN snmp_ups_states s ON s.target_id=l.target_id WHERE s.target_id IS NULL",
        ),
        (
            "UPS-samples без состояния ИБП",
            "SELECT COUNT(*) FROM snmp_ups_samples p LEFT JOIN snmp_ups_states s ON s.target_id=p.target_id WHERE s.target_id IS NULL",
        ),
        (
            "SNMP-samples с отсутствующей метрикой",
            "SELECT COUNT(*) FROM snmp_samples s LEFT JOIN snmp_metrics m ON m.id=s.metric_id WHERE m.id IS NULL",
        ),
        (
            "SNMP interface samples с отсутствующим интерфейсом",
            "SELECT COUNT(*) FROM snmp_interface_samples s LEFT JOIN snmp_interfaces i ON i.id=s.interface_id WHERE i.id IS NULL",
        ),
        (
            "Сессии с отсутствующим пользователем",
            "SELECT COUNT(*) FROM user_sessions s LEFT JOIN users u ON u.id=s.user_id WHERE u.id IS NULL",
        ),
        (
            "Аудит со ссылкой на отсутствующего пользователя",
            "SELECT COUNT(*) FROM audit_log a LEFT JOIN users u ON u.id=a.user_id WHERE a.user_id IS NOT NULL AND u.id IS NULL",
        ),
        (
            "Сообщения с отсутствующим отправителем",
            "SELECT COUNT(*) FROM chat_messages m LEFT JOIN users u ON u.id=m.sender_id WHERE u.id IS NULL",
        ),
        (
            "Сообщения с отсутствующим получателем",
            "SELECT COUNT(*) FROM chat_messages m LEFT JOIN users u ON u.id=m.recipient_id WHERE u.id IS NULL",
        ),
        (
            "Оповещения с отсутствующим пользователем",
            "SELECT COUNT(*) FROM user_notifications n LEFT JOIN users u ON u.id=n.user_id WHERE u.id IS NULL",
        ),
        (
            "Push-подписки с отсутствующим пользователем",
            "SELECT COUNT(*) FROM push_subscriptions p LEFT JOIN users u ON u.id=p.user_id WHERE u.id IS NULL",
        ),
    )
    for label, query in orphan_queries:
        checks += 1
        count = session.execute(text(query)).scalar_one()
        if count:
            issues.append(f"{label}: {count}")

    return IntegrityResult(not issues, tuple(issues), checks)


def human_size(size: int) -> str:
    units = ("Б", "КБ", "МБ", "ГБ", "ТБ")
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.0f} {unit}" if unit == "Б" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} Б"
