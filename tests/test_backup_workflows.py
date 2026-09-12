import hashlib
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session

from monitoring.config import Settings
from monitoring.db import Base
from monitoring.models import (
    AppSetting,
    AuditLog,
    CheckResult,
    Incident,
    MonitorTarget,
    PortalMetric,
    Site,
    SnmpConfig,
    SnmpInterface,
    SnmpInterfaceSample,
    SnmpMetric,
    SnmpSample,
    SnmpSupply,
    SnmpThreshold,
    TargetCheck,
    TargetCheckResult,
    User,
    UserRole,
    WorkSchedule,
)
from monitoring.services.audit import audit_details_for_table, format_audit_entry_text, write_audit
from monitoring.services.auth import hash_password
from monitoring.services.backups import (
    DEFAULT_SETTING_VALUES,
    EXPECTED_ALEMBIC_REVISION,
    BackupError,
    check_database_integrity,
    create_backup,
    inspect_backup,
    restore_backup,
)
from monitoring.services.secrets import encrypt_secret
from monitoring.services.target_checks import ensure_primary_check


def _fresh_database():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        connection.execute(
            text("INSERT INTO alembic_version(version_num) VALUES (:revision)"),
            {"revision": EXPECTED_ALEMBIC_REVISION},
        )
    with Session(engine) as session:
        session.add(WorkSchedule(id=0, name="Круглосуточно", is_24x7=True, built_in=True))
        for key, value in DEFAULT_SETTING_VALUES.items():
            session.add(AppSetting(key=key, value=value, description=""))
        session.add(
            User(
                username="admin",
                password_hash=hash_password("admin"),
                role=UserRole.ADMIN,
                active=True,
                must_change_default_password=True,
            )
        )
        session.commit()
    return engine


def test_database_integrity_requires_current_alembic_revision() -> None:
    engine = _fresh_database()
    with Session(engine) as session:
        current = check_database_integrity(session)
        assert not any(issue.startswith("Версия схемы базы:") for issue in current.issues)

        session.execute(text("UPDATE alembic_version SET version_num = 'invalid'"))
        stale = check_database_integrity(session)

    assert stale.ok is False
    assert f"Версия схемы базы: invalid, ожидается {EXPECTED_ALEMBIC_REVISION}" in stale.issues


def test_backup_roundtrip_configuration_and_full(tmp_path: Path) -> None:
    engine = _fresh_database()
    settings = Settings(
        environment="development",
        database_url="sqlite://",
        secret_key="release-056-test-secret",
        backup_dir=str(tmp_path),
    )
    with Session(engine, expire_on_commit=False) as session:
        schedule = WorkSchedule(name="Магазин", monday_start="09:00", monday_end="18:00")
        site = Site(name="Филиал", schedule=schedule)
        target = MonitorTarget(
            site=site,
            name="Камера входа",
            kind="camera",
            checker_type="tcp",
            address="192.0.2.10",
            port=554,
            interval_seconds=300,
            comment="Комментарий",
        )
        session.add(target)
        session.flush()
        ensure_primary_check(session, target)
        target.unstable_pending_down = True
        target.unstable_until = datetime(2026, 9, 1, 12, tzinfo=UTC)
        service_check = TargetCheck(
            target_id=target.id,
            name="Web service",
            checker_type="https",
            port=443,
            enabled=True,
            is_primary=False,
            display_order=1,
            http_expected_status=200,
            http_content_contains="healthy",
            http_content_not_contains="error",
            http_max_response_ms=250.0,
            tls_monitor_enabled=True,
            tls_warning_days=30,
            tls_critical_days=7,
        )
        dns_check = TargetCheck(
            target_id=target.id,
            name="DNS A",
            checker_type="dns",
            port=53,
            enabled=True,
            is_primary=False,
            display_order=2,
            dns_name="example.com",
            dns_record_type="A",
            dns_expected_address="192.0.2.1",
            dns_max_response_ms=250.0,
        )
        session.add(service_check)
        session.add(dns_check)
        session.flush()
        service_check.unstable_pending_down = True
        service_check.unstable_until = datetime(2026, 9, 1, 12, tzinfo=UTC)
        session.add(
            TargetCheckResult(
                check_id=service_check.id,
                status="up",
                latency_ms=2.5,
                message="TCP-соединение установлено",
                tls_not_after=datetime(2026, 12, 1, tzinfo=UTC),
                tls_days_remaining=90.0,
                tls_health="ok",
            )
        )
        session.add(CheckResult(target_id=target.id, status="up", latency_ms=3.0, message="ok"))
        snmp_config = SnmpConfig(
            target_id=target.id,
            enabled=True,
            version="v1",
            community_encrypted=encrypt_secret(settings, "private-community"),
            sys_name="switch",
            last_status="ok",
        )
        session.add(snmp_config)
        session.flush()
        snmp_metric = SnmpMetric(
            target_id=target.id,
            oid="1.3.6.1.4.1.1.0",
            name="Counter",
            detected_type="Counter64",
            last_value="99",
            last_numeric_value=99,
        )
        session.add(snmp_metric)
        derived_metric = SnmpMetric(
            target_id=target.id,
            source_kind="formula",
            formula="round(hr_storage_free_bytes(1) / MiB, 1)",
            name="Свободная память",
            unit="MiB",
            detected_type="Formula",
            last_value="12.5",
            last_numeric_value=12.5,
            display_order=2,
        )
        session.add(derived_metric)
        session.flush()
        session.add(SnmpSample(metric_id=snmp_metric.id, value=99))
        session.add(SnmpSample(metric_id=derived_metric.id, value=12.5))
        interface = SnmpInterface(
            target_id=target.id,
            if_index=1,
            if_name="ether1",
            if_alias="WAN",
            speed_bps=1_000_000_000,
            admin_status=1,
            oper_status=1,
            traffic_counter_mode="hc64",
            in_octets="1000000",
            out_octets="2000000",
            traffic_uptime_ticks=12345,
            rx_bps=100_000,
            tx_bps=200_000,
            in_errors=1,
            out_errors=2,
            in_discards=3,
            out_discards=4,
            monitor_enabled=True,
            present=True,
        )
        session.add(interface)
        session.flush()
        session.add(
            SnmpInterfaceSample(
                interface_id=interface.id,
                rx_bps=100_000,
                tx_bps=200_000,
                in_errors=1,
                out_errors=2,
                in_discards=3,
                out_discards=4,
            )
        )
        supply = SnmpSupply(
            target_id=target.id,
            hr_device_index=7,
            supply_index=1,
            supply_class=3,
            supply_type=3,
            description="Black Toner",
            custom_name="Чёрный картридж",
            unit_code=19,
            max_capacity=100,
            level=42,
            percent_remaining=42,
            level_state="ok",
            present=True,
        )
        session.add(supply)
        session.flush()
        session.add(
            SnmpThreshold(
                target_id=target.id,
                source_kind="supply",
                supply_id=supply.id,
                field="percent",
                operator="lt",
                warning_value=20,
                critical_value=10,
                current_level="normal",
            )
        )
        session.add(
            Incident(target_id=target.id, status="open", failure_count=2, last_message="test")
        )
        write_audit(
            session,
            "target.updated",
            entity_type="target",
            entity_id=target.id,
            entity_name=target.name,
            details={"comment": {"old": "", "new": "Комментарий"}},
        )
        session.add(
            PortalMetric(
                cpu_percent=1,
                memory_percent=2,
                disk_percent=3,
                uptime_seconds=4,
                bytes_sent=5,
                bytes_received=6,
                packets_sent=7,
                packets_received=8,
            )
        )
        session.commit()

        config_backup = create_backup(session, settings, backup_type="configuration")
        full_backup = create_backup(session, settings, backup_type="full")
        assert config_backup.integrity_ok is True and full_backup.integrity_ok is True

        # Configuration restore preserves only configuration and starts operational data from zero.
        restore_backup(session, settings, config_backup.path)
        session.commit()
        session.expire_all()
        assert session.scalar(select(func.count(MonitorTarget.id))) == 1
        assert session.scalar(select(func.count(CheckResult.id))) == 0
        assert session.scalar(select(func.count(TargetCheck.id))) == 3
        assert session.scalar(select(func.count(TargetCheckResult.id))) == 0
        restored_target = session.scalar(select(MonitorTarget))
        assert restored_target is not None
        assert restored_target.unstable_pending_down is False
        assert restored_target.unstable_until is None
        restored_service_check = session.scalar(
            select(TargetCheck).where(TargetCheck.name == "Web service")
        )
        assert restored_service_check is not None
        assert restored_service_check.unstable_pending_down is False
        assert restored_service_check.unstable_until is None
        assert restored_service_check.port == 443
        assert restored_service_check.http_expected_status == 200
        assert restored_service_check.http_content_contains == "healthy"
        assert restored_service_check.http_content_not_contains == "error"
        assert restored_service_check.http_max_response_ms == 250.0
        assert (
            restored_service_check.tls_monitor_enabled,
            restored_service_check.tls_warning_days,
            restored_service_check.tls_critical_days,
        ) == (True, 30, 7)
        restored_dns_check = session.scalar(select(TargetCheck).where(TargetCheck.name == "DNS A"))
        assert restored_dns_check is not None
        assert (
            restored_dns_check.dns_name,
            restored_dns_check.dns_record_type,
            restored_dns_check.dns_expected_address,
            restored_dns_check.dns_max_response_ms,
        ) == ("example.com", "A", "192.0.2.1", 250.0)
        assert session.scalar(select(func.count(Incident.id))) == 0
        assert session.scalar(select(func.count(AuditLog.id))) == 0
        assert session.scalar(select(func.count(PortalMetric.id))) == 0
        restored_config = session.get(SnmpConfig, target.id)
        assert restored_config is not None and restored_config.enabled is True
        assert restored_config.version == "v1"
        assert restored_config.sys_name is None and restored_config.last_status == "never"
        restored_interface = session.scalar(select(SnmpInterface))
        assert restored_interface is not None
        assert restored_interface.monitor_enabled is True
        assert restored_interface.if_name == "ether1"
        assert restored_interface.present is False
        assert restored_interface.admin_status is None
        assert restored_interface.oper_status is None
        assert restored_interface.traffic_counter_mode is None
        assert restored_interface.in_octets is None
        assert restored_interface.rx_bps is None
        assert restored_interface.in_errors is None
        restored_supply = session.scalar(select(SnmpSupply))
        assert restored_supply is not None
        assert restored_supply.description == "Black Toner"
        assert restored_supply.custom_name == "Чёрный картридж"
        assert restored_supply.present is False
        assert restored_supply.level is None
        assert restored_supply.percent_remaining is None
        restored_threshold = session.scalar(
            select(SnmpThreshold).where(SnmpThreshold.source_kind == "supply")
        )
        assert restored_threshold is not None
        assert restored_threshold.supply_id == restored_supply.id
        assert restored_threshold.warning_value == 20
        assert restored_threshold.critical_value == 10
        assert session.scalar(select(func.count(SnmpSample.id))) == 0
        restored_formula = session.scalar(
            select(SnmpMetric).where(SnmpMetric.source_kind == "formula")
        )
        assert restored_formula is not None
        assert restored_formula.formula == "round(hr_storage_free_bytes(1) / MiB, 1)"
        assert restored_formula.last_value is None
        assert session.scalar(select(func.count(SnmpInterfaceSample.id))) == 0
        assert check_database_integrity(session).ok is True

        # Full restore brings operational history back as well.
        restore_backup(session, settings, full_backup.path)
        session.commit()
        session.expire_all()
        assert session.scalar(select(func.count(CheckResult.id))) == 1
        restored_target = session.scalar(select(MonitorTarget))
        assert restored_target is not None
        assert restored_target.unstable_pending_down is True
        assert restored_target.unstable_until is not None
        assert restored_target.unstable_until.replace(tzinfo=UTC) == datetime(
            2026, 9, 1, 12, tzinfo=UTC
        )
        assert session.scalar(select(func.count(TargetCheck.id))) == 3
        restored_dns_check = session.scalar(select(TargetCheck).where(TargetCheck.name == "DNS A"))
        assert restored_dns_check is not None
        assert restored_dns_check.dns_name == "example.com"
        restored_service_check = session.scalar(
            select(TargetCheck).where(TargetCheck.name == "Web service")
        )
        assert restored_service_check is not None
        assert restored_service_check.unstable_pending_down is True
        assert restored_service_check.unstable_until is not None
        assert restored_service_check.unstable_until.replace(tzinfo=UTC) == datetime(
            2026, 9, 1, 12, tzinfo=UTC
        )
        assert session.scalar(select(func.count(TargetCheckResult.id))) == 1
        restored_check_result = session.scalar(select(TargetCheckResult))
        assert restored_check_result is not None
        assert restored_check_result.tls_days_remaining == 90.0
        assert restored_check_result.tls_health == "ok"
        assert session.scalar(select(func.count(Incident.id))) == 1
        assert session.scalar(select(func.count(AuditLog.id))) == 1
        assert session.scalar(select(func.count(PortalMetric.id))) == 1
        assert session.scalar(select(func.count(SnmpSample.id))) == 2
        restored_formula = session.scalar(
            select(SnmpMetric).where(SnmpMetric.source_kind == "formula")
        )
        assert restored_formula is not None
        assert restored_formula.last_value == "12.5"
        assert session.scalar(select(func.count(SnmpInterfaceSample.id))) == 1
        restored_interface = session.scalar(select(SnmpInterface))
        assert restored_interface is not None
        assert restored_interface.monitor_enabled is True
        assert restored_interface.present is True
        assert restored_interface.admin_status == 1
        assert restored_interface.oper_status == 1
        assert restored_interface.traffic_counter_mode == "hc64"
        assert restored_interface.in_octets == "1000000"
        assert restored_interface.out_octets == "2000000"
        assert restored_interface.rx_bps == 100_000
        assert restored_interface.tx_bps == 200_000
        assert restored_interface.in_errors == 1
        assert restored_interface.out_discards == 4
        restored_supply = session.scalar(select(SnmpSupply))
        assert restored_supply is not None
        assert restored_supply.present is True
        assert restored_supply.custom_name == "Чёрный картридж"
        assert restored_supply.level == 42
        assert restored_supply.percent_remaining == 42
        restored_config = session.get(SnmpConfig, target.id)
        assert restored_config is not None and restored_config.sys_name == "switch"
        assert "private-community" not in restored_config.community_encrypted
        assert check_database_integrity(session).ok is True


def test_backup_requires_exact_current_version(tmp_path: Path) -> None:
    engine = _fresh_database()
    settings = Settings(
        environment="development", database_url="sqlite://", backup_dir=str(tmp_path)
    )
    with Session(engine) as session:
        info = create_backup(session, settings, backup_type="configuration")
    changed = tmp_path / "old-version.mxbak"
    with (
        zipfile.ZipFile(info.path, "r") as source,
        zipfile.ZipFile(changed, "w", zipfile.ZIP_DEFLATED) as target,
    ):
        for item in source.infolist():
            if item.filename in {"manifest.json", "manifest.sha256"}:
                continue
            target.writestr(item, source.read(item.filename))
        manifest = json.loads(source.read("manifest.json"))
        manifest["app_version"] = "0.0.0"
        manifest_bytes = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
        target.writestr("manifest.json", manifest_bytes)
        target.writestr("manifest.sha256", hashlib.sha256(manifest_bytes).hexdigest())
    inspected = inspect_backup(changed, verify_integrity=True)
    assert inspected.compatible is False
    assert "0.0.0" in inspected.message and "0.8.5" in inspected.message


def test_configuration_and_full_backup_preserve_site_entry_flag(tmp_path: Path) -> None:
    engine = _fresh_database()
    settings = Settings(
        environment="development", database_url="sqlite://", backup_dir=str(tmp_path)
    )
    with Session(engine) as session:
        site = Site(name="Филиал")
        target = MonitorTarget(
            site=site,
            name="Router",
            kind="network",
            checker_type="icmp",
            address="192.0.2.1",
            port=1,
            is_site_entry=True,
        )
        session.add(target)
        session.commit()
        configuration = create_backup(session, settings, backup_type="configuration")
        full = create_backup(session, settings, backup_type="full")

        target.is_site_entry = False
        session.commit()
        restore_backup(session, settings, configuration.path)
        restored = session.scalar(select(MonitorTarget).where(MonitorTarget.name == "Router"))
        assert restored is not None and restored.is_site_entry is True

        restored.is_site_entry = False
        session.commit()
        restore_backup(session, settings, full.path)
        restored = session.scalar(select(MonitorTarget).where(MonitorTarget.name == "Router"))
        assert restored is not None and restored.is_site_entry is True


def test_configuration_backup_requires_all_current_sections(tmp_path: Path) -> None:
    engine = _fresh_database()
    settings = Settings(
        environment="development", database_url="sqlite://", backup_dir=str(tmp_path)
    )
    with Session(engine) as session:
        original = create_backup(session, settings, backup_type="configuration")
    legacy = tmp_path / "configuration-without-interfaces.mxbak"
    with (
        zipfile.ZipFile(original.path, "r") as source,
        zipfile.ZipFile(legacy, "w", zipfile.ZIP_DEFLATED) as target,
    ):
        manifest = json.loads(source.read("manifest.json"))
        manifest["entries"] = [
            entry for entry in manifest["entries"] if entry["table"] != "snmp_interfaces"
        ]
        for item in source.infolist():
            if item.filename in {"manifest.json", "manifest.sha256", "data/snmp_interfaces.jsonl"}:
                continue
            target.writestr(item, source.read(item.filename))
        manifest_bytes = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
        target.writestr("manifest.json", manifest_bytes)
        target.writestr("manifest.sha256", hashlib.sha256(manifest_bytes).hexdigest())
    with Session(engine) as session, pytest.raises(BackupError, match="snmp_interfaces"):
        restore_backup(session, settings, legacy)


def test_full_backup_requires_all_current_sections(tmp_path: Path) -> None:
    engine = _fresh_database()
    settings = Settings(
        environment="development", database_url="sqlite://", backup_dir=str(tmp_path)
    )
    with Session(engine) as session:
        original = create_backup(session, settings, backup_type="full")
    legacy = tmp_path / "full-without-interface-samples.mxbak"
    with (
        zipfile.ZipFile(original.path, "r") as source,
        zipfile.ZipFile(legacy, "w", zipfile.ZIP_DEFLATED) as target,
    ):
        manifest = json.loads(source.read("manifest.json"))
        manifest["entries"] = [
            entry for entry in manifest["entries"] if entry["table"] != "snmp_interface_samples"
        ]
        for item in source.infolist():
            if item.filename in {
                "manifest.json",
                "manifest.sha256",
                "data/snmp_interface_samples.jsonl",
            }:
                continue
            target.writestr(item, source.read(item.filename))
        manifest_bytes = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
        target.writestr("manifest.json", manifest_bytes)
        target.writestr("manifest.sha256", hashlib.sha256(manifest_bytes).hexdigest())
    with Session(engine) as session, pytest.raises(BackupError, match="snmp_interface_samples"):
        restore_backup(session, settings, legacy)


def test_configuration_backup_requires_target_checks(tmp_path: Path) -> None:
    engine = _fresh_database()
    settings = Settings(
        environment="development", database_url="sqlite://", backup_dir=str(tmp_path)
    )
    with Session(engine) as session:
        site = Site(name="Филиал")
        target = MonitorTarget(
            site=site,
            name="Старый объект",
            checker_type="tcp",
            address="192.0.2.55",
            port=1541,
            interval_seconds=300,
        )
        session.add(target)
        session.commit()
        original = create_backup(session, settings, backup_type="configuration")

    legacy = tmp_path / "configuration-without-target-checks.mxbak"
    with (
        zipfile.ZipFile(original.path, "r") as source,
        zipfile.ZipFile(legacy, "w", zipfile.ZIP_DEFLATED) as target_zip,
    ):
        manifest = json.loads(source.read("manifest.json"))
        manifest["entries"] = [
            entry for entry in manifest["entries"] if entry["table"] != "target_checks"
        ]
        for item in source.infolist():
            if item.filename in {
                "manifest.json",
                "manifest.sha256",
                "data/target_checks.jsonl",
            }:
                continue
            target_zip.writestr(item, source.read(item.filename))
        manifest_bytes = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
        target_zip.writestr("manifest.json", manifest_bytes)
        target_zip.writestr("manifest.sha256", hashlib.sha256(manifest_bytes).hexdigest())

    with Session(engine) as session, pytest.raises(BackupError, match="target_checks"):
        restore_backup(session, settings, legacy)


def test_database_integrity_rejects_previous_alembic_head() -> None:
    engine = _fresh_database()
    with engine.begin() as connection:
        connection.execute(text("UPDATE alembic_version SET version_num = 'invalid'"))
    with Session(engine) as session:
        result = check_database_integrity(session)
        assert result.ok is False
    assert any(f"ожидается {EXPECTED_ALEMBIC_REVISION}" in issue for issue in result.issues)


def test_audit_snapshot_and_compact_details() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        entry = write_audit(
            session,
            "target.updated",
            entity_type="target",
            entity_id=6,
            entity_name="Камера входа",
            details={"comment": {"old": "", "new": "У входа"}},
        )
        session.flush()
        text_value = format_audit_entry_text(entry, "admin", lambda _: "17.08.2026 22:00")
        assert "Событие: Обновление объекта" in text_value
        assert "Объект изменения: Объект Камера входа · ID 6" in text_value
        assert "Инициатор: admin" in text_value
        compact = audit_details_for_table(entry.details)
        assert "_entity_name" not in compact
        assert "Камера входа" not in compact


def test_ui_contracts() -> None:
    root = Path("src/monitoring")
    settings = (root / "templates/settings.html").read_text(encoding="utf-8")
    targets = (root / "templates/targets.html").read_text(encoding="utf-8")
    audit = (root / "templates/audit.html").read_text(encoding="utf-8")
    css = (root / "static/app.css").read_text(encoding="utf-8")
    js = (root / "static/app.js").read_text(encoding="utf-8")
    users = (root / "templates/users.html").read_text(encoding="utf-8")

    assert "Экспорт и импорт" not in targets
    assert "Создать бэкап конфигурации" in settings
    assert "Создать полный бэкап" in settings
    assert "Проверить целостность базы" in settings
    assert "Бэкап другой версии восстановить нельзя" in settings
    assert "data-no-async" in settings
    assert "audit_details_for_table" in Path("src/monitoring/web/admin_routes.py").read_text(
        encoding="utf-8"
    )
    assert "table_details" in audit
    assert "toast-warning-password" in js
    assert "Используется стандартный пароль admin" in js
    assert 'data-confirm="Удалить пользователя' in users
    assert 'title="Проверить доступность сейчас"' in (
        root / "templates/_target_tools.html"
    ).read_text(encoding="utf-8")
    assert "-webkit-appearance: none;" in css
    assert ".incident-last-error { grid-column: 1 / -1; }" in css
    assert ".audit-export-bar .button { flex: 0 0 auto; width: auto; }" in css
