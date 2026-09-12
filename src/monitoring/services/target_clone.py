"""Copy target configuration without carrying operational state to a new target."""

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from monitoring.models import (
    MonitorTarget,
    SnmpConfig,
    SnmpInterface,
    SnmpMetric,
    SnmpSupply,
    SnmpThreshold,
    TargetCheck,
)


@dataclass(frozen=True, slots=True)
class TargetCloneResult:
    """Counts of copied configuration records, suitable for an audit entry."""

    checks: int = 0
    metrics: int = 0
    interfaces: int = 0
    supplies: int = 0
    thresholds: int = 0
    snmp_configured: bool = False

    def audit_details(self) -> dict[str, int | bool]:
        return {
            "checks": self.checks,
            "metrics": self.metrics,
            "interfaces": self.interfaces,
            "supplies": self.supplies,
            "thresholds": self.thresholds,
            "snmp_configured": self.snmp_configured,
        }


def clone_target_configuration(
    session: Session, source: MonitorTarget, destination: MonitorTarget
) -> TargetCloneResult:
    """Copy reusable target configuration, deliberately excluding runtime data.

    The destination target itself and its primary check are created by the caller.
    This function copies only secondary checks and telemetry definitions.  Samples,
    results, incidents, last values, discovery timestamps and health runtime state
    are intentionally left at their defaults.
    """

    if source.id is None or destination.id is None:
        raise ValueError("Перед копированием оба объекта должны быть сохранены")

    copied_checks = _clone_secondary_checks(session, source.id, destination.id)
    snmp_configured = _clone_snmp_config(session, source.id, destination.id)
    metric_ids = _clone_metrics(session, source.id, destination.id)
    interface_ids = _clone_interfaces(session, source.id, destination.id)
    supply_ids = _clone_supplies(session, source.id, destination.id)
    copied_thresholds = _clone_thresholds(
        session,
        source.id,
        destination.id,
        metric_ids,
        interface_ids,
        supply_ids,
    )
    return TargetCloneResult(
        checks=copied_checks,
        metrics=len(metric_ids),
        interfaces=len(interface_ids),
        supplies=len(supply_ids),
        thresholds=copied_thresholds,
        snmp_configured=snmp_configured,
    )


def _clone_secondary_checks(session: Session, source_id: int, destination_id: int) -> int:
    source_checks = session.scalars(
        select(TargetCheck)
        .where(TargetCheck.target_id == source_id, TargetCheck.is_primary.is_(False))
        .order_by(TargetCheck.display_order, TargetCheck.id)
    ).all()
    for check in source_checks:
        session.add(
            TargetCheck(
                target_id=destination_id,
                name=check.name,
                checker_type=check.checker_type,
                address_override=check.address_override,
                port=check.port,
                path=check.path,
                timeout_seconds=check.timeout_seconds,
                retries=check.retries,
                enabled=check.enabled,
                is_primary=False,
                display_order=check.display_order,
                http_expected_status=check.http_expected_status,
                http_content_contains=check.http_content_contains,
                http_content_not_contains=check.http_content_not_contains,
                http_max_response_ms=check.http_max_response_ms,
                tls_monitor_enabled=check.tls_monitor_enabled,
                tls_warning_days=check.tls_warning_days,
                tls_critical_days=check.tls_critical_days,
                dns_name=check.dns_name,
                dns_record_type=check.dns_record_type,
                dns_expected_address=check.dns_expected_address,
                dns_max_response_ms=check.dns_max_response_ms,
                directory_path=check.directory_path,
                directory_pattern=check.directory_pattern,
                directory_period_hours=check.directory_period_hours,
                directory_show_last=check.directory_show_last,
                directory_username=check.directory_username,
                # Ciphertext is not exposed or decrypted. It is safe to reuse it
                # inside the same application secret domain.
                directory_password_encrypted=check.directory_password_encrypted,
            )
        )
    session.flush()
    return len(source_checks)


def _clone_snmp_config(session: Session, source_id: int, destination_id: int) -> bool:
    source = session.get(SnmpConfig, source_id)
    if source is None:
        return False
    session.add(
        SnmpConfig(
            target_id=destination_id,
            enabled=source.enabled,
            version=source.version,
            port=source.port,
            # Kept encrypted and never placed in the response or audit payload.
            community_encrypted=source.community_encrypted,
            timeout_seconds=source.timeout_seconds,
            retries=source.retries,
            ups_enabled=source.ups_enabled,
        )
    )
    session.flush()
    return True


def _clone_metrics(session: Session, source_id: int, destination_id: int) -> dict[int, int]:
    mapping: dict[int, int] = {}
    for metric in session.scalars(
        select(SnmpMetric)
        .where(SnmpMetric.target_id == source_id)
        .order_by(SnmpMetric.display_order, SnmpMetric.id)
    ):
        copied = SnmpMetric(
            target_id=destination_id,
            oid=metric.oid,
            source_kind=metric.source_kind,
            formula=metric.formula,
            name=metric.name,
            unit=metric.unit,
            enabled=metric.enabled,
            display_order=metric.display_order,
        )
        session.add(copied)
        session.flush()
        mapping[metric.id] = copied.id
    return mapping


def _clone_interfaces(session: Session, source_id: int, destination_id: int) -> dict[int, int]:
    mapping: dict[int, int] = {}
    for interface in session.scalars(
        select(SnmpInterface)
        .where(SnmpInterface.target_id == source_id)
        .order_by(SnmpInterface.if_index, SnmpInterface.id)
    ):
        copied = SnmpInterface(
            target_id=destination_id,
            if_index=interface.if_index,
            if_name=interface.if_name,
            if_descr=interface.if_descr,
            if_alias=interface.if_alias,
            if_type=interface.if_type,
            if_mtu=interface.if_mtu,
            speed_bps=interface.speed_bps,
            phys_address=interface.phys_address,
            monitor_enabled=interface.monitor_enabled,
            present=True,
        )
        session.add(copied)
        session.flush()
        mapping[interface.id] = copied.id
    return mapping


def _clone_supplies(session: Session, source_id: int, destination_id: int) -> dict[int, int]:
    mapping: dict[int, int] = {}
    for supply in session.scalars(
        select(SnmpSupply)
        .where(SnmpSupply.target_id == source_id)
        .order_by(SnmpSupply.hr_device_index, SnmpSupply.supply_index, SnmpSupply.id)
    ):
        copied = SnmpSupply(
            target_id=destination_id,
            hr_device_index=supply.hr_device_index,
            supply_index=supply.supply_index,
            marker_index=supply.marker_index,
            colorant_index=supply.colorant_index,
            supply_class=supply.supply_class,
            supply_type=supply.supply_type,
            description=supply.description,
            custom_name=supply.custom_name,
            unit_code=supply.unit_code,
            present=True,
        )
        session.add(copied)
        session.flush()
        mapping[supply.id] = copied.id
    return mapping


def _clone_thresholds(
    session: Session,
    source_id: int,
    destination_id: int,
    metric_ids: dict[int, int],
    interface_ids: dict[int, int],
    supply_ids: dict[int, int],
) -> int:
    copied_count = 0
    for threshold in session.scalars(
        select(SnmpThreshold)
        .where(SnmpThreshold.target_id == source_id)
        .order_by(SnmpThreshold.id)
    ):
        metric_id = metric_ids.get(threshold.metric_id) if threshold.metric_id else None
        interface_id = (
            interface_ids.get(threshold.interface_id) if threshold.interface_id else None
        )
        supply_id = supply_ids.get(threshold.supply_id) if threshold.supply_id else None
        if threshold.source_kind == "metric" and metric_id is None:
            continue
        if threshold.source_kind == "interface" and interface_id is None:
            continue
        if threshold.source_kind == "supply" and supply_id is None:
            continue
        session.add(
            SnmpThreshold(
                target_id=destination_id,
                source_kind=threshold.source_kind,
                metric_id=metric_id,
                interface_id=interface_id,
                supply_id=supply_id,
                field=threshold.field,
                operator=threshold.operator,
                warning_value=threshold.warning_value,
                critical_value=threshold.critical_value,
                enabled=threshold.enabled,
            )
        )
        copied_count += 1
    session.flush()
    return copied_count
