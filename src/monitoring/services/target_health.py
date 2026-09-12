from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from monitoring.models import (
    CheckResult,
    Incident,
    IncidentSourceKind,
    IncidentStatus,
    MonitorTarget,
    SnmpConfig,
    TargetCheck,
    TargetCheckResult,
)
from monitoring.services.site_entry import load_site_entry_gates
from monitoring.services.unstable_link import unstable_link_active


class TargetHealthState(StrEnum):
    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"
    OFFLINE = "offline"
    SITE_UNREACHABLE = "site_unreachable"
    UNKNOWN = "unknown"
    DISABLED = "disabled"
    OFF_HOURS = "off_hours"


HEALTH_LABELS: dict[str, str] = {
    TargetHealthState.OK.value: "OK",
    TargetHealthState.WARNING.value: "Warning",
    TargetHealthState.CRITICAL.value: "Critical",
    TargetHealthState.OFFLINE.value: "Offline",
    TargetHealthState.SITE_UNREACHABLE.value: "Нет связи с площадкой",
    TargetHealthState.UNKNOWN.value: "Нет данных",
    TargetHealthState.DISABLED.value: "Отключён",
    TargetHealthState.OFF_HOURS.value: "Вне графика",
}

HEALTH_FILTER_STATES = frozenset(
    {
        TargetHealthState.OK.value,
        TargetHealthState.WARNING.value,
        TargetHealthState.CRITICAL.value,
        TargetHealthState.OFFLINE.value,
        TargetHealthState.SITE_UNREACHABLE.value,
        TargetHealthState.UNKNOWN.value,
        TargetHealthState.DISABLED.value,
        TargetHealthState.OFF_HOURS.value,
    }
)

HEALTH_SORT_RANK: dict[str, int] = {
    TargetHealthState.OFFLINE.value: 0,
    TargetHealthState.CRITICAL.value: 1,
    TargetHealthState.WARNING.value: 2,
    TargetHealthState.SITE_UNREACHABLE.value: 3,
    TargetHealthState.UNKNOWN.value: 4,
    TargetHealthState.OK.value: 5,
    TargetHealthState.DISABLED.value: 6,
    TargetHealthState.OFF_HOURS.value: 7,
}


SERVICE_LABELS: dict[str, str] = {
    "up": "Доступен",
    "down": "Недоступен",
    "unknown": "Не проверялся",
    "disabled": "Отключён",
    "waiting_primary": "Ожидает основную",
    "waiting_site": "Нет связи с площадкой",
    "off_hours": "Вне графика",
}


@dataclass(frozen=True, slots=True)
class DirectoryFileHealth:
    name: str
    modified_at: datetime
    size_bytes: int


@dataclass(frozen=True, slots=True)
class ServiceHealth:
    check_id: int
    name: str
    is_primary: bool
    checker_type: str
    address: str
    port: int
    path: str
    dns_record_type: str | None
    enabled: bool
    status: str
    label: str
    latency_ms: float | None
    checked_at: datetime | None
    message: str | None
    tls_days_remaining: float | None
    tls_health: str | None
    unstable: bool
    directory_files: tuple[DirectoryFileHealth, ...]
    directory_recent_count: int | None
    directory_scanned_at: datetime | None


@dataclass(frozen=True, slots=True)
class TargetHealth:
    target_id: int
    state: str
    label: str
    availability: str
    reason: str | None
    reason_kind: str | None
    additional_problem_count: int
    services_ok: int | None
    services_total: int
    services: tuple[ServiceHealth, ...]
    unstable: bool


@dataclass(frozen=True, slots=True)
class _Problem:
    severity: str
    reason: str
    kind: str
    order: int


def _value(value: object | None) -> str:
    if value is None:
        return ""
    raw = getattr(value, "value", value)
    return str(raw)


def _normalize_availability(value: object | None) -> str:
    status = _value(value).strip().lower()
    if status in {"up", "down", "off_hours"}:
        return status
    return "unknown"


def _severity(value: object | None, *, source_kind: str) -> str:
    if source_kind == IncidentSourceKind.CHECK.value:
        return TargetHealthState.CRITICAL.value
    severity = _value(value).strip().lower()
    if severity == TargetHealthState.CRITICAL.value:
        return TargetHealthState.CRITICAL.value
    return TargetHealthState.WARNING.value


def _latest_primary_results(
    session: Session, target_ids: Sequence[int]
) -> dict[int, CheckResult]:
    if not target_ids:
        return {}
    ranked = (
        select(
            CheckResult.id.label("result_id"),
            CheckResult.target_id.label("target_id"),
            func.row_number()
            .over(
                partition_by=CheckResult.target_id,
                order_by=(CheckResult.checked_at.desc(), CheckResult.id.desc()),
            )
            .label("row_number"),
        )
        .where(CheckResult.target_id.in_(target_ids))
        .subquery()
    )
    rows = session.scalars(
        select(CheckResult)
        .join(ranked, CheckResult.id == ranked.c.result_id)
        .where(ranked.c.row_number == 1)
    ).all()
    return {row.target_id: row for row in rows}


def _latest_secondary_results(
    session: Session, check_ids: Sequence[int]
) -> dict[int, TargetCheckResult]:
    if not check_ids:
        return {}
    ranked = (
        select(
            TargetCheckResult.id.label("result_id"),
            TargetCheckResult.check_id.label("check_id"),
            func.row_number()
            .over(
                partition_by=TargetCheckResult.check_id,
                order_by=(
                    TargetCheckResult.checked_at.desc(),
                    TargetCheckResult.id.desc(),
                ),
            )
            .label("row_number"),
        )
        .where(TargetCheckResult.check_id.in_(check_ids))
        .subquery()
    )
    rows = session.scalars(
        select(TargetCheckResult)
        .join(ranked, TargetCheckResult.id == ranked.c.result_id)
        .where(ranked.c.row_number == 1)
    ).all()
    return {row.check_id: row for row in rows}


def _incident_problem(
    incident: Incident,
    checks_by_id: Mapping[int, TargetCheck],
    latest_results: Mapping[int, TargetCheckResult],
) -> _Problem | None:
    source_kind = _value(incident.source_kind)
    if source_kind == IncidentSourceKind.CHECK.value:
        check = checks_by_id.get(incident.check_id or -1)
        # A deleted/disabled secondary check is not a current health problem. Multi-check
        # Core normally closes those incidents administratively, but ignoring a stale row
        # here keeps the aggregate view robust if a restore/race left one behind.
        if check is None or not check.enabled:
            return None
        name = check.name
        return _Problem(
            severity=TargetHealthState.CRITICAL.value,
            reason=f"{name} недоступен",
            kind="check",
            order=int(incident.id or 0),
        )
    if source_kind == IncidentSourceKind.CHECK_TLS.value:
        check = checks_by_id.get(incident.check_id or -1)
        latest = latest_results.get(incident.check_id or -1)
        # A stale expiry incident never outranks a fresh HTTPS availability failure.
        if (
            check is None
            or not check.enabled
            or check.checker_type != "https"
            or not check.tls_monitor_enabled
            or latest is None
            or latest.config_version != check.config_version
            or _normalize_availability(latest.status) != "up"
            or latest.tls_health not in {"warning", "critical"}
        ):
            return None
        days = max(0, int(latest.tls_days_remaining or 0))
        return _Problem(
            severity=_severity(incident.severity, source_kind=source_kind),
            reason=f"TLS: {days} дней",
            kind="tls",
            order=0,
        )
    if source_kind != IncidentSourceKind.SNMP.value:
        return None
    severity = _severity(incident.severity, source_kind=source_kind)
    message = (incident.last_message or "").strip()
    reason = message or (
        "SNMP: критическое значение"
        if severity == TargetHealthState.CRITICAL.value
        else "SNMP: предупреждение"
    )
    return _Problem(
        severity=severity,
        reason=reason,
        kind="snmp",
        order=int(incident.id or 0),
    )


def _service_status(
    *,
    check: TargetCheck,
    target: MonitorTarget,
    availability: str,
    primary_result: CheckResult | None,
    secondary_result: TargetCheckResult | None,
    open_check_incident: bool,
) -> ServiceHealth:
    if check.checker_type == "directory":
        address = check.directory_path or "—"
    elif check.checker_type == "dns":
        address = check.dns_name or target.address
    else:
        address = check.address_override or target.address
    latency_ms: float | None = None
    checked_at: datetime | None = None
    message: str | None = None
    tls_days_remaining: float | None = None
    tls_health: str | None = None
    directory_files: tuple[DirectoryFileHealth, ...] = ()
    if check.checker_type == "directory":
        parsed_files: list[DirectoryFileHealth] = []
        for item in check.directory_last_files or []:
            try:
                modified_at = datetime.fromisoformat(str(item["modified_at"]))
                parsed_files.append(
                    DirectoryFileHealth(
                        name=str(item["name"]),
                        modified_at=(
                            modified_at
                            if modified_at.tzinfo is not None
                            else modified_at.replace(tzinfo=UTC)
                        ),
                        size_bytes=int(item["size_bytes"]),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
        directory_files = tuple(parsed_files)

    if check.is_primary:
        result = primary_result
        if result is not None:
            latency_ms = result.latency_ms
            checked_at = result.checked_at
            message = result.message
        if not target.enabled or not check.enabled:
            status = "disabled"
        elif availability == "off_hours":
            status = "off_hours"
        elif availability == "up":
            status = "up"
        elif availability == "down":
            status = "down"
        else:
            status = "unknown"
    else:
        result = secondary_result
        if result is not None and result.config_version == check.config_version:
            latency_ms = result.latency_ms
            checked_at = result.checked_at
            message = result.message
            tls_days_remaining = result.tls_days_remaining
            tls_health = result.tls_health
        else:
            result = None
        if not target.enabled or not check.enabled:
            status = "disabled"
        elif availability == "off_hours":
            status = "off_hours"
        elif availability != "up":
            status = "waiting_primary"
        elif open_check_incident:
            status = "down"
        elif result is None:
            status = "unknown"
        else:
            result_status = _normalize_availability(result.status)
            status = result_status if result_status in {"up", "down"} else "unknown"

    label = SERVICE_LABELS[status]
    if check.checker_type == "directory" and status == "down":
        if (message or "").startswith("Каталог недоступен"):
            label = "Каталог недоступен"
        elif (message or "").startswith("За последние"):
            label = "Нет свежих файлов"
        else:
            label = "Ошибка каталога"

    return ServiceHealth(
        check_id=check.id,
        name="Основная" if check.is_primary else check.name,
        is_primary=check.is_primary,
        checker_type=check.checker_type,
        address=address,
        port=check.port,
        path=check.path,
        dns_record_type=check.dns_record_type,
        enabled=check.enabled,
        status=status,
        label=label,
        latency_ms=latency_ms,
        checked_at=checked_at,
        message=message,
        tls_days_remaining=tls_days_remaining,
        tls_health=tls_health,
        unstable=status == "up" and unstable_link_active(check),
        directory_files=directory_files,
        directory_recent_count=check.directory_recent_count,
        directory_scanned_at=check.directory_scanned_at,
    )


def get_targets_health(
    session: Session,
    availability_by_target: Mapping[int, object],
) -> dict[int, TargetHealth]:
    """Build aggregate health for many targets using a fixed number of SQL queries.

    `availability_by_target` is intentionally supplied by the caller. Existing pages remain
    the source of truth for primary availability and schedule semantics; this service adds
    secondary checks, incidents and SNMP degradation without creating a second availability
    engine or any new incidents.
    """

    target_ids = list(dict.fromkeys(int(target_id) for target_id in availability_by_target))
    if not target_ids:
        return {}

    targets = session.scalars(
        select(MonitorTarget).where(MonitorTarget.id.in_(target_ids))
    ).all()
    targets_by_id = {target.id: target for target in targets}
    gates_by_site = load_site_entry_gates(
        session, {target.site_id for target in targets}
    )

    checks = session.scalars(
        select(TargetCheck)
        .where(TargetCheck.target_id.in_(target_ids))
        .order_by(TargetCheck.target_id, TargetCheck.display_order, TargetCheck.id)
    ).all()
    checks_by_target: dict[int, list[TargetCheck]] = {}
    checks_by_id: dict[int, TargetCheck] = {}
    secondary_ids: list[int] = []
    for check in checks:
        checks_by_target.setdefault(check.target_id, []).append(check)
        checks_by_id[check.id] = check
        if not check.is_primary:
            secondary_ids.append(check.id)

    latest_primary = _latest_primary_results(session, target_ids)
    latest_secondary = _latest_secondary_results(session, secondary_ids)

    incidents = session.scalars(
        select(Incident)
        .where(
            Incident.target_id.in_(target_ids),
            Incident.status == IncidentStatus.OPEN,
            Incident.source_kind.in_(
                (
                    IncidentSourceKind.CHECK.value,
                    IncidentSourceKind.CHECK_TLS.value,
                    IncidentSourceKind.SNMP.value,
                )
            ),
        )
        .order_by(Incident.id.desc())
    ).all()
    incidents_by_target: dict[int, list[Incident]] = {}
    open_check_ids: set[int] = set()
    for incident in incidents:
        incidents_by_target.setdefault(incident.target_id, []).append(incident)
        if (
            _value(incident.source_kind) == IncidentSourceKind.CHECK.value
            and incident.check_id is not None
        ):
            open_check_ids.add(incident.check_id)

    snmp_configs = session.scalars(
        select(SnmpConfig).where(SnmpConfig.target_id.in_(target_ids))
    ).all()
    snmp_by_target = {config.target_id: config for config in snmp_configs}

    result: dict[int, TargetHealth] = {}
    severity_rank = {
        TargetHealthState.WARNING.value: 1,
        TargetHealthState.CRITICAL.value: 2,
    }

    for target_id in target_ids:
        target = targets_by_id.get(target_id)
        if target is None:
            continue
        supplied_availability = availability_by_target.get(target_id)
        availability = _normalize_availability(supplied_availability)
        if supplied_availability is None:
            primary_fallback = latest_primary.get(target_id)
            availability = _normalize_availability(
                primary_fallback.status if primary_fallback is not None else None
            )
        target_checks = checks_by_target.get(target_id, [])

        services = tuple(
            _service_status(
                check=check,
                target=target,
                availability=availability,
                primary_result=latest_primary.get(target_id),
                secondary_result=(
                    None if check.is_primary else latest_secondary.get(check.id)
                ),
                open_check_incident=check.id in open_check_ids,
            )
            for check in target_checks
        )
        secondary_services = tuple(
            service for service in services if not service.is_primary
        )
        services_total = sum(service.enabled for service in secondary_services)
        services_ok = (
            sum(service.enabled and service.status == "up" for service in secondary_services)
            if target.enabled and availability == "up"
            else None
        )

        state: str
        reason: str | None = None
        reason_kind: str | None = None
        additional_problem_count = 0

        if not target.enabled:
            state = TargetHealthState.DISABLED.value
        elif availability == "off_hours":
            state = TargetHealthState.OFF_HOURS.value
        elif (
            (site_gate := gates_by_site.get(target.site_id)) is not None
            and site_gate.blocked
            and site_gate.entry_target_id != target.id
        ):
            services = tuple(
                replace(
                    service,
                    status="waiting_site",
                    label=SERVICE_LABELS["waiting_site"],
                    latency_ms=None,
                    checked_at=None,
                    message=None,
                )
                if service.enabled
                else service
                for service in services
            )
            state = TargetHealthState.SITE_UNREACHABLE.value
            availability = TargetHealthState.SITE_UNREACHABLE.value
            reason = site_gate.entry_target_name
            reason_kind = "site_entry"
            services_ok = None
        elif availability == "down":
            state = TargetHealthState.OFFLINE.value
            reason = "Основная проверка недоступна"
            reason_kind = "availability"
        elif availability != "up":
            state = TargetHealthState.UNKNOWN.value
        else:
            problems = [
                problem
                for incident in incidents_by_target.get(target_id, [])
                if (
                    problem := _incident_problem(
                        incident, checks_by_id, latest_secondary
                    )
                )
                is not None
            ]
            snmp_config = snmp_by_target.get(target_id)
            has_open_snmp_problem = any(problem.kind == "snmp" for problem in problems)
            if (
                snmp_config is not None
                and snmp_config.enabled
                and _value(snmp_config.last_status).lower() == "error"
                and not has_open_snmp_problem
            ):
                problems.append(
                    _Problem(
                        severity=TargetHealthState.WARNING.value,
                        reason="SNMP недоступен",
                        kind="snmp",
                        order=0,
                    )
                )
            problems.sort(
                key=lambda item: (severity_rank.get(item.severity, 0), item.order),
                reverse=True,
            )
            if problems:
                main = problems[0]
                state = main.severity
                reason = main.reason
                reason_kind = main.kind
                additional_problem_count = len(problems) - 1
            else:
                state = TargetHealthState.OK.value

        result[target_id] = TargetHealth(
            target_id=target_id,
            state=state,
            label=HEALTH_LABELS[state],
            availability=availability,
            reason=reason,
            reason_kind=reason_kind,
            additional_problem_count=additional_problem_count,
            services_ok=services_ok,
            services_total=services_total,
            services=services,
            unstable=target.enabled and availability == "up" and unstable_link_active(target),
        )

    return result
