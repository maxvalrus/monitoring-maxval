"""Availability gates for the one optional entry target of a site.

This deliberately models neither a dependency graph nor a new incident type.  A
primary DOWN result of the enabled entry target temporarily suppresses polling of
its site siblings.  Existing history and incidents of those siblings remain intact.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from monitoring.models import CheckResult, MonitorTarget, Site, WorkSchedule
from monitoring.services.work_schedules import schedule_is_working, schedule_timezone

ENTRY_TARGET_KINDS = frozenset({"network", "server"})


@dataclass(frozen=True, slots=True)
class SiteEntryGate:
    site_id: int
    entry_target_id: int
    entry_target_name: str
    entry_enabled: bool
    entry_status: str

    @property
    def blocked(self) -> bool:
        return self.entry_enabled and self.entry_status == "down"


def _value(value: object | None) -> str:
    if value is None:
        return ""
    return str(getattr(value, "value", value)).strip().lower()


def load_site_entry_gates(
    session: Session,
    site_ids: Iterable[int] | None = None,
    *,
    now: datetime | None = None,
) -> dict[int, SiteEntryGate]:
    """Load entry gates and their latest primary result in a constant query count."""
    normalized = None if site_ids is None else sorted({int(item) for item in site_ids})
    if normalized == []:
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
        .subquery()
    )
    query = (
        select(MonitorTarget, CheckResult.status, WorkSchedule)
        .join(Site, Site.id == MonitorTarget.site_id)
        .outerjoin(WorkSchedule, WorkSchedule.id == Site.schedule_id)
        .outerjoin(
            ranked,
            (ranked.c.target_id == MonitorTarget.id) & (ranked.c.row_number == 1),
        )
        .outerjoin(CheckResult, CheckResult.id == ranked.c.result_id)
        .where(MonitorTarget.is_site_entry.is_(True))
        .order_by(MonitorTarget.site_id, MonitorTarget.id)
    )
    if normalized is not None:
        query = query.where(MonitorTarget.site_id.in_(normalized))

    current = now or datetime.now(UTC)
    timezone_name = schedule_timezone(session)
    result: dict[int, SiteEntryGate] = {}
    for entry, result_status, schedule in session.execute(query):
        status = _value(result_status)
        # A stale DOWN result must not block a site while its work schedule is inactive.
        if not schedule_is_working(schedule, current, timezone_name):
            status = "off_hours"
        result.setdefault(
            entry.site_id,
            SiteEntryGate(
                site_id=entry.site_id,
                entry_target_id=entry.id,
                entry_target_name=entry.name,
                entry_enabled=bool(entry.enabled),
                entry_status=status,
            ),
        )
    return result


def blocked_site_ids(session: Session, site_ids: Iterable[int] | None = None) -> set[int]:
    return {
        site_id
        for site_id, gate in load_site_entry_gates(session, site_ids).items()
        if gate.blocked
    }


def blocking_gate_for_target(session: Session, target: MonitorTarget) -> SiteEntryGate | None:
    if target.is_site_entry:
        return None
    gate = load_site_entry_gates(session, (target.site_id,)).get(target.site_id)
    return gate if gate is not None and gate.blocked else None


def set_site_entry(session: Session, target: MonitorTarget, enabled: bool) -> int | None:
    """Set/unset an entry target and return an id of a replaced entry, if any."""
    if not enabled:
        target.is_site_entry = False
        session.flush()
        return None
    if _value(target.kind) not in ENTRY_TARGET_KINDS:
        raise ValueError(
            "Точкой входа площадки может быть только объект типа «Сеть» или «Сервер»"
        )
    previous = session.scalar(
        select(MonitorTarget)
        .where(
            MonitorTarget.site_id == target.site_id,
            MonitorTarget.is_site_entry.is_(True),
            MonitorTarget.id != target.id,
        )
        .order_by(MonitorTarget.id)
        .limit(1)
    )
    previous_id = previous.id if previous is not None else None
    if previous is not None:
        previous.is_site_entry = False
        # PostgreSQL does not defer the partial unique index: clear before setting.
        session.flush()
    target.is_site_entry = True
    session.flush()
    return previous_id


def normalize_site_entry_for_kind(target: MonitorTarget) -> bool:
    if target.is_site_entry and _value(target.kind) not in ENTRY_TARGET_KINDS:
        target.is_site_entry = False
        return True
    return False
