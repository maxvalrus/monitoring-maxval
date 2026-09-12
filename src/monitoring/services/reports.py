from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from monitoring.models import AppSetting, CheckResult, MonitorTarget, Site
from monitoring.services.system_metrics import ChartData, chart_data


@dataclass(frozen=True, slots=True)
class AvailabilityRow:
    target_id: int
    target_name: str
    site_name: str
    kind: str
    up_count: int
    down_count: int
    unknown_count: int
    availability: float | None


@dataclass(frozen=True, slots=True)
class SiteAvailabilityRow:
    site_id: int
    site_name: str
    up_count: int
    down_count: int
    unknown_count: int
    availability: float | None


@dataclass(frozen=True, slots=True)
class TargetHistory:
    target: MonitorTarget
    site: Site
    checked_count: int
    up_count: int
    down_count: int
    unknown_count: int
    availability: float | None
    latency_points: str
    latency_chart: ChartData
    results: list[CheckResult]
    result_limit: int
    latest_status: str | None
    is_online: bool


def _availability(up_count: int, down_count: int) -> float | None:
    known = up_count + down_count
    return round(up_count * 100 / known, 2) if known else None


def _history_result_limit(session: Session) -> int:
    setting = session.get(AppSetting, "target_history_max_results")
    try:
        value = int(setting.value) if setting is not None else 1000
    except ValueError:
        value = 1000
    return max(100, min(100000, value))


def availability_report(
    session: Session,
    *,
    hours: int,
    site_id: int = 0,
    kind: str = "all",
) -> tuple[list[AvailabilityRow], list[SiteAvailabilityRow]]:
    threshold = datetime.now(UTC) - timedelta(hours=hours)
    up = func.sum(case((CheckResult.status == "up", 1), else_=0))
    down = func.sum(case((CheckResult.status == "down", 1), else_=0))
    unknown = func.sum(case((CheckResult.status == "unknown", 1), else_=0))
    conditions = []
    if site_id:
        conditions.append(Site.id == site_id)
    if kind != "all":
        conditions.append(MonitorTarget.kind == kind)

    target_rows = session.execute(
        select(MonitorTarget, Site, up, down, unknown)
        .join(Site, Site.id == MonitorTarget.site_id)
        .outerjoin(
            CheckResult,
            (CheckResult.target_id == MonitorTarget.id)
            & (CheckResult.checked_at >= threshold),
        )
        .where(*conditions)
        .group_by(MonitorTarget.id, Site.id)
        .order_by(Site.name, MonitorTarget.name, MonitorTarget.id)
    ).all()
    targets = [
        AvailabilityRow(
            target_id=target.id,
            target_name=target.name,
            site_name=site.name,
            kind=target.kind,
            up_count=int(up_count or 0),
            down_count=int(down_count or 0),
            unknown_count=int(unknown_count or 0),
            availability=_availability(int(up_count or 0), int(down_count or 0)),
        )
        for target, site, up_count, down_count, unknown_count in target_rows
    ]

    site_rows = session.execute(
        select(Site.id, Site.name, up, down, unknown)
        .join(MonitorTarget, MonitorTarget.site_id == Site.id)
        .outerjoin(
            CheckResult,
            (CheckResult.target_id == MonitorTarget.id)
            & (CheckResult.checked_at >= threshold),
        )
        .where(*conditions)
        .group_by(Site.id, Site.name)
        .order_by(Site.name, Site.id)
    ).all()
    sites = [
        SiteAvailabilityRow(
            site_id=row_site_id,
            site_name=site_name,
            up_count=int(up_count or 0),
            down_count=int(down_count or 0),
            unknown_count=int(unknown_count or 0),
            availability=_availability(int(up_count or 0), int(down_count or 0)),
        )
        for row_site_id, site_name, up_count, down_count, unknown_count in site_rows
    ]
    return targets, sites


def target_history(session: Session, target_id: int, *, hours: int) -> TargetHistory:
    row = session.execute(
        select(MonitorTarget, Site)
        .join(Site, Site.id == MonitorTarget.site_id)
        .where(MonitorTarget.id == target_id)
    ).one_or_none()
    if row is None:
        raise LookupError("Объект не найден")
    target, site = row
    threshold = datetime.now(UTC) - timedelta(hours=hours)
    result_limit = _history_result_limit(session)
    latest_status = session.scalar(
        select(CheckResult.status)
        .where(CheckResult.target_id == target_id)
        .order_by(CheckResult.checked_at.desc(), CheckResult.id.desc())
        .limit(1)
    )
    results = list(
        reversed(
            session.scalars(
                select(CheckResult)
                .where(
                    CheckResult.target_id == target_id,
                    CheckResult.checked_at >= threshold,
                )
                .order_by(CheckResult.checked_at.desc(), CheckResult.id.desc())
                .limit(result_limit)
            ).all()
        )
    )
    up_count = sum(item.status == "up" for item in results)
    down_count = sum(item.status == "down" for item in results)
    unknown_count = len(results) - up_count - down_count
    latency_values = [
        float(item.latency_ms if item.latency_ms is not None else 0.0) for item in results
    ]
    latency_chart = chart_data(latency_values, [item.checked_at for item in results])
    return TargetHistory(
        target=target,
        site=site,
        checked_count=len(results),
        up_count=up_count,
        down_count=down_count,
        unknown_count=unknown_count,
        availability=_availability(up_count, down_count),
        latency_points=latency_chart.points,
        latency_chart=latency_chart,
        results=results,
        result_limit=result_limit,
        latest_status=latest_status,
        is_online=bool(target.enabled and site.enabled and latest_status == "up"),
    )
