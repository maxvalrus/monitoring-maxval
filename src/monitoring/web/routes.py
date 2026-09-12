import ipaddress
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import cache
from hashlib import sha256
from pathlib import Path
from typing import Annotated
from urllib.parse import quote_plus, urlencode

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import case, func, or_, select

from monitoring import __version__
from monitoring.config import get_settings
from monitoring.models import (
    AppSetting,
    CheckResult,
    Incident,
    IncidentStatus,
    MonitorTarget,
    PushSubscription,
    Site,
    SnmpConfig,
    SnmpInterface,
    SnmpMetric,
    SnmpSupply,
    SnmpThreshold,
    SnmpUpsState,
    TargetKind,
    User,
    WorkSchedule,
)
from monitoring.notifications import EmailNotifier, Notification, smtp_error_message
from monitoring.services.audit import audit_changes, write_audit
from monitoring.services.backups import (
    BackupError,
    database_has_meaningful_data,
    human_size,
    inspect_backup,
    list_backups,
    staged_backup_path,
)
from monitoring.services.exports import availability_pdf_bytes, xlsx_sheets_bytes
from monitoring.services.pagination import (
    Pagination,
    SortState,
    page_url,
    positive_int,
    sort_url,
)
from monitoring.services.push import (
    delete_subscription_by_id,
    push_device_label,
    send_test_push_to_subscription,
    set_vapid_subject,
)
from monitoring.services.reports import availability_report, target_history
from monitoring.services.settings import update_setting
from monitoring.services.smtp_settings import (
    SMTP_SETTING_KEYS,
    SmtpForm,
    load_smtp_settings,
    update_smtp_settings,
)
from monitoring.services.snmp import trim_snmp_samples_for_target
from monitoring.services.snmp_graphs import build_snmp_history_graph
from monitoring.services.snmp_supplies import supply_level_label
from monitoring.services.snmp_thresholds import ThresholdLevel, evaluate_level
from monitoring.services.snmp_ups import battery_status_label, output_source_label
from monitoring.services.system_metrics import (
    format_bytes,
    format_duration,
    format_short_duration,
    portal_dashboard,
)
from monitoring.services.target_health import HEALTH_FILTER_STATES, get_targets_health
from monitoring.services.time_display import (
    DEFAULT_TIMEZONE,
    format_datetime,
    session_datetime_formatter,
)
from monitoring.services.tls import TlsManager, TlsManagerError
from monitoring.services.work_schedules import schedule_is_working, schedule_timezone
from monitoring.web.dependencies import AdminAuth, CurrentAuth, DbSession, template_context
from monitoring.web.security import (
    client_ip,
    is_https_request,
    session_cookie_name,
    session_token,
    set_session_cookie,
    verify_session_csrf,
)

router = APIRouter()
logger = logging.getLogger(__name__)
templates = Jinja2Templates(directory=Path(__file__).resolve().parent.parent / "templates")
templates.env.globals["app_version"] = __version__
templates.env.globals["page_url"] = page_url
templates.env.globals["sort_url"] = sort_url


@cache
def static_asset_revision(filename: str) -> str:
    """Return a stable content revision for cache-busted presentation assets."""
    if filename not in {"app.css", "app.js", "wallboard.css"}:
        raise ValueError(f"Unsupported static asset: {filename}")
    asset = Path(__file__).resolve().parent.parent / "static" / filename
    return sha256(asset.read_bytes()).hexdigest()[:12]


templates.env.globals["static_asset_revision"] = static_asset_revision


def display_datetime(value: datetime, pattern: str = "%d.%m.%Y %H:%M:%S %Z") -> str:
    return format_datetime(value, DEFAULT_TIMEZONE, pattern)


templates.env.globals["display_datetime"] = display_datetime


def request_ip_hostname(request: Request) -> str:
    """Use an IP only when the portal itself was opened by IP, never client IP."""
    hostname = request.url.hostname or ""
    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        return ""


@dataclass(frozen=True, slots=True)
class SupplyLevelView:
    label: str
    percent: float | None
    level: str
    title: str


@dataclass(frozen=True, slots=True)
class TargetView:
    id: int
    name: str
    site_name: str
    kind: str
    checker_type: str
    address: str
    port: int
    interval_seconds: int
    favorite: bool
    is_site_entry: bool
    status: str
    latency_ms: float | None
    checked_at: datetime | None
    message: str | None
    comment: str | None
    notifications_suppressed: bool
    availability_24h: float | None
    snmp_enabled: bool
    snmp_status: str
    snmp_metric_count: int
    snmp_interface_count: int
    snmp_threshold_count: int
    open_incident_count: int


def availability_color_thresholds(session: DbSession) -> tuple[int, int]:
    values = {
        key: value
        for key, value in session.execute(
            select(AppSetting.key, AppSetting.value).where(
                AppSetting.key.in_(
                    (
                        "availability_warning_threshold_percent",
                        "availability_good_threshold_percent",
                    )
                )
            )
        )
    }
    try:
        warning = int(values.get("availability_warning_threshold_percent", "1"))
        good = int(values.get("availability_good_threshold_percent", "100"))
    except ValueError:
        return 1, 100
    if not 0 <= warning < good <= 100:
        return 1, 100
    return warning, good


def _compact_sparkline(values: list[float]) -> str | None:
    if len(values) < 2:
        return None
    minimum = min(values)
    spread = max(values) - minimum or 1.0
    return " ".join(
        f"{index * 100 / (len(values) - 1):.1f},{26 - (value - minimum) * 22 / spread:.1f}"
        for index, value in enumerate(values)
    )


def dashboard_latency_sparklines(session: DbSession, target_ids: list[int]) -> dict[int, str]:
    if not target_ids:
        return {}
    ranked = (
        select(
            CheckResult.target_id,
            CheckResult.latency_ms,
            func.row_number()
            .over(
                partition_by=CheckResult.target_id,
                order_by=(CheckResult.checked_at.desc(), CheckResult.id.desc()),
            )
            .label("position"),
        )
        .where(
            CheckResult.target_id.in_(target_ids),
            CheckResult.latency_ms.is_not(None),
        )
        .subquery()
    )
    values: dict[int, list[float]] = {}
    rows = session.execute(
        select(ranked.c.target_id, ranked.c.latency_ms)
        .where(ranked.c.position <= 16)
        .order_by(ranked.c.target_id, ranked.c.position.desc())
    )
    for target_id, latency_ms in rows:
        values.setdefault(target_id, []).append(float(latency_ms))
    return {
        target_id: points
        for target_id, samples in values.items()
        if (points := _compact_sparkline(samples)) is not None
    }


def _compact_supply_label(description: str | None, supply_index: int) -> str:
    text = (description or "").casefold()
    aliases = (
        (("black", "черн", "чёрн", "schwarz"), "K"),
        (("cyan", "голуб", "бирюз"), "C"),
        (("magenta", "пурпур", "малинов"), "M"),
        (("yellow", "желт", "жёлт", "gelb"), "Y"),
    )
    for needles, label in aliases:
        if any(needle in text for needle in needles):
            return label
    if "waste" in text or "отработ" in text:
        return "W"
    if "toner" in text or "тонер" in text or "ink" in text or "чернил" in text:
        return "T"
    return f"R{supply_index}"


def dashboard_supply_levels(
    session: DbSession, target_ids: list[int]
) -> dict[int, tuple[SupplyLevelView, ...]]:
    if not target_ids:
        return {}
    supplies = session.scalars(
        select(SnmpSupply)
        .where(
            SnmpSupply.target_id.in_(target_ids),
            SnmpSupply.present.is_(True),
            SnmpSupply.supply_class == 3,
            SnmpSupply.supply_type.in_((3, 5, 6, 21)),
        )
        .order_by(
            SnmpSupply.target_id,
            SnmpSupply.hr_device_index,
            SnmpSupply.supply_index,
        )
    ).all()
    if not supplies:
        return {}
    supply_ids = [item.id for item in supplies]
    thresholds_by_supply: dict[int, list[SnmpThreshold]] = {}
    for threshold in session.scalars(
        select(SnmpThreshold).where(
            SnmpThreshold.source_kind == "supply",
            SnmpThreshold.enabled.is_(True),
            SnmpThreshold.supply_id.in_(supply_ids),
        )
    ).all():
        if threshold.supply_id is not None:
            thresholds_by_supply.setdefault(threshold.supply_id, []).append(threshold)

    rank = {
        ThresholdLevel.NORMAL: 0,
        ThresholdLevel.WARNING: 1,
        ThresholdLevel.CRITICAL: 2,
    }
    result: dict[int, list[SupplyLevelView]] = {}
    for supply in supplies:
        label = _compact_supply_label(
            " ".join(filter(None, (supply.custom_name, supply.description))),
            supply.supply_index,
        )
        display_name = supply.display_name
        level = ThresholdLevel.NORMAL
        if supply.percent_remaining is None:
            level_name = "unknown"
            title = f"{display_name}: точный процент недоступен"
        else:
            for threshold in thresholds_by_supply.get(supply.id, ()):
                candidate = evaluate_level(
                    float(supply.percent_remaining),
                    operator=threshold.operator,
                    warning=threshold.warning_value,
                    critical=threshold.critical_value,
                )
                if rank[candidate] > rank[level]:
                    level = candidate
            level_name = level.value
            title = f"{display_name}: {supply.percent_remaining:.0f}%"
        result.setdefault(supply.target_id, []).append(
            SupplyLevelView(
                label=label,
                percent=supply.percent_remaining,
                level=level_name,
                title=title,
            )
        )
    label_order = {"K": 0, "C": 1, "M": 2, "Y": 3}
    return {
        target_id: tuple(
            sorted(
                items,
                key=lambda item: (label_order.get(item.label, 10), item.label),
            )[:4]
        )
        for target_id, items in result.items()
    }


def latest_results_subquery():
    ranked = select(
        CheckResult.target_id,
        CheckResult.status,
        CheckResult.latency_ms,
        CheckResult.checked_at,
        CheckResult.message,
        func.row_number()
        .over(
            partition_by=CheckResult.target_id,
            order_by=(CheckResult.checked_at.desc(), CheckResult.id.desc()),
        )
        .label("position"),
    ).subquery()
    return select(ranked).where(ranked.c.position == 1).subquery()


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, session: DbSession, auth: CurrentAuth) -> HTMLResponse:
    latest = latest_results_subquery()
    availability_warning_threshold, availability_good_threshold = availability_color_thresholds(
        session
    )
    now = datetime.now(UTC)
    availability_since = now - timedelta(hours=24)
    availability = (
        select(
            CheckResult.target_id.label("target_id"),
            func.sum(case((CheckResult.status == "up", 1), else_=0)).label("up_count"),
            func.sum(case((CheckResult.status == "down", 1), else_=0)).label("down_count"),
        )
        .where(CheckResult.checked_at >= availability_since)
        .group_by(CheckResult.target_id)
        .subquery()
    )
    snmp_metrics = (
        select(SnmpMetric.target_id.label("target_id"), func.count(SnmpMetric.id).label("count"))
        .group_by(SnmpMetric.target_id)
        .subquery()
    )
    snmp_interfaces = (
        select(
            SnmpInterface.target_id.label("target_id"),
            func.count(SnmpInterface.id).label("count"),
        )
        .where(SnmpInterface.monitor_enabled.is_(True))
        .group_by(SnmpInterface.target_id)
        .subquery()
    )
    snmp_thresholds = (
        select(
            SnmpThreshold.target_id.label("target_id"),
            func.count(SnmpThreshold.id).label("count"),
        )
        .group_by(SnmpThreshold.target_id)
        .subquery()
    )
    open_incidents = (
        select(
            Incident.target_id.label("target_id"),
            func.count(Incident.id).label("count"),
        )
        .where(Incident.status == IncidentStatus.OPEN)
        .group_by(Incident.target_id)
        .subquery()
    )
    selected_status = request.query_params.get("status", "all")
    if selected_status not in {"all", "up", "down", "unknown", "off_hours"}:
        selected_status = "all"
    selected_site = positive_int(request.query_params.get("site_id"), 0)
    selected_kind = request.query_params.get("kind", "all")
    allowed_kinds = {kind.value for kind in TargetKind}
    if selected_kind not in {"all", *allowed_kinds}:
        selected_kind = "all"
    selected_sort = request.query_params.get("sort", "default")
    if selected_sort not in {"default", "open_incidents"}:
        selected_sort = "default"
    conditions = [MonitorTarget.enabled.is_(True), Site.enabled.is_(True)]
    if selected_site:
        conditions.append(Site.id == selected_site)
    if selected_kind != "all":
        conditions.append(MonitorTarget.kind == selected_kind)

    rows = session.execute(
        select(
            MonitorTarget,
            Site,
            WorkSchedule,
            latest.c.status,
            latest.c.latency_ms,
            latest.c.checked_at,
            latest.c.message,
            SnmpConfig.enabled,
            SnmpConfig.last_status,
            availability.c.up_count,
            availability.c.down_count,
            snmp_metrics.c.count,
            snmp_interfaces.c.count,
            snmp_thresholds.c.count,
            open_incidents.c.count,
        )
        .join(Site, MonitorTarget.site_id == Site.id)
        .outerjoin(WorkSchedule, WorkSchedule.id == Site.schedule_id)
        .outerjoin(latest, latest.c.target_id == MonitorTarget.id)
        .outerjoin(SnmpConfig, SnmpConfig.target_id == MonitorTarget.id)
        .outerjoin(availability, availability.c.target_id == MonitorTarget.id)
        .outerjoin(snmp_metrics, snmp_metrics.c.target_id == MonitorTarget.id)
        .outerjoin(snmp_interfaces, snmp_interfaces.c.target_id == MonitorTarget.id)
        .outerjoin(snmp_thresholds, snmp_thresholds.c.target_id == MonitorTarget.id)
        .outerjoin(open_incidents, open_incidents.c.target_id == MonitorTarget.id)
        .where(*conditions)
        .order_by(
            MonitorTarget.favorite.desc(),
            MonitorTarget.display_order,
            MonitorTarget.id,
        )
    ).all()
    timezone_name = schedule_timezone(session)
    all_targets: list[TargetView] = []
    for (
        target,
        site,
        schedule,
        result_status,
        latency_ms,
        checked_at,
        message,
        snmp_enabled,
        snmp_status,
        up_count,
        down_count,
        snmp_metric_count,
        snmp_interface_count,
        snmp_threshold_count,
        open_incident_count,
    ) in rows:
        working = schedule_is_working(schedule, now, timezone_name)
        effective_status = (result_status or "unknown") if working else "off_hours"
        schedule_name = schedule.name if schedule is not None else "Круглосуточно"
        all_targets.append(
            TargetView(
                id=target.id,
                name=target.name,
                site_name=site.name,
                kind=target.kind,
                checker_type=target.checker_type,
                address=target.address,
                port=target.port,
                interval_seconds=target.interval_seconds,
                favorite=target.favorite,
                is_site_entry=target.is_site_entry,
                status=effective_status,
                latency_ms=latency_ms if working and result_status == "up" else None,
                checked_at=checked_at,
                message=(message or "Проверка ещё не выполнялась")
                if working
                else f"Вне рабочего времени · {schedule_name}",
                comment=target.comment,
                notifications_suppressed=target.notifications_suppressed,
                availability_24h=(
                    round(int(up_count or 0) * 100 / (int(up_count or 0) + int(down_count or 0)), 2)
                    if int(up_count or 0) + int(down_count or 0)
                    else None
                ),
                snmp_enabled=bool(snmp_enabled),
                snmp_status=snmp_status or "never",
                snmp_metric_count=int(snmp_metric_count or 0),
                snmp_interface_count=int(snmp_interface_count or 0),
                snmp_threshold_count=int(snmp_threshold_count or 0),
                open_incident_count=int(open_incident_count or 0),
            )
        )

    filtered = (
        all_targets
        if selected_status == "all"
        else [target for target in all_targets if target.status == selected_status]
    )
    if selected_sort == "open_incidents":
        filtered.sort(key=lambda target: target.open_incident_count, reverse=True)
    selected_health = request.query_params.get("health", "").strip().lower()
    all_target_health = get_targets_health(
        session, {target.id: target.status for target in filtered}
    )
    if selected_health in HEALTH_FILTER_STATES:
        filtered = [
            target
            for target in filtered
            if (health := all_target_health.get(target.id)) is not None
            and health.state == selected_health
        ]
    else:
        selected_health = ""
    pager = Pagination.from_request(request, len(filtered))
    focus_target_id = positive_int(request.query_params.get("focus_target_id"), 0)
    if focus_target_id and "page" not in request.query_params:
        focus_index = next(
            (index for index, item in enumerate(filtered) if item.id == focus_target_id), None
        )
        if focus_index is not None:
            focus_page = focus_index // pager.per_page + 1
            pager = Pagination(
                page=focus_page,
                pages=pager.pages,
                per_page=pager.per_page,
                total=pager.total,
                offset=(focus_page - 1) * pager.per_page,
            )
    targets = filtered[pager.offset : pager.offset + pager.per_page]
    target_health = {
        target.id: all_target_health[target.id]
        for target in targets
        if target.id in all_target_health
    }
    # Critical is already a Target Health result. The ordinary state page reuses
    # this batch-computed value for the visual attention cards; it never creates
    # an incident or performs an additional per-target lookup.
    critical_alert_targets = [
        {
            "id": target.id,
            "name": target.name,
            "description": f"{target.site_name} · {target.address}"
            + (f":{target.port}" if target.checker_type != "icmp" else "")
            + f" · {health.reason or 'Критическое состояние объекта'}",
        }
        for target in filtered
        if (health := all_target_health.get(target.id)) is not None
        and health.state == "critical"
    ]
    visible_printer_ids = [
        target.id for target in targets if target.kind == TargetKind.PRINTER.value
    ]
    supply_levels = dashboard_supply_levels(session, visible_printer_ids)
    latency_sparklines = dashboard_latency_sparklines(session, [target.id for target in targets])
    status_counts = {
        key: sum(target.status == key for target in filtered)
        for key in ("up", "down", "unknown", "off_hours")
    }
    incident_count = sum(target.open_incident_count for target in filtered)
    counters = {
        "total": len(filtered),
        "up": status_counts["up"],
        "down": status_counts["down"],
        "unknown": status_counts["unknown"],
        "off_hours": status_counts["off_hours"],
        "incidents": incident_count,
    }
    sites = session.scalars(
        select(Site).where(Site.enabled.is_(True)).order_by(Site.display_order, Site.id)
    ).all()
    notification_settings = {
        key: value
        for key, value in session.execute(
            select(AppSetting.key, AppSetting.value).where(
                AppSetting.key.in_(
                    (
                        "notifications_enabled",
                        "smtp_enabled",
                        "smtp_host",
                        "smtp_sender",
                        "smtp_recipient",
                    )
                )
            )
        )
    }
    external_enabled = notification_settings.get("notifications_enabled", "true") == "true"
    smtp_available = bool(
        external_enabled
        and notification_settings.get("smtp_enabled", "true") == "true"
        and notification_settings.get("smtp_host")
        and notification_settings.get("smtp_sender")
        and notification_settings.get("smtp_recipient")
    )
    push_available = bool(
        external_enabled and session.scalar(select(func.count(PushSubscription.id)))
    )
    scheduler = getattr(request.app.state, "scheduler", None)
    health_snapshot = getattr(scheduler, "health_snapshot", None)
    scheduler_snapshot = health_snapshot() if callable(health_snapshot) else None
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context=template_context(
            request,
            auth,
            targets=targets,
            target_health=target_health,
            critical_alert_targets=critical_alert_targets,
            latency_sparklines=latency_sparklines,
            supply_levels=supply_levels,
            push_available=push_available,
            smtp_available=smtp_available,
            availability_warning_threshold=availability_warning_threshold,
            availability_good_threshold=availability_good_threshold,
            counters=counters,
            pager=pager,
            sites=sites,
            selected_status=selected_status,
            selected_site=selected_site,
            selected_kind=selected_kind,
            selected_sort=selected_sort,
            selected_health=selected_health,
            display_datetime=session_datetime_formatter(session),
            portal=portal_dashboard(session, scheduler=scheduler_snapshot),
            format_bytes=format_bytes,
            format_duration=format_duration,
            format_short_duration=format_short_duration,
        ),
    )


@router.get("/wallboard", response_class=HTMLResponse)
def wallboard(request: Request, session: DbSession, auth: CurrentAuth) -> HTMLResponse:
    """Read-only TV view; it only reads the same persisted state as dashboard."""
    health_snapshot = getattr(request.app.state, "scheduler", None)
    snapshot_method = getattr(health_snapshot, "health_snapshot", None)
    scheduler_snapshot = snapshot_method() if callable(snapshot_method) else None
    # The HUD does not collect anything itself. It only presents the same portal
    # snapshot that is already rendered on the ordinary state dashboard.
    portal = portal_dashboard(session, scheduler=scheduler_snapshot)
    portal_tones = {
        "normal": "ok",
        "warning": "warning",
        "critical": "danger",
        "neutral": "neutral",
    }
    portal_labels = {
        "normal": "Норма",
        "warning": "Внимание",
        "critical": "Критично",
        "neutral": "Неизвестно",
    }
    wallboard_portal: dict[str, object] = {
        "state": portal_tones.get(portal.health.level, "neutral"),
        "label": portal_labels.get(portal.health.level, "Неизвестно"),
        "summary": portal.health.detail,
        "items": [
            {
                "label": "CPU",
                "icon": "cpu",
                "value": f"{portal.current.cpu_percent:.1f}%",
                "tone": "warning" if portal.current.cpu_percent >= 95 else "ok",
                "meter": portal.current.cpu_percent,
                "points": portal.cpu_chart.points,
                "title": f"Загрузка процессора: {portal.current.cpu_percent:.1f}%. Предупреждение — от 95%.",
            },
            {
                "label": "RAM",
                "icon": "memory",
                "value": f"{portal.current.memory_percent:.1f}%",
                "tone": "danger" if portal.current.memory_percent >= 97 else (
                    "warning" if portal.current.memory_percent >= 90 else "ok"
                ),
                "meter": portal.current.memory_percent,
                "points": portal.memory_chart.points,
                "title": f"Использовано памяти: {portal.current.memory_percent:.1f}%. Warning — от 90%, Critical — от 97%.",
            },
            {
                "label": "Диск",
                "icon": "disk",
                "value": f"{portal.current.disk_percent:.1f}%",
                "tone": "danger" if portal.current.disk_percent >= 90 else (
                    "warning" if portal.current.disk_percent >= 80 else "ok"
                ),
                "meter": portal.current.disk_percent,
                "points": portal.disk_chart.points,
                "title": f"Использовано диска: {portal.current.disk_percent:.1f}%. Warning — от 80%, Critical — от 90%.",
            },
            {
                "label": "RX / TX",
                "icon": "network",
                "network_rx": f"↓ {format_bytes(portal.receive_rate)}/с",
                "network_tx": f"↑ {format_bytes(portal.send_rate)}/с",
                "tone": "neutral",
                "points": portal.network_chart.points,
                "title": f"Приём: {format_bytes(portal.receive_rate)}/с. Передача: {format_bytes(portal.send_rate)}/с.",
            },
        ],
    }
    if portal.scheduler is not None:
        scheduler = portal.scheduler
        delayed_tone = "danger" if scheduler.missed_interval_count else (
            "warning" if scheduler.delayed_count else "ok"
        )
        wallboard_portal["items"].extend([
            {
                "label": "Проверки · 5 мин",
                "icon": "checks",
                "value": str(scheduler.checks_5m),
                "tone": "ok",
                "title": f"Завершено проверок за последние 5 минут: {scheduler.checks_5m}.",
            },
            {
                "label": "Очередь",
                "icon": "queue",
                "value": f"{scheduler.queue_count} / {scheduler.delayed_count}",
                "tone": delayed_tone,
                "title": f"В очереди: {scheduler.queue_count}. Просрочено: {scheduler.delayed_count}.",
            },
            {
                "label": "Планировщик",
                "icon": "scheduler",
                "value": "Остановлен" if not scheduler.running else (
                    "Нет запаса" if scheduler.headroom_percent is None
                    else f"Запас {scheduler.headroom_percent:.0f}%"
                ),
                "tone": "warning" if scheduler.manual_running else (
                    "ok" if scheduler.running else "danger"
                ),
                "title": "Планировщик остановлен." if not scheduler.running else (
                    "Ручной опрос выполняется. "
                    + ("Запас scheduler пока не рассчитан." if scheduler.headroom_percent is None
                       else f"Запас scheduler: {scheduler.headroom_percent:.0f}%")
                    if scheduler.manual_running else (
                        "Запас scheduler пока не рассчитан." if scheduler.headroom_percent is None
                        else f"Запас scheduler: {scheduler.headroom_percent:.0f}%"
                    )
                ),
                "meter": scheduler.headroom_percent,
            },
        ])
    latest = latest_results_subquery()
    open_incidents = (
        select(Incident.target_id.label("target_id"), func.count(Incident.id).label("count"))
        .where(Incident.status == IncidentStatus.OPEN).group_by(Incident.target_id).subquery()
    )
    rows = session.execute(
        select(MonitorTarget, Site, WorkSchedule, latest.c.status, latest.c.latency_ms,
               latest.c.checked_at, latest.c.message, open_incidents.c.count)
        .join(Site, MonitorTarget.site_id == Site.id)
        .outerjoin(WorkSchedule, WorkSchedule.id == Site.schedule_id)
        .outerjoin(latest, latest.c.target_id == MonitorTarget.id)
        .outerjoin(open_incidents, open_incidents.c.target_id == MonitorTarget.id)
        .order_by(Site.display_order, Site.id, MonitorTarget.favorite.desc(), MonitorTarget.display_order, MonitorTarget.id)
    ).all()
    now, timezone_name = datetime.now(UTC), schedule_timezone(session)
    targets: list[dict[str, object]] = []
    site_layout_scales: dict[int, int] = {}
    states: dict[int, str] = {}
    for target, site, schedule, result_status, latency_ms, checked_at, message, incident_count in rows:
        site_layout_scales[site.id] = site.layout_scale
        if not target.enabled or not site.enabled:
            effective = "disabled"
        elif not schedule_is_working(schedule, now, timezone_name):
            effective = "off_hours"
        else:
            effective = result_status or "unknown"
        states[target.id] = effective
        targets.append({"id": target.id, "site_id": site.id, "site_name": site.name, "site_order": site.display_order,
                        "name": target.name, "kind": target.kind, "address": target.address, "port": target.port,
                        "checker_type": target.checker_type, "enabled": target.enabled and site.enabled,
                        "status": effective, "latency_ms": latency_ms if effective == "up" else None,
                        "checked_at": checked_at, "message": message or "Проверка ещё не выполнялась",
                        "layout_x": target.layout_x, "layout_y": target.layout_y,
                        "open_incident_count": int(incident_count or 0)})
    wallboard_portal["items"].append({
        "label": "Объекты",
        "icon": "objects",
        "value": str(len(targets)),
        "tone": "neutral",
        "title": f"Всего объектов мониторинга: {len(targets)}.",
    })
    health = get_targets_health(session, states)
    for item in targets:
        item_health = health.get(item["id"])
        item["health"] = {
            "state": item_health.state if item_health is not None else "unknown",
            "label": item_health.label if item_health is not None else "Нет данных",
            "reason": item_health.reason if item_health is not None else None,
        }
        service_details = [
            {
                "name": service.name,
                "is_primary": service.is_primary,
                "checker_type": service.checker_type,
                "status": service.status,
                "label": service.label,
            }
            for service in (item_health.services if item_health is not None else ())
        ]
        item["service_details"] = service_details
        item["services"] = [service for service in service_details if not service["is_primary"]]
    sites: list[dict[str, object]] = []
    for site_id in dict.fromkeys(item["site_id"] for item in targets):
        items = [item for item in targets if item["site_id"] == site_id]
        health_counts = {
            state: sum(1 for item in items if health.get(item["id"]) and health[item["id"]].state == state)
            for state in ("ok", "warning", "critical", "offline", "site_unreachable", "unknown", "disabled")
        }
        problems = sum(health_counts[state] for state in ("warning", "critical", "offline", "site_unreachable"))
        accent = (
            "danger" if health_counts["offline"] or health_counts["critical"] or health_counts["site_unreachable"]
            else "warning" if health_counts["warning"]
            else "ok" if health_counts["ok"]
            else "neutral"
        )
        sites.append({"id": site_id, "name": items[0]["site_name"], "layout_scale": site_layout_scales[site_id], "targets": items,
                      "problems": problems, "health_counts": health_counts, "accent": accent})
    recent_since = now - timedelta(hours=1)
    recent = session.execute(
        select(Incident, MonitorTarget.name, Site.name)
        .join(MonitorTarget, Incident.target_id == MonitorTarget.id).join(Site, MonitorTarget.site_id == Site.id)
        .where(or_(Incident.opened_at >= recent_since, Incident.resolved_at >= recent_since))
        .order_by(func.coalesce(Incident.resolved_at, Incident.opened_at).desc()).limit(8)
    ).all()
    events = [{"target": name, "site": site_name, "at": incident.resolved_at or incident.opened_at,
               "kind": "Восстановление" if incident.resolved_at else "Сбой", "message": incident.last_message or "Без описания",
               "resolved": incident.resolved_at is not None} for incident, name, site_name in recent]
    status_targets = {
        key: [item for item in targets if health.get(item["id"]) and health[item["id"]].state == key]
        for key in ("offline", "critical", "warning", "unknown")
    }
    counts = {key: len(items) for key, items in status_targets.items()}
    return templates.TemplateResponse(request=request, name="wallboard.html", context=template_context(
        request, auth, sites=sites, health=health, events=events, status_targets=status_targets, counts=counts,
        display_datetime=session_datetime_formatter(session), now=now, wallboard_portal=wallboard_portal,
    ))


@router.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request, session: DbSession, auth: CurrentAuth) -> HTMLResponse:
    allowed_hours = {24, 168, 720, 2160}
    hours = positive_int(request.query_params.get("hours"), 168)
    if hours not in allowed_hours:
        hours = 168
    selected_site = positive_int(request.query_params.get("site_id"), 0)
    selected_kind = request.query_params.get("kind", "all")
    allowed_kinds = {"all", *(item.value for item in TargetKind)}
    if selected_kind not in allowed_kinds:
        selected_kind = "all"

    targets, site_rows = availability_report(
        session,
        hours=hours,
        site_id=selected_site,
        kind=selected_kind,
    )
    sort_state = SortState.from_request(
        request,
        {"site", "target", "kind", "up", "down", "unknown", "availability"},
        "site",
    )
    report_sort_keys = {
        "site": lambda row: row.site_name.casefold(),
        "target": lambda row: row.target_name.casefold(),
        "kind": lambda row: row.kind.casefold(),
        "up": lambda row: row.up_count,
        "down": lambda row: row.down_count,
        "unknown": lambda row: row.unknown_count,
        "availability": lambda row: row.availability if row.availability is not None else -1,
    }
    targets.sort(
        key=report_sort_keys[sort_state.column],
        reverse=sort_state.direction == "desc",
    )
    pager = Pagination.from_request(request, len(targets))
    report_rows = targets[pager.offset : pager.offset + pager.per_page]

    site_sort_state = SortState.from_request(
        request,
        {"site", "up", "down", "unknown", "availability"},
        "site",
        column_parameter="site_sort",
        direction_parameter="site_direction",
    )
    site_sort_keys = {
        "site": lambda row: row.site_name.casefold(),
        "up": lambda row: row.up_count,
        "down": lambda row: row.down_count,
        "unknown": lambda row: row.unknown_count,
        "availability": lambda row: row.availability if row.availability is not None else -1,
    }
    site_rows.sort(
        key=site_sort_keys[site_sort_state.column],
        reverse=site_sort_state.direction == "desc",
    )

    sites = session.scalars(select(Site).order_by(Site.display_order, Site.id)).all()
    kind_options = (
        (TargetKind.SERVER.value, "Серверы"),
        (TargetKind.COMPUTER.value, "Компьютеры"),
        (TargetKind.NETWORK.value, "Сеть"),
        (TargetKind.PRINTER.value, "Принтеры"),
        (TargetKind.UPS.value, "ИБП"),
        (TargetKind.CAMERA.value, "Камеры"),
        (TargetKind.WEBSITE.value, "Сайты"),
        (TargetKind.SERVICE.value, "Сервисы"),
    )
    return templates.TemplateResponse(
        request=request,
        name="reports.html",
        context=template_context(
            request,
            auth,
            report_rows=report_rows,
            site_rows=site_rows,
            sites=sites,
            selected_site=selected_site,
            selected_kind=selected_kind,
            selected_hours=hours,
            kind_options=kind_options,
            kind_labels=dict(kind_options),
            pager=pager,
            sort_state=sort_state,
            site_sort_state=site_sort_state,
            report_export_query=urlencode(
                {
                    "hours": hours,
                    "site_id": selected_site,
                    "kind": selected_kind,
                    "sort": sort_state.column,
                    "direction": sort_state.direction,
                    "site_sort": site_sort_state.column,
                    "site_direction": site_sort_state.direction,
                }
            ),
        ),
    )


@router.get("/reports/export/{export_format}")
def reports_export(
    export_format: str,
    request: Request,
    session: DbSession,
    auth: CurrentAuth,
) -> Response:
    if export_format not in {"xlsx", "pdf"}:
        raise HTTPException(status_code=404, detail="Неизвестный формат экспорта")
    allowed_hours = {24, 168, 720, 2160}
    hours = positive_int(request.query_params.get("hours"), 168)
    if hours not in allowed_hours:
        hours = 168
    selected_site = positive_int(request.query_params.get("site_id"), 0)
    selected_kind = request.query_params.get("kind", "all")
    allowed_kinds = {"all", *(item.value for item in TargetKind)}
    if selected_kind not in allowed_kinds:
        selected_kind = "all"

    targets, site_rows = availability_report(
        session,
        hours=hours,
        site_id=selected_site,
        kind=selected_kind,
    )
    sort_state = SortState.from_request(
        request,
        {"site", "target", "kind", "up", "down", "unknown", "availability"},
        "site",
    )
    report_sort_keys = {
        "site": lambda row: row.site_name.casefold(),
        "target": lambda row: row.target_name.casefold(),
        "kind": lambda row: row.kind.casefold(),
        "up": lambda row: row.up_count,
        "down": lambda row: row.down_count,
        "unknown": lambda row: row.unknown_count,
        "availability": lambda row: row.availability if row.availability is not None else -1,
    }
    targets.sort(
        key=report_sort_keys[sort_state.column],
        reverse=sort_state.direction == "desc",
    )
    site_sort_state = SortState.from_request(
        request,
        {"site", "up", "down", "unknown", "availability"},
        "site",
        column_parameter="site_sort",
        direction_parameter="site_direction",
    )
    site_sort_keys = {
        "site": lambda row: row.site_name.casefold(),
        "up": lambda row: row.up_count,
        "down": lambda row: row.down_count,
        "unknown": lambda row: row.unknown_count,
        "availability": lambda row: row.availability if row.availability is not None else -1,
    }
    site_rows.sort(
        key=site_sort_keys[site_sort_state.column],
        reverse=site_sort_state.direction == "desc",
    )
    kind_labels = {
        TargetKind.SERVER.value: "Серверы",
        TargetKind.COMPUTER.value: "Компьютеры",
        TargetKind.NETWORK.value: "Сеть",
        TargetKind.PRINTER.value: "Принтеры",
        TargetKind.UPS.value: "ИБП",
        TargetKind.CAMERA.value: "Камеры",
        TargetKind.WEBSITE.value: "Сайты",
        TargetKind.SERVICE.value: "Сервисы",
    }
    site_name = "Все площадки"
    if selected_site:
        site = session.get(Site, selected_site)
        site_name = site.name if site is not None else f"Площадка #{selected_site}"
    period_labels = {24: "24 часа", 168: "7 дней", 720: "30 дней", 2160: "90 дней"}
    kind_name = (
        "Все типы" if selected_kind == "all" else kind_labels.get(selected_kind, selected_kind)
    )
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")

    if export_format == "xlsx":
        data = xlsx_sheets_bytes(
            (
                (
                    "Площадки",
                    ("Площадка", "Успешно", "Ошибки", "Нет данных", "Доступность, %"),
                    (
                        (
                            row.site_name,
                            row.up_count,
                            row.down_count,
                            row.unknown_count,
                            row.availability,
                        )
                        for row in site_rows
                    ),
                ),
                (
                    "Объекты",
                    (
                        "Площадка",
                        "Объект",
                        "Тип",
                        "Успешно",
                        "Ошибки",
                        "Нет данных",
                        "Доступность, %",
                    ),
                    (
                        (
                            row.site_name,
                            row.target_name,
                            kind_labels.get(row.kind, row.kind),
                            row.up_count,
                            row.down_count,
                            row.unknown_count,
                            row.availability,
                        )
                        for row in targets
                    ),
                ),
            )
        )
        return Response(
            data,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f'attachment; filename="availability-{stamp}.xlsx"'},
        )

    data = availability_pdf_bytes(
        period_label=period_labels[hours],
        site_label=site_name,
        kind_label=kind_name,
        site_rows=site_rows,
        target_rows=targets,
        kind_labels=kind_labels,
    )
    return Response(
        data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="availability-{stamp}.pdf"'},
    )


@router.get("/targets/{target_id}/history", response_class=HTMLResponse)
def target_history_page(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: CurrentAuth,
) -> HTMLResponse:
    allowed_hours = {24, 168, 720, 2160}
    hours = positive_int(request.query_params.get("hours"), 24)
    if hours not in allowed_hours:
        hours = 24
    try:
        history = target_history(session, target_id, hours=hours)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    snmp_config = session.get(SnmpConfig, target_id)
    # These are bounded, target-scoped current-state reads. They reuse the persisted
    # SNMP runtime and never cause a poll or history scan from the history page.
    supplies = session.scalars(
        select(SnmpSupply)
        .where(SnmpSupply.target_id == target_id, SnmpSupply.present.is_(True))
        .order_by(SnmpSupply.hr_device_index, SnmpSupply.supply_index)
    ).all()
    ups_state = session.get(SnmpUpsState, target_id)
    sort_state = SortState.from_request(
        request,
        {"checked_at", "status", "latency", "message"},
        "checked_at",
        "desc",
    )
    history_sort_keys = {
        "checked_at": lambda item: item.checked_at,
        "status": lambda item: item.status,
        "latency": lambda item: item.latency_ms if item.latency_ms is not None else -1,
        "message": lambda item: (item.message or "").casefold(),
    }
    history.results.sort(
        key=history_sort_keys[sort_state.column],
        reverse=sort_state.direction == "desc",
    )
    pager = Pagination.from_request(request, len(history.results), default_per_page=20)
    history_results = history.results[pager.offset : pager.offset + pager.per_page]
    snmp_graph_choices, snmp_graph, snmp_graph_selection = build_snmp_history_graph(
        session,
        target_id,
        hours=hours,
        selection=request.query_params.get("snmp_graph"),
    )
    history_availability = (
        "off_hours"
        if not schedule_is_working(
            history.site.schedule,
            datetime.now(UTC),
            schedule_timezone(session),
        )
        else history.latest_status
    )
    target_health = get_targets_health(session, {target_id: history_availability}).get(target_id)
    return templates.TemplateResponse(
        request=request,
        name="target_history.html",
        context=template_context(
            request,
            auth,
            history=history,
            target_health=target_health,
            snmp_config=snmp_config,
            supplies=supplies,
            ups_state=ups_state,
            supply_level_label=supply_level_label,
            battery_status_label=battery_status_label,
            output_source_label=output_source_label,
            history_results=history_results,
            pager=pager,
            selected_hours=hours,
            snmp_graph_choices=snmp_graph_choices,
            snmp_graph=snmp_graph,
            snmp_graph_selection=snmp_graph_selection,
            kind_labels={
                "server": "Серверы",
                "computer": "Компьютеры",
                "network": "Сеть",
                "printer": "Принтеры",
                "ups": "ИБП",
                "camera": "Камеры",
                "website": "Сайты",
                "service": "Сервисы",
            },
            display_datetime=session_datetime_formatter(session),
            format_bytes=format_bytes,
            sort_state=sort_state,
        ),
    )


SETTING_LABELS = {
    "default_check_interval_seconds": "Интервал проверки по умолчанию",
    "failures_before_incident": "Ошибок до инцидента",
    "history_retention_days": "Хранение истории, дней",
    "target_history_max_results": "Максимум результатов объекта",
    "audit_retention_days": "Хранение журнала аудита, дней",
    "notification_retention_days": "Хранение оповещений, дней",
    "min_password_length": "Минимальная длина пароля",
    "notifications_enabled": "Уведомления",
    "display_timezone": "Часовой пояс интерфейса",
    "portal_metric_interval_seconds": "Запись состояния портала, секунд",
    "portal_metric_retention_hours": "Хранение показателей портала, часов",
    "snmp_sample_retention_days": "Хранение SNMP samples, дней",
    "snmp_sample_max_per_target": "Максимум записей SNMP data на объект",
    "tls_expiry_warning_enabled": "Предупреждать об окончании TLS-сертификата",
    "tls_expiry_warning_days": "Срок предупреждения об окончании TLS-сертификата, дней",
}


SETTING_DEFAULTS = {
    "default_check_interval_seconds": "300 секунд",
    "failures_before_incident": "2 ошибки подряд",
    "history_retention_days": "90 дней",
    "target_history_max_results": "1000 записей",
    "audit_retention_days": "7 дней",
    "notification_retention_days": "30 дней",
    "min_password_length": "8 символов",
    "notifications_enabled": "включено",
    "display_timezone": "Europe/Moscow",
    "portal_metric_interval_seconds": "60 секунд",
    "portal_metric_retention_hours": "168 часов (7 дней)",
    "snmp_sample_retention_days": "30 дней",
    "snmp_sample_max_per_target": "1000 записей",
    "tls_expiry_warning_enabled": "включено",
    "tls_expiry_warning_days": "14 дней",
}

_SETTING_HELP_BASE = {
    "default_check_interval_seconds": "Интервал, который подставляется новым объектам. Меньшее значение даёт более частые проверки и увеличивает сетевую и серверную нагрузку.",
    "failures_before_incident": "Сколько подряд неудачных проверок требуется для открытия инцидента. Большее значение уменьшает ложные срабатывания, но замедляет фиксацию реальной проблемы.",
    "history_retention_days": "Сколько дней хранить подробные результаты проверок объектов. Более долгий срок увеличивает объём базы данных.",
    "target_history_max_results": "Максимум последних результатов одного объекта, используемых для его статистики и графика. Таблица при этом отображается страницами.",
    "audit_retention_days": "Сколько дней хранить журнал действий пользователей и изменений настроек. Более старые записи удаляются автоматически.",
    "notification_retention_days": "Сколько дней хранить внутренние оповещения пользователей. Более старые записи автоматически удаляются; сообщения чата эта настройка не затрагивает.",
    "min_password_length": "Минимальная длина нового пароля пользователя. Уже созданные пароли автоматически не меняются.",
    "notifications_enabled": "Главный переключатель внешних каналов. По умолчанию: включено. При включении работают настроенные SMTP, PWA Push и будущие внешние каналы. Внутренний центр оповещений продолжает работать даже при выключении.",
    "display_timezone": "Часовой пояс IANA для дат интерфейса и определения рабочего времени площадок. Указывайте имя зоны, а не UTC+3 или MSK. Примеры: Europe/Moscow, Europe/Kaliningrad, Asia/Yekaterinburg, Asia/Novosibirsk, Asia/Irkutsk, Asia/Vladivostok.",
    "portal_metric_interval_seconds": "Как часто сохранять показатели CPU, памяти, диска и сети сервера портала для исторических графиков.",
    "portal_metric_retention_hours": "Сколько часов хранить исторические показатели сервера портала. Больший срок требует больше места в базе.",
    "snmp_sample_retention_days": "Сколько дней хранить числовую историю ручных SNMP-метрик. Последние текстовые значения и настройки SNMP эта очистка не затрагивает.",
    "snmp_sample_max_per_target": "Максимум числовых SNMP samples на один объект независимо от их возраста. При уменьшении значения самые старые записи удаляются сразу. Одновременно действует настройка хранения в днях.",
    "tls_expiry_warning_enabled": "Включает предупреждения администраторам о приближении срока окончания активного TLS-сертификата.",
    "tls_expiry_warning_days": "За сколько дней до окончания активного TLS-сертификата отправлять предупреждение администраторам.",
}

SETTING_HELP = {
    key: f"{text} По умолчанию: {SETTING_DEFAULTS[key]}."
    for key, text in _SETTING_HELP_BASE.items()
}

SMTP_HELP = {
    "enabled": "Разрешает автоматическую отправку писем через SMTP. Для отправки также должен быть включён общий переключатель «Уведомления». Ручное тестовое письмо остаётся доступно для проверки настроек. По умолчанию: включено.",
    "host": "Адрес SMTP-сервера, через который портал отправляет уведомления. По умолчанию: не задан.",
    "port": "Порт SMTP-сервера. Для STARTTLS обычно используется 587. По умолчанию: 587.",
    "username": "Логин для авторизации на SMTP-сервере. Оставьте пустым, если сервер не требует авторизации. По умолчанию: не задан.",
    "password": "Пароль SMTP. Сохранённый пароль не выводится обратно; пустое поле оставляет его без изменений. По умолчанию: не задан.",
    "sender": "Адрес, который будет указан отправителем уведомлений. По умолчанию: не задан.",
    "recipient": "Один или несколько адресов получателей. Их можно разделять запятой, точкой с запятой или новой строкой. По умолчанию: не задано.",
    "starttls": "Включает защищённое соединение STARTTLS. Обычно используется с портом 587. По умолчанию: включено.",
}


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, session: DbSession, auth: CurrentAuth) -> HTMLResponse:
    availability_warning_threshold, availability_good_threshold = availability_color_thresholds(
        session
    )
    items = [
        item
        for item in session.scalars(select(AppSetting).order_by(AppSetting.key)).all()
        if item.key not in SMTP_SETTING_KEYS
        and item.key
        not in {
            "push_vapid_private_key",
            "push_vapid_public_key",
            "push_vapid_subject",
            "https_enabled",
            "https_redirect_http",
            "availability_warning_threshold_percent",
            "availability_good_threshold_percent",
        }
    ]
    app_settings = get_settings()
    tls_status = TlsManager(app_settings).status()
    https_enabled = (
        session.get(AppSetting, "https_enabled").value
        if session.get(AppSetting, "https_enabled")
        else "false"
    ) == "true"
    https_redirect_http = (
        session.get(AppSetting, "https_redirect_http").value
        if session.get(AppSetting, "https_redirect_http")
        else "false"
    ) == "true"
    tls_warning_enabled = (
        session.get(AppSetting, "tls_expiry_warning_enabled").value
        if session.get(AppSetting, "tls_expiry_warning_enabled")
        else "false"
    ) == "true"
    tls_warning_days = (
        session.get(AppSetting, "tls_expiry_warning_days").value
        if session.get(AppSetting, "tls_expiry_warning_days")
        else "14"
    )
    email = load_smtp_settings(session, app_settings)
    push_subscriptions = (
        session.scalar(
            select(func.count(PushSubscription.id)).where(PushSubscription.user_id == auth.user.id)
        )
        or 0
    )
    push_subscription_rows = []
    backup_rows = []
    backup_candidate = None
    backup_candidate_token = request.query_params.get("backup_candidate", "")
    backup_candidate_error = ""
    backup_sort_state = SortState.from_request(
        request,
        {"created_at", "backup_type", "creation_mode", "app_version", "size_bytes"},
        "created_at",
        "desc",
        column_parameter="backup_sort",
        direction_parameter="backup_direction",
    )
    if auth.user.role == "admin":
        push_subscription_rows = session.execute(
            select(PushSubscription, User)
            .join(User, PushSubscription.user_id == User.id)
            .order_by(PushSubscription.updated_at.desc(), PushSubscription.id.desc())
        ).all()
        backup_rows = list_backups(app_settings)
        backup_sort_keys = {
            "created_at": lambda item: (item.created_at, item.filename.casefold()),
            "backup_type": lambda item: (
                item.backup_type_label.casefold(),
                item.filename.casefold(),
            ),
            "creation_mode": lambda item: (
                item.creation_mode_label.casefold(),
                item.filename.casefold(),
            ),
            "app_version": lambda item: (item.app_version.casefold(), item.filename.casefold()),
            "size_bytes": lambda item: (item.size_bytes, item.filename.casefold()),
        }
        backup_rows = sorted(
            backup_rows,
            key=backup_sort_keys[backup_sort_state.column],
            reverse=backup_sort_state.direction == "desc",
        )
        if backup_candidate_token:
            try:
                backup_candidate = inspect_backup(
                    staged_backup_path(app_settings, backup_candidate_token),
                    verify_integrity=True,
                )
            except BackupError as exc:
                backup_candidate_error = str(exc)
                backup_candidate_token = ""
    response = templates.TemplateResponse(
        request=request,
        name="settings.html",
        context=template_context(
            request,
            auth,
            settings_items=items,
            setting_labels=SETTING_LABELS,
            setting_help=SETTING_HELP,
            smtp_help=SMTP_HELP,
            email_config={
                "configured": email.configured,
                "enabled": email.channel_enabled,
                "host": email.host,
                "port": email.port,
                "username": email.username,
                "sender": email.sender,
                "recipient": email.recipient,
                "starttls": email.use_starttls,
                "password_configured": bool(email.password),
            },
            backup_rows=backup_rows,
            push_subscriptions=int(push_subscriptions),
            push_subscription_rows=push_subscription_rows,
            push_device_label=push_device_label,
            tls_status=tls_status,
            https_enabled=https_enabled,
            https_redirect_http=https_redirect_http,
            tls_warning_enabled=tls_warning_enabled,
            tls_warning_days=tls_warning_days,
            availability_warning_threshold=availability_warning_threshold,
            availability_good_threshold=availability_good_threshold,
            internal_ca_default_ip=request_ip_hostname(request),
            backup_sort_state=backup_sort_state,
            backup_candidate=backup_candidate,
            backup_candidate_token=backup_candidate_token,
            backup_candidate_error=backup_candidate_error,
            backup_database_nonempty=database_has_meaningful_data(session),
            human_size=human_size,
            display_datetime=session_datetime_formatter(session),
        ),
    )
    legacy_token = request.cookies.get(app_settings.session_cookie_name)
    https_cookie = session_cookie_name(app_settings, request)
    if is_https_request(request) and legacy_token and not request.cookies.get(https_cookie):
        set_session_cookie(response, legacy_token, app_settings, secure=True, name=https_cookie)
        response.delete_cookie(
            app_settings.session_cookie_name,
            httponly=True,
            secure=True,
            samesite="lax",
            path="/",
        )
    return response


@router.post("/settings")
def settings_update(
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    key: Annotated[str, Form()],
    value: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    if not verify_session_csrf(auth.user_session.csrf_token, csrf_token):
        raise HTTPException(
            status_code=400,
            detail="Недействительный CSRF-токен",
        )
    current_setting = session.get(AppSetting, key)
    old_value = current_setting.value if current_setting is not None else None
    try:
        setting = update_setting(session, key, value)
    except ValueError as exc:
        return RedirectResponse(
            f"/settings?error={quote_plus(str(exc))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    if setting.key == "snmp_sample_max_per_target":
        for target_id in session.scalars(select(MonitorTarget.id)).all():
            trim_snmp_samples_for_target(session, target_id)
    write_audit(
        session,
        "setting.updated",
        user_id=auth.user.id,
        entity_type="setting",
        entity_id=setting.key,
        entity_name=setting.key,
        details=audit_changes({"value": old_value}, {"value": setting.value})
        or {"unchanged": True},
        ip_address=client_ip(request),
    )
    session.commit()
    return RedirectResponse(
        f"/settings?notice={quote_plus('Настройка сохранена')}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/settings/availability-thresholds")
def availability_thresholds_update(
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    warning_threshold: Annotated[str, Form()],
    good_threshold: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    if not verify_session_csrf(auth.user_session.csrf_token, csrf_token):
        raise HTTPException(status_code=400, detail="Недействительный CSRF-токен")
    try:
        warning = int(warning_threshold.strip())
        good = int(good_threshold.strip())
        if warning >= good:
            raise ValueError("Жёлтый порог должен быть меньше зелёного")
        old_warning, old_good = availability_color_thresholds(session)
        warning_setting = update_setting(
            session, "availability_warning_threshold_percent", str(warning)
        )
        good_setting = update_setting(session, "availability_good_threshold_percent", str(good))
    except ValueError as exc:
        return RedirectResponse(
            f"/settings?error={quote_plus(str(exc))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    write_audit(
        session,
        "availability.thresholds_updated",
        user_id=auth.user.id,
        entity_type="setting",
        entity_id="availability_color_thresholds",
        entity_name="Пороги доступности",
        details=audit_changes(
            {"warning": old_warning, "good": old_good},
            {"warning": warning_setting.value, "good": good_setting.value},
        )
        or {"unchanged": True},
        ip_address=client_ip(request),
    )
    session.commit()
    return RedirectResponse(
        f"/settings?notice={quote_plus('Пороги доступности сохранены')}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/settings/push/subscriptions/{subscription_id}/test")
def push_subscription_test(
    subscription_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    if not verify_session_csrf(auth.user_session.csrf_token, csrf_token):
        raise HTTPException(status_code=400, detail="Недействительный CSRF-токен")
    if not set_vapid_subject(session, str(request.base_url)):
        return RedirectResponse(
            "/settings?error="
            + quote_plus("Тестовый Push доступен только при открытии портала по HTTPS"),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    session.commit()
    result = send_test_push_to_subscription(subscription_id)
    write_audit(
        session,
        "push.test_sent" if result.sent else "push.test_failed",
        user_id=auth.user.id,
        entity_type="push_subscription",
        entity_id=str(subscription_id),
        details={"sent": result.sent, "failed": result.failed},
        ip_address=client_ip(request),
    )
    session.commit()
    if result.sent:
        message = "Тестовый Push отправлен"
        parameter = "notice"
    else:
        message = result.message or "Тестовый Push не отправлен"
        parameter = "error"
    return RedirectResponse(
        f"/settings?{parameter}={quote_plus(message)}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/settings/push/subscriptions/{subscription_id}/delete")
def push_subscription_delete(
    subscription_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    if not verify_session_csrf(auth.user_session.csrf_token, csrf_token):
        raise HTTPException(status_code=400, detail="Недействительный CSRF-токен")
    row = delete_subscription_by_id(session, subscription_id)
    if row is None:
        return RedirectResponse(
            "/settings?error=" + quote_plus("Push-подписка уже удалена"),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    write_audit(
        session,
        "push.subscription_deleted",
        user_id=auth.user.id,
        entity_type="push_subscription",
        entity_id=str(subscription_id),
        entity_name=f"пользователь ID {row.user_id}",
        ip_address=client_ip(request),
    )
    session.commit()
    return RedirectResponse(
        "/settings?notice=" + quote_plus("Push-подписка удалена"),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/settings/https/candidate")
def https_candidate_upload(
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    certificate: Annotated[UploadFile, File()],
    private_key: Annotated[UploadFile, File()],
) -> RedirectResponse:
    if not verify_session_csrf(auth.user_session.csrf_token, csrf_token):
        raise HTTPException(
            status_code=400,
            detail="Недействительный CSRF-токен",
        )
    try:
        result = TlsManager(get_settings()).upload_candidate(certificate.file, private_key.file)
    except TlsManagerError as exc:
        return RedirectResponse(
            f"/settings?error={quote_plus(str(exc))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    finally:
        certificate.file.close()
        private_key.file.close()
    write_audit(
        session,
        "https.candidate_validated",
        user_id=auth.user.id,
        entity_type="https",
        details={"expires_at": result.get("expires_at")},
        ip_address=client_ip(request),
    )
    session.commit()
    return RedirectResponse(
        "/settings?notice=" + quote_plus("TLS-кандидат проверен и готов к активации"),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/settings/https/internal-ca")
def https_internal_ca(
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    common_name: Annotated[str, Form()],
    dns_names: Annotated[str, Form()] = "",
    ip_addresses: Annotated[str, Form()] = "",
) -> RedirectResponse:
    if not verify_session_csrf(auth.user_session.csrf_token, csrf_token):
        raise HTTPException(status_code=400, detail="Недействительный CSRF-токен")
    names = [value.strip() for value in dns_names.replace(";", ",").split(",") if value.strip()]
    addresses = [
        value.strip() for value in ip_addresses.replace(";", ",").split(",") if value.strip()
    ]
    try:
        result = TlsManager(get_settings()).create_internal_candidate(
            common_name=common_name, dns_names=names, ip_addresses=addresses
        )
    except TlsManagerError as exc:
        return RedirectResponse(
            "/settings?error=" + quote_plus(str(exc)), status_code=status.HTTP_303_SEE_OTHER
        )
    write_audit(
        session,
        "https.internal_ca_candidate_created",
        user_id=auth.user.id,
        entity_type="https",
        details={
            "expires_at": result.get("expires_at"),
            "dns_names": names,
            "ip_addresses": addresses,
        },
        ip_address=client_ip(request),
    )
    session.commit()
    return RedirectResponse(
        "/settings?notice=" + quote_plus("Внутренний CA и TLS-кандидат готовы к активации"),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/settings/https/internal-ca/certificate")
def https_internal_ca_download(session: DbSession, auth: AdminAuth) -> Response:
    certificate = TlsManager(get_settings()).internal_ca_certificate()
    return Response(
        certificate,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": "attachment; filename=monitoring-maxval-internal-ca.pem"},
    )


@router.post("/settings/https/warnings")
def https_warning_settings(
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    enabled: Annotated[str | None, Form()] = None,
    days: Annotated[str, Form()] = "14",
) -> RedirectResponse:
    if not verify_session_csrf(auth.user_session.csrf_token, csrf_token):
        raise HTTPException(status_code=400, detail="Недействительный CSRF-токен")
    try:
        update_setting(
            session, "tls_expiry_warning_enabled", "true" if enabled == "true" else "false"
        )
        update_setting(session, "tls_expiry_warning_days", days)
    except ValueError as exc:
        return RedirectResponse(
            "/settings?error=" + quote_plus(str(exc)), status_code=status.HTTP_303_SEE_OTHER
        )
    session.commit()
    return RedirectResponse(
        "/settings?notice=" + quote_plus("Предупреждение о сроке сертификата сохранено"),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/settings/https")
def https_update(
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    https_enabled: Annotated[str | None, Form()] = None,
    https_redirect_http: Annotated[str | None, Form()] = None,
) -> RedirectResponse:
    if not verify_session_csrf(auth.user_session.csrf_token, csrf_token):
        raise HTTPException(
            status_code=400,
            detail="Недействительный CSRF-токен",
        )
    enabled = https_enabled == "true"
    redirect = https_redirect_http == "true"
    manager = TlsManager(get_settings())
    status_info = manager.status()
    redirect_allowed = enabled and status_info.active_valid and status_info.active_redirect_safe
    if redirect and not redirect_allowed:
        message = (
            "Перенаправление HTTP недоступно: до окончания активного сертификата "
            "осталось не более двух суток. Замените сертификат; прямой HTTP остаётся доступен."
            if status_info.active_valid and not status_info.active_redirect_safe
            else "Перенаправление доступно только при включённом и проверенном HTTPS"
        )
        return RedirectResponse(
            "/settings?error=" + quote_plus(message),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    try:
        manager.apply(https_enabled=enabled, redirect_http=redirect)
    except TlsManagerError as exc:
        return RedirectResponse(
            f"/settings?error={quote_plus(str(exc))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    session.get(AppSetting, "https_enabled").value = "true" if enabled else "false"
    session.get(AppSetting, "https_redirect_http").value = (
        "true" if redirect and enabled else "false"
    )
    write_audit(
        session,
        "https.settings_updated",
        user_id=auth.user.id,
        entity_type="https",
        details={"enabled": enabled, "redirect_http": redirect and enabled},
        ip_address=client_ip(request),
    )
    session.commit()
    destination = "/settings?notice=" + quote_plus("Настройки HTTPS применены")
    response = RedirectResponse(destination, status_code=status.HTTP_303_SEE_OTHER)
    if not enabled:
        app_settings = get_settings()
        raw_token = session_token(request, app_settings)
        if raw_token:
            set_session_cookie(
                response,
                raw_token,
                app_settings,
                secure=False,
                name=app_settings.session_cookie_name,
            )
            response.delete_cookie(
                session_cookie_name(app_settings, request),
                httponly=True,
                secure=True,
                samesite="lax",
                path="/",
            )
        forwarded_host = request.headers.get(
            "x-forwarded-host",
            request.headers.get("host", ""),
        )
        hostname = forwarded_host.split(":", 1)[0]
        if request.url.scheme == "https" and hostname:
            response.headers["location"] = (
                f"http://{hostname}:{get_settings().http_public_port}{destination}"
            )
    return response


@router.post("/settings/https/rollback")
def https_rollback(
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    if not verify_session_csrf(auth.user_session.csrf_token, csrf_token):
        raise HTTPException(
            status_code=400,
            detail="Недействительный CSRF-токен",
        )
    try:
        TlsManager(get_settings()).rollback()
    except TlsManagerError as exc:
        return RedirectResponse(
            f"/settings?error={quote_plus(str(exc))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    session.get(AppSetting, "https_enabled").value = "true"
    session.get(AppSetting, "https_redirect_http").value = "false"
    write_audit(
        session,
        "https.rolled_back",
        user_id=auth.user.id,
        entity_type="https",
        ip_address=client_ip(request),
    )
    session.commit()
    return RedirectResponse(
        "/settings?notice=" + quote_plus("Восстановлена последняя рабочая TLS-конфигурация"),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/settings/smtp")
def settings_smtp_update(
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    # A fresh installation intentionally has no SMTP credentials.  All fields
    # except the CSRF token must therefore be optional at the HTTP boundary so
    # an administrator can switch this channel off before configuring it.
    smtp_host: Annotated[str, Form()] = "",
    smtp_port: Annotated[int, Form()] = 587,
    smtp_username: Annotated[str, Form()] = "",
    smtp_sender: Annotated[str, Form()] = "",
    smtp_recipient: Annotated[str, Form()] = "",
    smtp_password: Annotated[str, Form()] = "",
    smtp_enabled: Annotated[str | None, Form()] = None,
    smtp_starttls: Annotated[str | None, Form()] = None,
    clear_password: Annotated[str | None, Form()] = None,
) -> RedirectResponse:
    if not verify_session_csrf(auth.user_session.csrf_token, csrf_token):
        raise HTTPException(status_code=400, detail="Недействительный CSRF-токен")
    try:
        email = update_smtp_settings(
            session,
            get_settings(),
            SmtpForm(
                host=smtp_host,
                port=smtp_port,
                username=smtp_username,
                password=smtp_password,
                sender=smtp_sender,
                recipient=smtp_recipient,
                starttls=smtp_starttls == "true",
                enabled=smtp_enabled == "true",
                clear_password=clear_password == "true",
            ),
        )
    except (RuntimeError, ValueError) as exc:
        session.rollback()
        return RedirectResponse(
            f"/settings?error={quote_plus(str(exc))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    write_audit(
        session,
        "setting.smtp_updated",
        user_id=auth.user.id,
        entity_type="setting",
        entity_id="smtp",
        entity_name="SMTP",
        details={
            "configured": email.configured,
            "enabled": email.channel_enabled,
            "starttls": email.use_starttls,
            "password_configured": bool(email.password),
        },
        ip_address=client_ip(request),
    )
    session.commit()
    return RedirectResponse(
        f"/settings?notice={quote_plus('SMTP-настройки сохранены')}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/settings/test-email")
async def settings_test_email(
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    if not verify_session_csrf(auth.user_session.csrf_token, csrf_token):
        raise HTTPException(status_code=400, detail="Недействительный CSRF-токен")
    try:
        notifier = EmailNotifier(load_smtp_settings(session, get_settings()))
        await notifier.send(
            Notification(
                subject="[Мониторинг Maxval] Проверка почтовых уведомлений",
                body=(
                    "Тестовое письмо успешно отправлено из раздела настроек.\n\n"
                    f"Время: {session_datetime_formatter(session)(datetime.now(UTC))}\n"
                ),
            ),
            force=True,
        )
    except Exception as exc:
        logger.warning("SMTP test failed: %s", type(exc).__name__)
        write_audit(
            session,
            "notification.test_failed",
            user_id=auth.user.id,
            entity_type="email",
            ip_address=client_ip(request),
        )
        session.commit()
        message = smtp_error_message(exc)
        return RedirectResponse(
            f"/settings?error={quote_plus(f'Письмо не отправлено: {message}')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    write_audit(
        session,
        "notification.test_sent",
        user_id=auth.user.id,
        entity_type="email",
        ip_address=client_ip(request),
    )
    session.commit()
    return RedirectResponse(
        f"/settings?notice={quote_plus('Тестовое письмо отправлено')}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/incidents", response_class=HTMLResponse)
def incidents_page(request: Request, session: DbSession, auth: CurrentAuth) -> HTMLResponse:
    selected_kind = request.query_params.get("kind", "all")
    allowed_kinds = {kind.value for kind in TargetKind}
    if selected_kind not in {"all", *allowed_kinds}:
        selected_kind = "all"
    selected_incident_status = request.query_params.get("status", "all")
    if selected_incident_status not in {"all", "open", "resolved"}:
        selected_incident_status = "all"
    selected_target_id = positive_int(request.query_params.get("target_id"), 0)
    selected_target_name = None
    if selected_target_id:
        selected_target_name = session.scalar(
            select(MonitorTarget.name).where(MonitorTarget.id == selected_target_id)
        )
        if selected_target_name is None:
            selected_target_id = 0
    conditions = []
    if selected_kind != "all":
        conditions.append(MonitorTarget.kind == selected_kind)
    if selected_incident_status != "all":
        conditions.append(Incident.status == selected_incident_status)
    if selected_target_id:
        conditions.append(Incident.target_id == selected_target_id)
    total = (
        session.scalar(
            select(func.count(Incident.id))
            .select_from(Incident)
            .join(MonitorTarget, MonitorTarget.id == Incident.target_id)
            .where(*conditions)
        )
        or 0
    )
    pager = Pagination.from_request(request, total)
    focus_incident_id = positive_int(request.query_params.get("focus_id"), 0)
    incident_order = (
        case((Incident.status == IncidentStatus.OPEN, 0), else_=1),
        Incident.opened_at.desc(),
        Incident.id.desc(),
    )
    if focus_incident_id and "page" not in request.query_params:
        ordered_ids = list(
            session.scalars(
                select(Incident.id)
                .join(MonitorTarget, MonitorTarget.id == Incident.target_id)
                .where(*conditions)
                .order_by(*incident_order)
            ).all()
        )
        try:
            focus_index = ordered_ids.index(focus_incident_id)
        except ValueError:
            focus_index = None
        if focus_index is not None:
            focus_page = focus_index // pager.per_page + 1
            pager = Pagination(
                page=focus_page,
                pages=pager.pages,
                per_page=pager.per_page,
                total=pager.total,
                offset=(focus_page - 1) * pager.per_page,
            )
    rows = session.execute(
        select(Incident, MonitorTarget, Site)
        .join(MonitorTarget, MonitorTarget.id == Incident.target_id)
        .join(Site, Site.id == MonitorTarget.site_id)
        .where(*conditions)
        .order_by(*incident_order)
        .offset(pager.offset)
        .limit(pager.per_page)
    ).all()
    kind_options = (
        (TargetKind.SERVER.value, "Серверы"),
        (TargetKind.COMPUTER.value, "Компьютеры"),
        (TargetKind.NETWORK.value, "Сеть"),
        (TargetKind.PRINTER.value, "Принтеры"),
        (TargetKind.UPS.value, "ИБП"),
        (TargetKind.CAMERA.value, "Камеры"),
        (TargetKind.WEBSITE.value, "Сайты"),
        (TargetKind.SERVICE.value, "Сервисы"),
    )
    return templates.TemplateResponse(
        request=request,
        name="incidents.html",
        context=template_context(
            request,
            auth,
            incident_rows=rows,
            pager=pager,
            selected_kind=selected_kind,
            selected_incident_status=selected_incident_status,
            selected_target_id=selected_target_id,
            selected_target_name=selected_target_name,
            kind_options=kind_options,
            kind_labels=dict(kind_options),
            display_datetime=session_datetime_formatter(session),
        ),
    )
