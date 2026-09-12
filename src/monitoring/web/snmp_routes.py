from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Annotated

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import func, select

from monitoring.models import (
    CheckResult,
    MonitorTarget,
    SnmpConfig,
    SnmpInterface,
    SnmpMetric,
    SnmpSample,
    SnmpSupply,
    SnmpThreshold,
    SnmpUpsLine,
    SnmpUpsSample,
    SnmpUpsState,
)
from monitoring.services.audit import audit_changes, write_audit
from monitoring.services.pagination import Pagination, SortState
from monitoring.services.scheduler import CheckScheduler
from monitoring.services.snmp import (
    MAX_MANUAL_OIDS_PER_TARGET,
    SnmpMetricForm,
    SnmpService,
    SnmpSettingsForm,
    snmp_sample_limit,
)
from monitoring.services.snmp_discovery import (
    DISCOVERY_DEFAULT_PAGE_SIZE,
    MAX_DISCOVERY_RESULTS,
    discovery_roots,
    discovery_store,
)
from monitoring.services.snmp_graphs import SnmpGraphPanel, SnmpGraphSeries
from monitoring.services.snmp_interfaces import (
    MAX_MONITORED_INTERFACES,
    format_interface_rate,
    format_interface_speed,
    interface_status_label,
)
from monitoring.services.snmp_oid_catalog import DISCOVERY_CATEGORY_LABELS
from monitoring.services.snmp_order import move_metric
from monitoring.services.snmp_supplies import (
    supply_class_label,
    supply_level_label,
    supply_type_label,
    supply_unit_label,
)
from monitoring.services.snmp_thresholds import (
    SnmpThresholdService,
    validate_threshold_values,
)
from monitoring.services.snmp_ups import battery_status_label, output_source_label
from monitoring.services.system_metrics import chart_data, format_duration
from monitoring.services.time_display import session_datetime_formatter
from monitoring.web.admin_routes import redirect_with, require_csrf
from monitoring.web.dependencies import AdminAuth, CurrentAuth, DbSession, template_context
from monitoring.web.routes import templates
from monitoring.web.security import client_ip

router = APIRouter()
SNMP_SAMPLES_DEFAULT_PAGE_SIZE = 20
UPS_HISTORY_CHART_SAMPLE_LIMIT = 500
UPS_HISTORY_ALLOWED_HOURS = {24, 168, 720}


def _format_metric_value(value: Decimal) -> str:
    rendered = format(value, "f").rstrip("0").rstrip(".")
    return rendered or "0"


def _target_or_404(session: DbSession, target_id: int) -> MonitorTarget:
    target = session.get(MonitorTarget, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Объект не найден")
    return target


def _discovery_export_payload(target: MonitorTarget, discovery: object) -> dict[str, object]:
    """Serialize a short-lived discovery result without SNMP credentials."""
    # Kept next to the route rather than in the store: export is presentation only,
    # and the store intentionally knows nothing about target data or HTTP responses.
    from monitoring.services.snmp_discovery import SnmpDiscoveryResult

    assert isinstance(discovery, SnmpDiscoveryResult)
    return {
        "format": "monitoring-maxval-snmp-discovery-v1",
        "exported_at": datetime.now(UTC).isoformat(),
        "target": {"id": target.id, "name": target.name, "address": target.address},
        "discovery": {
            "status": discovery.status,
            "message": discovery.message,
            "roots": list(discovery.roots),
            "truncated": discovery.truncated,
            "elapsed_ms": discovery.elapsed_ms,
            "item_count": len(discovery.items),
        },
        "items": [
            {
                "oid": item.oid,
                "name": item.name,
                "value": item.value,
                "detected_type": item.detected_type,
                "error": item.error,
                "category": item.category,
                "category_label": item.category_label,
                "system": item.is_system,
                "recommended": item.recommended,
            }
            for item in discovery.items
        ],
    }


def _ups_history_context(
    session: DbSession, target_id: int, request: Request, hours: int
) -> tuple[int, list[SnmpGraphPanel], list[SnmpUpsSample], Pagination]:
    hours = hours if hours in UPS_HISTORY_ALLOWED_HOURS else 24
    now = datetime.now(UTC)
    since = now - timedelta(hours=hours)
    state = session.get(SnmpUpsState, target_id)
    chart_samples = session.scalars(
        select(SnmpUpsSample)
        .where(SnmpUpsSample.target_id == target_id)
        .order_by(SnmpUpsSample.collected_at.desc(), SnmpUpsSample.id.desc())
        .limit(UPS_HISTORY_CHART_SAMPLE_LIMIT)
    ).all()
    total_samples = (
        session.scalar(
            select(func.count())
            .select_from(SnmpUpsSample)
            .where(SnmpUpsSample.target_id == target_id)
        )
        or 0
    )
    pager = Pagination.from_request(
        request, total_samples, default_per_page=SNMP_SAMPLES_DEFAULT_PAGE_SIZE
    )
    samples = session.scalars(
        select(SnmpUpsSample)
        .where(SnmpUpsSample.target_id == target_id)
        .order_by(SnmpUpsSample.collected_at.desc(), SnmpUpsSample.id.desc())
        .offset(pager.offset)
        .limit(pager.per_page)
    ).all()
    def utc_value(value: datetime) -> datetime:
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)

    last_polled_at = state.last_polled_at if state is not None else None
    if last_polled_at is not None:
        last_polled_at = utc_value(last_polled_at)

    def metric_series(key: str, current_value: Decimal | None) -> list[tuple[datetime, float]]:
        result = [
            (utc_value(item.collected_at), float(item.value))
            for item in reversed(chart_samples)
            if item.metric_key == key and utc_value(item.collected_at) >= since
        ]
        # Samples deliberately retain only changes.  The state is refreshed by
        # every successful UPS polling, therefore it is safe to extend a graph
        # visually with a recent unchanged value without inserting a DB sample.
        if current_value is not None and last_polled_at is not None and last_polled_at >= since:
            current_timestamp = min(last_polled_at, now)
            if not result:
                result.append((since, float(current_value)))
            if result[-1][0] < current_timestamp:
                result.append((current_timestamp, float(current_value)))
            elif len(result) == 1:
                result.insert(0, (since, float(current_value)))
        return result

    def last_value(values: list[float]) -> str:
        if not values:
            return "—"
        return f"{values[-1]:.1f}".rstrip("0").rstrip(".")

    def panel(
        title: str,
        subtitle: str,
        unit: str,
        sources: list[tuple[str, str, Decimal | None, str]],
    ) -> SnmpGraphPanel | None:
        source_series = [
            (label, metric_series(key, current_value), css_class)
            for label, key, current_value, css_class in sources
        ]
        source_series = [item for item in source_series if item[1]]
        if not source_series:
            return None
        timestamps = sorted({point[0] for _, values, _ in source_series for point in values})
        combined_values = [value for _, values, _ in source_series for _, value in values]
        scale_max = chart_data(combined_values, [timestamps[-1]] * len(combined_values)).scale_max
        graph_series: list[SnmpGraphSeries] = []
        for label, values_at_time, css_class in source_series:
            values: list[float] = []
            index = 0
            current = values_at_time[0][1]
            for timestamp in timestamps:
                while index + 1 < len(values_at_time) and values_at_time[index + 1][0] <= timestamp:
                    index += 1
                    current = values_at_time[index][1]
                values.append(current)
            graph_series.append(
                SnmpGraphSeries(
                    label,
                    chart_data(values, timestamps, ceiling=scale_max).points,
                    css_class,
                    last_value(values),
                    tuple(values),
                )
            )
        return SnmpGraphPanel(
            title=title,
            subtitle=subtitle,
            unit=unit,
            series=tuple(graph_series),
            chart=chart_data(graph_series[0].values, timestamps, ceiling=scale_max),
        )

    charts: list[SnmpGraphPanel] = []
    for title, key, field, unit in (
        ("Заряд батареи", "battery_charge_percent", "battery_charge_percent", "%"),
        ("Автономность", "estimated_runtime_minutes", "estimated_runtime_minutes", "мин"),
        ("Напряжение батареи", "battery_voltage", "battery_voltage", "В"),
        ("Температура батареи", "battery_temperature", "battery_temperature", "°C"),
    ):
        item = panel(title, "Значение по данным UPS-MIB.", unit, [(title, key, getattr(state, field, None) if state else None, "snmp-series-metric")])
        if item is not None:
            charts.append(item)

    lines = session.scalars(
        select(SnmpUpsLine)
        .where(SnmpUpsLine.target_id == target_id)
        .order_by(SnmpUpsLine.direction, SnmpUpsLine.line_index)
    ).all()
    for title, subtitle, unit, field, directions in (
        ("Напряжение входа / выхода", "Напряжение по каждой доступной фазе.", "В", "voltage", {"input", "output"}),
        ("Ток входа / выхода", "Ток по каждой доступной фазе.", "А", "current", {"input", "output"}),
        ("Нагрузка выхода", "Процент нагрузки по каждой доступной фазе выхода.", "%", "load_percent", {"output"}),
    ):
        sources = []
        for line in lines:
            if line.direction not in directions:
                continue
            value = getattr(line, field)
            if value is None:
                continue
            direction = "Вход" if line.direction == "input" else "Выход"
            sources.append(
                (
                    f"{direction} L{line.line_index}",
                    f"{line.direction}_{field}:{line.line_index}",
                    value,
                    f"ups-series-{line.direction}-{line.line_index}",
                )
            )
        item = panel(title, subtitle, unit, sources)
        if item is not None:
            charts.append(item)
    return hours, charts, samples, pager


def _service(request: Request) -> SnmpService:
    scheduler: CheckScheduler | None = getattr(request.app.state, "scheduler", None)
    if scheduler is None or scheduler.snmp_service is None:
        raise HTTPException(status_code=503, detail="SNMP Core ещё не готов")
    return scheduler.snmp_service


def _settings_audit_state(config: SnmpConfig | None) -> dict[str, object]:
    if config is None:
        return {
            "enabled": False,
            "ups_enabled": False,
            "version": "v2c",
            "port": 161,
            "timeout_seconds": 3,
            "retries": 1,
        }
    return {
        "enabled": config.enabled,
        "ups_enabled": config.ups_enabled,
        "version": config.version,
        "port": config.port,
        "timeout_seconds": config.timeout_seconds,
        "retries": config.retries,
        "community_configured": bool(config.community_encrypted),
    }


def _metric_audit_state(metric: SnmpMetric) -> dict[str, object]:
    return {
        "name": metric.name,
        "source_kind": metric.source_kind,
        "oid": metric.oid or "",
        "formula": metric.formula or "",
        "unit": metric.unit or "",
        "enabled": metric.enabled,
    }


def _metric_form_draft(request: Request) -> dict[str, object] | None:
    """Return an unpersisted metric form after a validation error in this request."""
    draft = getattr(request.state, "snmp_metric_form_draft", None)
    return draft if isinstance(draft, dict) else None


@router.get("/targets/{target_id}/snmp", response_class=HTMLResponse)
def snmp_page(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: CurrentAuth,
) -> HTMLResponse:
    target = _target_or_404(session, target_id)
    metric_form_draft = _metric_form_draft(request)
    config = session.get(SnmpConfig, target_id)
    latest_status = session.scalar(
        select(CheckResult.status)
        .where(CheckResult.target_id == target_id)
        .order_by(CheckResult.checked_at.desc(), CheckResult.id.desc())
        .limit(1)
    )

    metric_sort_state = SortState.from_request(
        request,
        {
            "display_order",
            "name",
            "oid",
            "last_value",
            "unit",
            "detected_type",
            "last_collected_at",
            "last_error",
        },
        "display_order",
        "asc",
        column_parameter="metric_sort",
        direction_parameter="metric_direction",
    )
    metric_sort_columns = {
        "display_order": SnmpMetric.display_order,
        "name": SnmpMetric.name,
        "oid": SnmpMetric.oid,
        "last_value": SnmpMetric.last_value,
        "unit": SnmpMetric.unit,
        "detected_type": SnmpMetric.detected_type,
        "last_collected_at": SnmpMetric.last_collected_at,
        "last_error": SnmpMetric.last_error,
    }
    metric_order = metric_sort_state.order(
        metric_sort_columns[metric_sort_state.column]
    ).nulls_last()
    metrics = session.scalars(
        select(SnmpMetric)
        .where(SnmpMetric.target_id == target_id)
        .order_by(metric_order, SnmpMetric.id)
    ).all()
    monitored_interface_count = (
        session.scalar(
            select(func.count(SnmpInterface.id)).where(
                SnmpInterface.target_id == target_id,
                SnmpInterface.monitor_enabled.is_(True),
            )
        )
        or 0
    )
    threshold_count = (
        session.scalar(
            select(func.count(SnmpThreshold.id)).where(SnmpThreshold.target_id == target_id)
        )
        or 0
    )
    supply_count = (
        session.scalar(
            select(func.count(SnmpSupply.id)).where(
                SnmpSupply.target_id == target_id,
                SnmpSupply.present.is_(True),
            )
        )
        or 0
    )

    sample_sort_state = SortState.from_request(
        request,
        {"collected_at", "metric", "value", "unit"},
        "collected_at",
        "desc",
        column_parameter="sample_sort",
        direction_parameter="sample_direction",
    )
    sample_sort_columns = {
        "collected_at": SnmpSample.collected_at,
        "metric": SnmpMetric.name,
        "value": SnmpSample.value,
        "unit": SnmpMetric.unit,
    }
    sample_total = (
        session.scalar(
            select(func.count(SnmpSample.id))
            .join(SnmpMetric, SnmpMetric.id == SnmpSample.metric_id)
            .where(SnmpMetric.target_id == target_id)
        )
        or 0
    )
    sample_pager = Pagination.from_request(
        request,
        sample_total,
        default_per_page=SNMP_SAMPLES_DEFAULT_PAGE_SIZE,
    )
    sample_order = sample_sort_state.order(
        sample_sort_columns[sample_sort_state.column]
    ).nulls_last()
    samples = session.execute(
        select(SnmpSample, SnmpMetric)
        .join(SnmpMetric, SnmpMetric.id == SnmpSample.metric_id)
        .where(SnmpMetric.target_id == target_id)
        .order_by(sample_order, SnmpSample.id)
        .offset(sample_pager.offset)
        .limit(sample_pager.per_page)
    ).all()
    return templates.TemplateResponse(
        request=request,
        name="target_snmp.html",
        context=template_context(
            request,
            auth,
            target=target,
            config=config,
            metrics=metrics,
            metric_form_draft=metric_form_draft,
            metric_form_error=getattr(request.state, "snmp_metric_form_error", None),
            monitored_interface_count=monitored_interface_count,
            threshold_count=threshold_count,
            supply_count=supply_count,
            sample_total=sample_total,
            metric_sort_state=metric_sort_state,
            samples=samples,
            sample_pager=sample_pager,
            sample_sort_state=sample_sort_state,
            snmp_sample_max_per_target=snmp_sample_limit(session),
            latest_target_status=latest_status or "unknown",
            display_datetime=session_datetime_formatter(session),
            format_duration=format_duration,
            format_metric_value=_format_metric_value,
        ),
    )


@router.get("/targets/{target_id}/snmp/ups", response_class=HTMLResponse)
def snmp_ups_page(
    target_id: int, request: Request, session: DbSession, auth: CurrentAuth, hours: int = 24
) -> HTMLResponse:
    target = _target_or_404(session, target_id)
    state = session.get(SnmpUpsState, target_id)
    lines = (
        session.scalars(
            select(SnmpUpsLine)
            .where(SnmpUpsLine.target_id == target_id)
            .order_by(SnmpUpsLine.direction, SnmpUpsLine.line_index)
        ).all()
        if state is not None
        else ()
    )
    hours, charts, samples, pager = _ups_history_context(session, target_id, request, hours)
    return templates.TemplateResponse(
        request=request,
        name="target_snmp_ups.html",
        context=template_context(
            request,
            auth,
            target=target,
            config=session.get(SnmpConfig, target_id),
            state=state,
            lines=lines,
            battery_status_label=battery_status_label,
            output_source_label=output_source_label,
            hours=hours,
            charts=charts,
            samples=samples,
            pager=pager,
            display_datetime=session_datetime_formatter(session),
        ),
    )


@router.get("/targets/{target_id}/snmp/ups/history", response_class=HTMLResponse)
def snmp_ups_history_page(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: CurrentAuth,
    hours: int = 24,
) -> HTMLResponse:
    _target_or_404(session, target_id)
    hours = hours if hours in UPS_HISTORY_ALLOWED_HOURS else 24
    per_page = request.query_params.get("per_page", "")
    query = f"?hours={hours}"
    if per_page.isdecimal():
        query += f"&per_page={per_page}"
    return RedirectResponse(f"/targets/{target_id}/snmp/ups{query}#ups-history")


@router.post("/targets/{target_id}/snmp/ups/poll")
async def snmp_ups_poll(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    _target_or_404(session, target_id)
    scheduler: CheckScheduler | None = getattr(request.app.state, "scheduler", None)
    if scheduler is None:
        return redirect_with(
            f"/targets/{target_id}/snmp/ups", "error", "Сервис проверок ещё не готов"
        )
    try:
        result = await scheduler.poll_snmp_ups_now(target_id)
    except LookupError as exc:
        return redirect_with(f"/targets/{target_id}/snmp/ups", "error", str(exc))
    parameter = "notice" if result.status in {"ok", "disabled", "skipped"} else "error"
    return redirect_with(f"/targets/{target_id}/snmp/ups", parameter, result.message)


@router.post("/targets/{target_id}/snmp/settings")
def snmp_settings_update(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    enabled: Annotated[str | None, Form()] = None,
    version: Annotated[str, Form()] = "v2c",
    port: Annotated[int, Form()] = 161,
    community: Annotated[str, Form()] = "",
    timeout_seconds: Annotated[int, Form()] = 3,
    retries: Annotated[int, Form()] = 1,
    ups_enabled: Annotated[str | None, Form()] = None,
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    target = _target_or_404(session, target_id)
    service = _service(request)
    before = _settings_audit_state(session.get(SnmpConfig, target_id))
    try:
        config = service.save_settings(
            session,
            target_id,
            SnmpSettingsForm(
                enabled=enabled == "true",
                port=port,
                community=community,
                timeout_seconds=timeout_seconds,
                retries=retries,
                ups_enabled=ups_enabled == "true",
                version=version,
            ),
        )
    except (LookupError, RuntimeError, ValueError) as exc:
        session.rollback()
        return redirect_with(f"/targets/{target_id}/snmp", "error", str(exc))
    write_audit(
        session,
        "snmp.settings_updated",
        user_id=auth.user.id,
        entity_type="snmp",
        entity_id=target_id,
        entity_name=target.name,
        details=audit_changes(before, _settings_audit_state(config)) or {"unchanged": True},
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(f"/targets/{target_id}/snmp", "notice", "Настройки SNMP сохранены")


@router.post("/targets/{target_id}/snmp/test")
async def snmp_test(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    target = _target_or_404(session, target_id)
    scheduler: CheckScheduler | None = getattr(request.app.state, "scheduler", None)
    if scheduler is None:
        return redirect_with(f"/targets/{target_id}/snmp", "error", "Сервис проверок ещё не готов")
    try:
        result = await scheduler.test_snmp_now(target_id)
    except LookupError as exc:
        return redirect_with(f"/targets/{target_id}/snmp", "error", str(exc))
    write_audit(
        session,
        "snmp.tested",
        user_id=auth.user.id,
        entity_type="snmp",
        entity_id=target_id,
        entity_name=target.name,
        details={"status": result.status},
        ip_address=client_ip(request),
    )
    session.commit()
    if result.status == "ok":
        labels = {
            "sys_name": "sysName",
            "sys_descr": "sysDescr",
            "sys_object_id": "sysObjectID",
            "sys_uptime_ticks": "sysUpTime",
        }
        details = "; ".join(
            f"{labels[key]}: {value}" for key, value in result.values.items() if key in labels
        )
        return redirect_with(f"/targets/{target_id}/snmp", "notice", f"SNMP доступен. {details}")
    parameter = "notice" if result.status in {"disabled", "skipped"} else "error"
    return redirect_with(f"/targets/{target_id}/snmp", parameter, result.message)


@router.get("/targets/{target_id}/snmp/discovery", response_class=HTMLResponse)
def snmp_discovery_page(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
) -> HTMLResponse:
    target = _target_or_404(session, target_id)
    config = session.get(SnmpConfig, target_id)
    token = request.query_params.get("token", "").strip()
    discovery = discovery_store.get(token, target_id=target_id, user_id=auth.user.id)

    annotated_items = []
    if discovery is not None:
        monitored_oids = set(
            session.scalars(select(SnmpMetric.oid).where(SnmpMetric.target_id == target_id)).all()
        )
        annotated_items = [
            replace(item, is_monitored=item.oid in monitored_oids) for item in discovery.items
        ]

    query = request.query_params.get("q", "").strip().casefold()
    category_filter = request.query_params.get("category", "").strip()
    type_filter = request.query_params.get("type", "").strip()
    state_filter = request.query_params.get("state", "all").strip()
    recommended_only = request.query_params.get("recommended", "") == "1"
    available_types = sorted({item.detected_type for item in annotated_items})

    if category_filter and category_filter not in DISCOVERY_CATEGORY_LABELS:
        category_filter = ""

    filtered_items = annotated_items
    if query:
        filtered_items = [
            item
            for item in filtered_items
            if query in " ".join((item.name or "", item.oid, item.value or "")).casefold()
        ]
    if category_filter:
        filtered_items = [item for item in filtered_items if item.category == category_filter]
    if type_filter:
        filtered_items = [item for item in filtered_items if item.detected_type == type_filter]
    if recommended_only:
        filtered_items = [item for item in filtered_items if item.recommended]
    if state_filter == "new":
        filtered_items = [item for item in filtered_items if item.selectable]
    elif state_filter == "monitored":
        filtered_items = [item for item in filtered_items if item.is_monitored]
    elif state_filter == "system":
        filtered_items = [item for item in filtered_items if item.is_system]
    elif state_filter != "all":
        state_filter = "all"

    pager = Pagination.from_request(
        request,
        len(filtered_items),
        default_per_page=DISCOVERY_DEFAULT_PAGE_SIZE,
    )

    page_items = filtered_items[pager.offset : pager.offset + pager.per_page]
    metric_count = (
        session.scalar(select(func.count(SnmpMetric.id)).where(SnmpMetric.target_id == target_id))
        or 0
    )
    return templates.TemplateResponse(
        request=request,
        name="target_snmp_discovery.html",
        context=template_context(
            request,
            auth,
            target=target,
            config=config,
            discovery=discovery,
            discovery_token=token if discovery is not None else "",
            discovery_items=page_items,
            discovery_pager=pager,
            discovery_query=request.query_params.get("q", ""),
            discovery_category=category_filter,
            discovery_categories=DISCOVERY_CATEGORY_LABELS,
            discovery_type=type_filter,
            discovery_state=state_filter,
            discovery_recommended=recommended_only,
            discovery_types=available_types,
            max_discovery_results=MAX_DISCOVERY_RESULTS,
            metric_count=metric_count,
            metric_remaining=max(0, MAX_MANUAL_OIDS_PER_TARGET - metric_count),
        ),
    )


@router.get("/targets/{target_id}/snmp/discovery/export.json")
def snmp_discovery_export_json(
    target_id: int,
    token: str,
    session: DbSession,
    auth: AdminAuth,
) -> Response:
    target = _target_or_404(session, target_id)
    discovery = discovery_store.get(token, target_id=target_id, user_id=auth.user.id)
    if discovery is None:
        raise HTTPException(
            status_code=404,
            detail="Результат Discovery истёк. Выполните сканирование ещё раз.",
        )
    payload = _discovery_export_payload(target, discovery)
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    return Response(
        json.dumps(payload, ensure_ascii=False, indent=2),
        media_type="application/json; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="snmp-discovery-target-{target_id}-{stamp}.json"'
            )
        },
    )


@router.post("/targets/{target_id}/snmp/discovery/run")
async def snmp_discovery_run(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    mode: Annotated[str, Form()],
    custom_oid: Annotated[str, Form()] = "",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    target = _target_or_404(session, target_id)
    try:
        roots = discovery_roots(mode, custom_oid)
    except ValueError as exc:
        return redirect_with(f"/targets/{target_id}/snmp/discovery", "error", str(exc))

    scheduler: CheckScheduler | None = getattr(request.app.state, "scheduler", None)
    if scheduler is None:
        return redirect_with(
            f"/targets/{target_id}/snmp/discovery", "error", "Сервис проверок ещё не готов"
        )
    try:
        result = await scheduler.discover_snmp_now(target_id, roots)
    except LookupError as exc:
        return redirect_with(f"/targets/{target_id}/snmp/discovery", "error", str(exc))

    write_audit(
        session,
        "snmp.discovery_executed",
        user_id=auth.user.id,
        entity_type="snmp",
        entity_id=target_id,
        entity_name=target.name,
        details={
            "status": result.status,
            "roots": list(result.roots),
            "result_count": len(result.items),
            "truncated": result.truncated,
        },
        ip_address=client_ip(request),
    )
    session.commit()

    if result.status in {"ok", "partial"}:
        token = discovery_store.put(target_id=target_id, user_id=auth.user.id, result=result)
        return redirect_with(
            f"/targets/{target_id}/snmp/discovery?token={token}",
            "notice",
            result.message,
        )
    parameter = "notice" if result.status in {"disabled", "skipped"} else "error"
    return redirect_with(f"/targets/{target_id}/snmp/discovery", parameter, result.message)


@router.post("/targets/{target_id}/snmp/discovery/add")
async def snmp_discovery_add(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
) -> RedirectResponse:
    target = _target_or_404(session, target_id)
    form = await request.form()
    require_csrf(auth, str(form.get("csrf_token", "")))
    token = str(form.get("token", ""))
    discovery = discovery_store.get(token, target_id=target_id, user_id=auth.user.id)
    if discovery is None:
        return redirect_with(
            f"/targets/{target_id}/snmp/discovery",
            "error",
            "Результат Discovery истёк. Выполните сканирование ещё раз.",
        )

    selected_raw = form.getlist("selected_index")
    selected_indexes: list[int] = []
    try:
        selected_indexes = sorted({int(value) for value in selected_raw})
    except (TypeError, ValueError):
        return redirect_with(
            f"/targets/{target_id}/snmp/discovery?token={token}",
            "error",
            "Некорректный список выбранных OID",
        )
    if not selected_indexes:
        return redirect_with(
            f"/targets/{target_id}/snmp/discovery?token={token}",
            "notice",
            "Выберите хотя бы один OID",
        )

    discovered_by_oid = {item.oid: item for item in discovery.items}
    service = _service(request)
    created: list[SnmpMetric] = []
    try:
        for index in selected_indexes:
            oid = str(form.get(f"oid_{index}", ""))
            item = discovered_by_oid.get(oid)
            if item is None or item.is_system or item.error is not None:
                raise ValueError("Выбранный OID отсутствует в текущем результате Discovery")
            name = str(form.get(f"name_{index}", "")).strip() or item.name or item.oid
            unit = str(form.get(f"unit_{index}", ""))
            metric = service.add_metric(
                session,
                target_id,
                SnmpMetricForm(name=name, oid=item.oid, unit=unit, enabled=True),
            )
            session.flush()
            created.append(metric)
            write_audit(
                session,
                "snmp.metric_created",
                user_id=auth.user.id,
                entity_type="snmp",
                entity_id=metric.id,
                entity_name=target.name,
                details=_metric_audit_state(metric),
                ip_address=client_ip(request),
            )
    except (LookupError, ValueError) as exc:
        session.rollback()
        return redirect_with(
            f"/targets/{target_id}/snmp/discovery?token={token}", "error", str(exc)
        )
    session.commit()
    return redirect_with(
        f"/targets/{target_id}/snmp/discovery?token={token}",
        "notice",
        f"Добавлено SNMP OID: {len(created)}",
    )


@router.get("/targets/{target_id}/snmp/interfaces", response_class=HTMLResponse)
def snmp_interfaces_page(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: CurrentAuth,
) -> HTMLResponse:
    target = _target_or_404(session, target_id)
    config = session.get(SnmpConfig, target_id)
    latest_status = session.scalar(
        select(CheckResult.status)
        .where(CheckResult.target_id == target_id)
        .order_by(CheckResult.checked_at.desc(), CheckResult.id.desc())
        .limit(1)
    )
    query = request.query_params.get("q", "").strip().casefold()
    state_filter = request.query_params.get("state", "all").strip()
    interfaces = session.scalars(
        select(SnmpInterface)
        .where(SnmpInterface.target_id == target_id)
        .order_by(SnmpInterface.present.desc(), SnmpInterface.if_index)
    ).all()
    if query:
        interfaces = [
            item
            for item in interfaces
            if query
            in " ".join(
                (item.if_name or "", item.if_descr or "", item.if_alias or "", str(item.if_index))
            ).casefold()
        ]
    if state_filter == "monitored":
        interfaces = [item for item in interfaces if item.monitor_enabled]
    elif state_filter == "up":
        interfaces = [item for item in interfaces if item.present and item.oper_status == 1]
    elif state_filter == "down":
        interfaces = [item for item in interfaces if item.present and item.oper_status == 2]
    elif state_filter == "missing":
        interfaces = [item for item in interfaces if not item.present]
    elif state_filter != "all":
        state_filter = "all"
    monitored_count = (
        session.scalar(
            select(func.count(SnmpInterface.id)).where(
                SnmpInterface.target_id == target_id,
                SnmpInterface.monitor_enabled.is_(True),
            )
        )
        or 0
    )
    return templates.TemplateResponse(
        request=request,
        name="target_snmp_interfaces.html",
        context=template_context(
            request,
            auth,
            target=target,
            config=config,
            latest_target_status=latest_status,
            interfaces=interfaces,
            interface_query=request.query_params.get("q", ""),
            interface_state=state_filter,
            monitored_count=monitored_count,
            max_monitored_interfaces=MAX_MONITORED_INTERFACES,
            interface_status_label=interface_status_label,
            format_interface_rate=format_interface_rate,
            format_interface_speed=format_interface_speed,
            display_datetime=session_datetime_formatter(session),
        ),
    )


@router.post("/targets/{target_id}/snmp/interfaces/discover")
async def snmp_interfaces_discover(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    target = _target_or_404(session, target_id)
    scheduler: CheckScheduler | None = getattr(request.app.state, "scheduler", None)
    if scheduler is None:
        return redirect_with(
            f"/targets/{target_id}/snmp/interfaces", "error", "Сервис проверок ещё не готов"
        )
    try:
        result = await scheduler.discover_snmp_interfaces_now(target_id)
    except LookupError as exc:
        return redirect_with(f"/targets/{target_id}/snmp/interfaces", "error", str(exc))
    write_audit(
        session,
        "snmp.interfaces_discovered",
        user_id=auth.user.id,
        entity_type="snmp",
        entity_id=target_id,
        entity_name=target.name,
        details={
            "status": result.status,
            "interface_count": len(result.items),
            "truncated": result.truncated,
        },
        ip_address=client_ip(request),
    )
    session.commit()
    parameter = "notice" if result.status in {"ok", "disabled", "skipped"} else "error"
    return redirect_with(f"/targets/{target_id}/snmp/interfaces", parameter, result.message)


@router.post("/targets/{target_id}/snmp/interfaces/poll")
async def snmp_interfaces_poll(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    _target_or_404(session, target_id)
    scheduler: CheckScheduler | None = getattr(request.app.state, "scheduler", None)
    if scheduler is None:
        return redirect_with(
            f"/targets/{target_id}/snmp/interfaces", "error", "Сервис проверок ещё не готов"
        )
    try:
        result = await scheduler.poll_snmp_interfaces_now(target_id)
    except LookupError as exc:
        return redirect_with(f"/targets/{target_id}/snmp/interfaces", "error", str(exc))
    parameter = "notice" if result.status in {"ok", "disabled", "skipped"} else "error"
    return redirect_with(f"/targets/{target_id}/snmp/interfaces", parameter, result.message)


@router.post("/targets/{target_id}/snmp/interfaces/selection")
async def snmp_interfaces_selection(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
) -> RedirectResponse:
    target = _target_or_404(session, target_id)
    form = await request.form()
    require_csrf(auth, str(form.get("csrf_token", "")))
    try:
        selected_ids = {int(value) for value in form.getlist("selected_interface_id")}
        visible_ids = {int(value) for value in form.getlist("visible_interface_id")}
    except (TypeError, ValueError):
        return redirect_with(
            f"/targets/{target_id}/snmp/interfaces", "error", "Некорректный выбор интерфейсов"
        )
    rows = session.scalars(select(SnmpInterface).where(SnmpInterface.target_id == target_id)).all()
    present_ids = {item.id for item in rows if item.present}
    if not visible_ids.issubset(present_ids) or not selected_ids.issubset(visible_ids):
        return redirect_with(
            f"/targets/{target_id}/snmp/interfaces",
            "error",
            "Выбран интерфейс, которого нет в текущем списке",
        )
    existing_outside_visible = sum(
        1 for item in rows if item.monitor_enabled and item.id not in visible_ids
    )
    if existing_outside_visible + len(selected_ids) > MAX_MONITORED_INTERFACES:
        return redirect_with(
            f"/targets/{target_id}/snmp/interfaces",
            "error",
            f"Можно выбрать не более {MAX_MONITORED_INTERFACES} интерфейсов",
        )
    changed = False
    enabled_indexes: list[int] = []
    for item in rows:
        if item.id not in visible_ids:
            if item.monitor_enabled:
                enabled_indexes.append(item.if_index)
            continue
        enabled = item.id in selected_ids
        if item.monitor_enabled != enabled:
            if not enabled:
                SnmpThresholdService().reset_for_interface(
                    session,
                    item.id,
                    message="Мониторинг SNMP-интерфейса отключён администратором",
                )
            item.monitor_enabled = enabled
            item.traffic_counter_mode = None
            item.in_octets = None
            item.out_octets = None
            item.traffic_at = None
            item.traffic_uptime_ticks = None
            item.rx_bps = None
            item.tx_bps = None
            item.in_errors = None
            item.out_errors = None
            item.in_discards = None
            item.out_discards = None
            item.traffic_error = None
            changed = True
        if enabled:
            enabled_indexes.append(item.if_index)
    if changed:
        write_audit(
            session,
            "snmp.interfaces_selection_changed",
            user_id=auth.user.id,
            entity_type="snmp",
            entity_id=target_id,
            entity_name=target.name,
            details={
                "enabled_count": len(enabled_indexes),
                "enabled_if_indexes": sorted(enabled_indexes),
            },
            ip_address=client_ip(request),
        )
    session.commit()
    return redirect_with(
        f"/targets/{target_id}/snmp/interfaces", "notice", "Выбор интерфейсов сохранён"
    )


@router.get("/targets/{target_id}/snmp/supplies", response_class=HTMLResponse)
def snmp_supplies_page(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: CurrentAuth,
) -> HTMLResponse:
    target = _target_or_404(session, target_id)
    config = session.get(SnmpConfig, target_id)
    supplies = session.scalars(
        select(SnmpSupply)
        .where(SnmpSupply.target_id == target_id)
        .order_by(
            SnmpSupply.present.desc(),
            SnmpSupply.hr_device_index,
            SnmpSupply.supply_index,
        )
    ).all()
    return templates.TemplateResponse(
        request=request,
        name="target_snmp_supplies.html",
        context=template_context(
            request,
            auth,
            target=target,
            config=config,
            supplies=supplies,
            display_datetime=session_datetime_formatter(session),
            supply_type_label=supply_type_label,
            supply_class_label=supply_class_label,
            supply_unit_label=supply_unit_label,
            supply_level_label=supply_level_label,
        ),
    )


@router.post("/targets/{target_id}/snmp/supplies/{supply_id}/name")
def snmp_supply_name_update(
    target_id: int,
    supply_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    custom_name: Annotated[str, Form()] = "",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    target = _target_or_404(session, target_id)
    supply = session.get(SnmpSupply, supply_id)
    if supply is None or supply.target_id != target_id:
        raise HTTPException(status_code=404, detail="Расходник не найден")
    normalized_name = custom_name.strip() or None
    if normalized_name is not None and len(normalized_name) > 160:
        return redirect_with(
            f"/targets/{target_id}/snmp/supplies",
            "error",
            "Имя расходника не должно быть длиннее 160 символов",
        )
    previous_name = supply.custom_name
    supply.custom_name = normalized_name
    write_audit(
        session,
        "snmp.supply_name_updated",
        user_id=auth.user.id,
        entity_type="snmp_supply",
        entity_id=supply.id,
        entity_name=target.name,
        details={
            "custom_name": {"old": previous_name, "new": normalized_name},
            "supply_index": supply.supply_index,
        },
        ip_address=client_ip(request),
    )
    session.commit()
    message = "Имя расходника сохранено" if normalized_name else "Пользовательское имя сброшено"
    return redirect_with(f"/targets/{target_id}/snmp/supplies", "notice", message)


@router.post("/targets/{target_id}/snmp/supplies/discover")
async def snmp_supplies_discover(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    target = _target_or_404(session, target_id)
    scheduler: CheckScheduler | None = getattr(request.app.state, "scheduler", None)
    if scheduler is None:
        return redirect_with(
            f"/targets/{target_id}/snmp/supplies",
            "error",
            "Сервис проверок ещё не готов",
        )
    try:
        result = await scheduler.discover_snmp_supplies_now(target_id)
    except LookupError as exc:
        return redirect_with(f"/targets/{target_id}/snmp/supplies", "error", str(exc))
    if result.status == "ok":
        write_audit(
            session,
            "snmp.supplies_discovered",
            user_id=auth.user.id,
            entity_type="snmp",
            entity_id=target_id,
            entity_name=target.name,
            details={"count": len(result.items), "truncated": result.truncated},
            ip_address=client_ip(request),
        )
        session.commit()
        return redirect_with(f"/targets/{target_id}/snmp/supplies", "notice", result.message)
    parameter = "notice" if result.status in {"disabled", "skipped"} else "error"
    return redirect_with(f"/targets/{target_id}/snmp/supplies", parameter, result.message)


@router.post("/targets/{target_id}/snmp/supplies/poll")
async def snmp_supplies_poll(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    _target_or_404(session, target_id)
    scheduler: CheckScheduler | None = getattr(request.app.state, "scheduler", None)
    if scheduler is None:
        return redirect_with(
            f"/targets/{target_id}/snmp/supplies",
            "error",
            "Сервис проверок ещё не готов",
        )
    try:
        result = await scheduler.poll_snmp_supplies_now(target_id)
    except LookupError as exc:
        return redirect_with(f"/targets/{target_id}/snmp/supplies", "error", str(exc))
    parameter = "notice" if result.status in {"ok", "disabled", "skipped"} else "error"
    return redirect_with(f"/targets/{target_id}/snmp/supplies", parameter, result.message)


@router.get("/targets/{target_id}/snmp/thresholds", response_class=HTMLResponse)
def snmp_thresholds_page(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: CurrentAuth,
) -> HTMLResponse:
    target = _target_or_404(session, target_id)
    service = SnmpThresholdService()
    thresholds = session.scalars(
        select(SnmpThreshold).where(SnmpThreshold.target_id == target_id).order_by(SnmpThreshold.id)
    ).all()
    edit_id = request.query_params.get("edit", "")
    editing = session.get(SnmpThreshold, int(edit_id)) if edit_id.isdecimal() else None
    if editing is not None and editing.target_id != target_id:
        editing = None
    labels = {}
    for threshold in thresholds:
        label, unit = service._source_label(session, threshold)
        labels[threshold.id] = f"{label}{(' · ' + unit) if unit else ''}"
    editing_source = ""
    if editing is not None:
        source_id = (
            editing.metric_id
            if editing.source_kind == "metric"
            else editing.interface_id
            if editing.source_kind == "interface"
            else editing.supply_id
            if editing.source_kind == "supply"
            else target_id
        )
        editing_field = (
            editing.field.replace(":", ".") if editing.source_kind == "ups" else editing.field
        )
        editing_source = f"{editing.source_kind}:{source_id}:{editing_field}"
    return templates.TemplateResponse(
        request=request,
        name="target_snmp_thresholds.html",
        context=template_context(
            request,
            auth,
            target=target,
            thresholds=thresholds,
            threshold_labels=labels,
            source_options=service.source_options(session, target_id),
            editing_threshold=editing,
            editing_source=editing_source,
            display_datetime=session_datetime_formatter(session),
        ),
    )


@router.post("/targets/{target_id}/snmp/thresholds/test")
async def snmp_thresholds_test(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    """Refresh normal SNMP data and re-evaluate enabled thresholds."""
    require_csrf(auth, csrf_token)
    _target_or_404(session, target_id)
    scheduler: CheckScheduler | None = getattr(request.app.state, "scheduler", None)
    if scheduler is None:
        return redirect_with(
            f"/targets/{target_id}/snmp/thresholds", "error", "Сервис проверок ещё не готов"
        )
    try:
        result = await scheduler.poll_snmp_interfaces_now(target_id)
    except LookupError as exc:
        return redirect_with(f"/targets/{target_id}/snmp/thresholds", "error", str(exc))
    if result.status == "ok":
        return redirect_with(
            f"/targets/{target_id}/snmp/thresholds",
            "notice",
            "SNMP-данные обновлены, пороги пересчитаны",
        )
    parameter = "notice" if result.status in {"disabled", "skipped"} else "error"
    return redirect_with(f"/targets/{target_id}/snmp/thresholds", parameter, result.message)


@router.post("/targets/{target_id}/snmp/thresholds")
@router.post("/targets/{target_id}/snmp/thresholds/{threshold_id}")
async def snmp_threshold_save(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    threshold_id: int | None = None,
) -> RedirectResponse:
    target = _target_or_404(session, target_id)
    form = await request.form()
    require_csrf(auth, str(form.get("csrf_token", "")))
    service = SnmpThresholdService()
    try:
        warning = (
            float(form["warning_value"]) if str(form.get("warning_value", "")).strip() else None
        )
        critical = (
            float(form["critical_value"]) if str(form.get("critical_value", "")).strip() else None
        )
        operator = str(form.get("operator", "gt"))
        validate_threshold_values(operator=operator, warning=warning, critical=critical)
        source_kind, metric_id, interface_id, supply_id, field = service.parse_source(
            session, target_id, str(form.get("source", ""))
        )
    except (TypeError, ValueError) as exc:
        return redirect_with(f"/targets/{target_id}/snmp/thresholds", "error", str(exc))

    threshold = session.get(SnmpThreshold, threshold_id) if threshold_id else None
    if threshold is not None and threshold.target_id != target_id:
        raise HTTPException(status_code=404)
    if threshold is None:
        threshold = SnmpThreshold(target_id=target_id)
        session.add(threshold)
        action = "snmp.threshold_created"
    else:
        service.reset_threshold(
            session,
            threshold,
            message="Настройка SNMP-порога изменена администратором",
        )
        action = "snmp.threshold_updated"

    threshold.source_kind = source_kind
    threshold.metric_id = metric_id
    threshold.interface_id = interface_id
    threshold.supply_id = supply_id
    threshold.field = field
    threshold.operator = operator
    threshold.warning_value = warning
    threshold.critical_value = critical
    threshold.enabled = str(form.get("enabled", "")) == "1"
    threshold.current_level = "normal"
    threshold.last_value = None
    threshold.last_evaluated_at = None
    session.flush()
    write_audit(
        session,
        action,
        user_id=auth.user.id,
        entity_type="snmp_threshold",
        entity_id=threshold.id,
        entity_name=target.name,
        details={"target_id": target_id, "field": field, "operator": operator},
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(
        f"/targets/{target_id}/snmp/thresholds",
        "notice",
        "SNMP-порог сохранён",
    )


@router.post("/targets/{target_id}/snmp/thresholds/{threshold_id}/toggle")
def snmp_threshold_toggle(
    target_id: int,
    threshold_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    target = _target_or_404(session, target_id)
    threshold = session.get(SnmpThreshold, threshold_id)
    if threshold is None or threshold.target_id != target_id:
        raise HTTPException(status_code=404)
    service = SnmpThresholdService()
    if threshold.enabled:
        service.reset_threshold(
            session,
            threshold,
            message="SNMP-порог отключён администратором",
            disable=True,
        )
    else:
        threshold.enabled = True
        threshold.current_level = "normal"
        threshold.last_value = None
        threshold.last_evaluated_at = None
    write_audit(
        session,
        "snmp.threshold_toggled",
        user_id=auth.user.id,
        entity_type="snmp_threshold",
        entity_id=threshold.id,
        entity_name=target.name,
        details={"enabled": threshold.enabled},
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(
        f"/targets/{target_id}/snmp/thresholds", "notice", "Состояние порога изменено"
    )


@router.post("/targets/{target_id}/snmp/thresholds/{threshold_id}/delete")
def snmp_threshold_delete(
    target_id: int,
    threshold_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    target = _target_or_404(session, target_id)
    threshold = session.get(SnmpThreshold, threshold_id)
    if threshold is None or threshold.target_id != target_id:
        raise HTTPException(status_code=404)
    service = SnmpThresholdService()
    service.reset_threshold(
        session,
        threshold,
        message="SNMP-порог удалён администратором",
    )
    write_audit(
        session,
        "snmp.threshold_deleted",
        user_id=auth.user.id,
        entity_type="snmp_threshold",
        entity_id=threshold.id,
        entity_name=target.name,
        ip_address=client_ip(request),
    )
    session.delete(threshold)
    session.commit()
    return redirect_with(f"/targets/{target_id}/snmp/thresholds", "notice", "SNMP-порог удалён")


@router.post("/targets/{target_id}/snmp/metrics")
def snmp_metric_create(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    name: Annotated[str, Form()],
    oid: Annotated[str, Form()] = "",
    unit: Annotated[str, Form()] = "",
    enabled: Annotated[str | None, Form()] = None,
    source_kind: Annotated[str, Form()] = "oid",
    formula: Annotated[str, Form()] = "",
) -> Response:
    require_csrf(auth, csrf_token)
    target = _target_or_404(session, target_id)
    try:
        metric = _service(request).add_metric(
            session,
            target_id,
            SnmpMetricForm(
                name,
                oid,
                unit,
                enabled == "true",
                source_kind=source_kind,
                formula=formula,
            ),
        )
    except (LookupError, ValueError) as exc:
        session.rollback()
        request.state.snmp_metric_form_draft = {
            "name": name,
            "oid": oid,
            "unit": unit,
            "enabled": enabled == "true",
            "source_kind": source_kind,
            "formula": formula,
        }
        request.state.snmp_metric_form_error = str(exc)
        response = snmp_page(target_id, request, session, auth)
        # The async form handler replaces only <main>; tell it that this rendered
        # validation response still belongs to the SNMP page, not to the POST URL.
        response.headers["X-Monitoring-Page-Path"] = f"/targets/{target_id}/snmp"
        return response
    session.flush()
    write_audit(
        session,
        "snmp.metric_created",
        user_id=auth.user.id,
        entity_type="snmp",
        entity_id=metric.id,
        entity_name=target.name,
        details=_metric_audit_state(metric),
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(f"/targets/{target_id}/snmp", "notice", "SNMP-метрика добавлена")


@router.post("/targets/{target_id}/snmp/metrics/{metric_id}")
def snmp_metric_update(
    target_id: int,
    metric_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    name: Annotated[str, Form()],
    oid: Annotated[str, Form()] = "",
    unit: Annotated[str, Form()] = "",
    enabled: Annotated[str | None, Form()] = None,
    source_kind: Annotated[str, Form()] = "oid",
    formula: Annotated[str, Form()] = "",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    target = _target_or_404(session, target_id)
    metric = session.get(SnmpMetric, metric_id)
    if metric is None or metric.target_id != target_id:
        raise HTTPException(status_code=404, detail="SNMP-метрика не найдена")
    before = _metric_audit_state(metric)
    try:
        metric = _service(request).update_metric(
            session,
            metric_id,
            SnmpMetricForm(
                name,
                oid,
                unit,
                enabled == "true",
                source_kind=source_kind,
                formula=formula,
            ),
        )
    except ValueError as exc:
        session.rollback()
        return redirect_with(f"/targets/{target_id}/snmp", "error", str(exc))
    write_audit(
        session,
        "snmp.metric_updated",
        user_id=auth.user.id,
        entity_type="snmp",
        entity_id=metric.id,
        entity_name=target.name,
        details=audit_changes(before, _metric_audit_state(metric)) or {"unchanged": True},
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(f"/targets/{target_id}/snmp", "notice", "SNMP-метрика сохранена")


@router.post("/targets/{target_id}/snmp/metrics/{metric_id}/move")
def snmp_metric_move(
    target_id: int,
    metric_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    direction: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    _target_or_404(session, target_id)
    metric = session.get(SnmpMetric, metric_id)
    if metric is None or metric.target_id != target_id:
        raise HTTPException(status_code=404, detail="SNMP-метрика не найдена")
    try:
        changed = move_metric(session, metric, direction)
    except ValueError as exc:
        session.rollback()
        return redirect_with(f"/targets/{target_id}/snmp", "error", str(exc))
    if changed:
        write_audit(
            session,
            "snmp.metric_order_changed",
            user_id=auth.user.id,
            entity_type="snmp",
            entity_id=metric.id,
            ip_address=client_ip(request),
        )
        session.commit()
        message = "Порядок SNMP-метрик изменён"
    else:
        session.rollback()
        message = "Метрика уже находится на границе списка"
    return redirect_with(f"/targets/{target_id}/snmp", "notice", message)


@router.post("/targets/{target_id}/snmp/metrics/{metric_id}/delete")
def snmp_metric_delete(
    target_id: int,
    metric_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    target = _target_or_404(session, target_id)
    metric = session.get(SnmpMetric, metric_id)
    if metric is None or metric.target_id != target_id:
        raise HTTPException(status_code=404, detail="SNMP-метрика не найдена")
    details = _metric_audit_state(metric)
    SnmpThresholdService().reset_for_metric(
        session,
        metric.id,
        message="SNMP-метрика удалена администратором",
    )
    session.delete(metric)
    write_audit(
        session,
        "snmp.metric_deleted",
        user_id=auth.user.id,
        entity_type="snmp",
        entity_id=metric_id,
        entity_name=target.name,
        details=details,
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(f"/targets/{target_id}/snmp", "notice", "SNMP OID удалён")


@router.post("/targets/{target_id}/snmp/clear")
def snmp_data_clear(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    target = _target_or_404(session, target_id)
    _service(request).clear_data(session, target_id)
    write_audit(
        session,
        "snmp.data_cleared",
        user_id=auth.user.id,
        entity_type="snmp",
        entity_id=target_id,
        entity_name=target.name,
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(f"/targets/{target_id}/snmp", "notice", "SNMP-данные очищены")
