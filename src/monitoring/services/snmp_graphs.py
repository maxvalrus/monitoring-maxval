from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from monitoring.models import SnmpInterface, SnmpInterfaceSample, SnmpMetric, SnmpSample
from monitoring.services.system_metrics import ChartData, chart_data

MAX_GRAPH_POINTS = 720


@dataclass(frozen=True, slots=True)
class SnmpGraphChoice:
    value: str
    label: str


@dataclass(frozen=True, slots=True)
class SnmpGraphSeries:
    label: str
    points: str
    css_class: str
    last_value: str
    values: tuple[float, ...]


@dataclass(frozen=True, slots=True)
class SnmpGraphPanel:
    title: str
    subtitle: str
    unit: str
    series: tuple[SnmpGraphSeries, ...]
    chart: ChartData

    @property
    def tooltip_series(self) -> tuple[dict[str, object], ...]:
        return tuple(
            {
                "label": item.label,
                "values": item.values,
                "points": item.points,
                "css_class": item.css_class,
            }
            for item in self.series
        )


@dataclass(frozen=True, slots=True)
class SnmpHistoryGraph:
    selection: str
    title: str
    panels: tuple[SnmpGraphPanel, ...]


def _downsample(values: list[object], maximum: int = MAX_GRAPH_POINTS) -> list[object]:
    if len(values) <= maximum:
        return values
    step = len(values) / maximum
    return [values[min(int(index * step), len(values) - 1)] for index in range(maximum)]


def _last(values: list[float], digits: int = 1) -> str:
    return f"{values[-1]:.{digits}f}" if values else "—"


def _interface_display_name(interface: SnmpInterface) -> str:
    name = interface.if_name or interface.if_descr or f"ifIndex {interface.if_index}"
    alias = (interface.if_alias or "").strip()
    if alias and alias.casefold() != name.strip().casefold():
        return f"{name} · {alias}"
    return name


def _counter_deltas(values: list[int | None]) -> list[float]:
    result: list[float] = []
    previous: int | None = None
    for value in values:
        if value is None:
            result.append(0.0)
            previous = None
        elif previous is None or value < previous:
            result.append(0.0)
            previous = value
        else:
            result.append(float(value - previous))
            previous = value
    return result


def graph_choices(
    session: Session,
    target_id: int,
    *,
    since: datetime,
) -> tuple[SnmpGraphChoice, ...]:
    choices: list[SnmpGraphChoice] = []
    interfaces = session.scalars(
        select(SnmpInterface)
        .where(
            SnmpInterface.target_id == target_id,
            SnmpInterface.monitor_enabled.is_(True),
            SnmpInterface.present.is_(True),
        )
        .order_by(SnmpInterface.if_index)
    ).all()
    for interface in interfaces:
        has_sample = session.scalar(
            select(SnmpInterfaceSample.id)
            .where(
                SnmpInterfaceSample.interface_id == interface.id,
                SnmpInterfaceSample.collected_at >= since,
            )
            .limit(1)
        )
        if has_sample is not None:
            name = _interface_display_name(interface)
            choices.append(
                SnmpGraphChoice(
                    value=f"interface:{interface.id}",
                    label=f"Интерфейс · {name}",
                )
            )

    metrics = session.scalars(
        select(SnmpMetric)
        .where(SnmpMetric.target_id == target_id, SnmpMetric.enabled.is_(True))
        .order_by(SnmpMetric.id)
    ).all()
    for metric in metrics:
        has_sample = session.scalar(
            select(SnmpSample.id)
            .where(SnmpSample.metric_id == metric.id, SnmpSample.collected_at >= since)
            .limit(1)
        )
        if has_sample is not None:
            choices.append(
                SnmpGraphChoice(value=f"metric:{metric.id}", label=f"SNMP · {metric.name}")
            )
    return tuple(choices)


def _interface_graph(
    session: Session,
    interface: SnmpInterface,
    *,
    since: datetime,
) -> SnmpHistoryGraph | None:
    samples = session.scalars(
        select(SnmpInterfaceSample)
        .where(
            SnmpInterfaceSample.interface_id == interface.id,
            SnmpInterfaceSample.collected_at >= since,
        )
        .order_by(SnmpInterfaceSample.collected_at)
    ).all()
    if not samples:
        return None

    samples = _downsample(samples)
    rx = [float(item.rx_bps or 0) / 1_000_000 for item in samples]
    tx = [float(item.tx_bps or 0) / 1_000_000 for item in samples]
    traffic_chart = chart_data(
        rx + tx,
        [item.collected_at for item in samples] * 2,
    )
    errors = [
        left + right
        for left, right in zip(
            _counter_deltas([item.in_errors for item in samples]),
            _counter_deltas([item.out_errors for item in samples]),
            strict=False,
        )
    ]
    discards = [
        left + right
        for left, right in zip(
            _counter_deltas([item.in_discards for item in samples]),
            _counter_deltas([item.out_discards for item in samples]),
            strict=False,
        )
    ]
    events_chart = chart_data(
        errors + discards,
        [item.collected_at for item in samples] * 2,
    )
    name = _interface_display_name(interface)
    return SnmpHistoryGraph(
        selection=f"interface:{interface.id}",
        title=f"SNMP · {name}",
        panels=(
            SnmpGraphPanel(
                title="Трафик RX / TX",
                subtitle="Средняя скорость за интервал SNMP polling.",
                unit="Mbit/s",
                series=(
                    SnmpGraphSeries(
                        "RX", chart_data(rx, [item.collected_at for item in samples], ceiling=traffic_chart.scale_max).points, "snmp-series-rx", _last(rx), tuple(rx)
                    ),
                    SnmpGraphSeries(
                        "TX", chart_data(tx, [item.collected_at for item in samples], ceiling=traffic_chart.scale_max).points, "snmp-series-tx", _last(tx), tuple(tx)
                    ),
                ),
                chart=chart_data(rx, [item.collected_at for item in samples], ceiling=traffic_chart.scale_max),
            ),
            SnmpGraphPanel(
                title="Ошибки / отбросы",
                subtitle="Суммарное изменение RX+TX за каждый интервал; сброс счётчика не создаёт всплеск.",
                unit="за интервал",
                series=(
                    SnmpGraphSeries(
                        "Ошибки",
                        chart_data(errors, [item.collected_at for item in samples], ceiling=events_chart.scale_max).points,
                        "snmp-series-errors",
                        _last(errors, 0),
                        tuple(errors),
                    ),
                    SnmpGraphSeries(
                        "Отбросы",
                        chart_data(discards, [item.collected_at for item in samples], ceiling=events_chart.scale_max).points,
                        "snmp-series-discards",
                        _last(discards, 0),
                        tuple(discards),
                    ),
                ),
                chart=chart_data(errors, [item.collected_at for item in samples], ceiling=events_chart.scale_max),
            ),
        ),
    )


def _metric_graph(
    session: Session,
    metric: SnmpMetric,
    *,
    since: datetime,
) -> SnmpHistoryGraph | None:
    samples = session.scalars(
        select(SnmpSample)
        .where(SnmpSample.metric_id == metric.id, SnmpSample.collected_at >= since)
        .order_by(SnmpSample.collected_at)
    ).all()
    if not samples:
        return None
    samples = _downsample(samples)
    values = [float(item.value) for item in samples]
    chart = chart_data(values, [item.collected_at for item in samples])
    name = metric.name
    return SnmpHistoryGraph(
        selection=f"metric:{metric.id}",
        title=f"SNMP · {name}",
        panels=(
            SnmpGraphPanel(
                title=name,
                subtitle=f"OID {metric.oid}",
                unit=metric.unit or "",
                series=(
                    SnmpGraphSeries(
                        name,
                        chart.points,
                        "snmp-series-metric",
                        _last(values),
                        tuple(values),
                    ),
                ),
                chart=chart,
            ),
        ),
    )


def build_snmp_history_graph(
    session: Session,
    target_id: int,
    *,
    hours: int,
    selection: str | None,
) -> tuple[tuple[SnmpGraphChoice, ...], SnmpHistoryGraph | None, str]:
    since = datetime.now(UTC) - timedelta(hours=hours)
    choices = graph_choices(session, target_id, since=since)
    allowed = {choice.value for choice in choices}
    selected = selection if selection in allowed else (choices[0].value if choices else "")
    if not selected:
        return choices, None, ""
    kind, raw_id = selected.split(":", 1)
    item_id = int(raw_id)
    if kind == "interface":
        item = session.scalar(
            select(SnmpInterface).where(
                SnmpInterface.id == item_id,
                SnmpInterface.target_id == target_id,
                SnmpInterface.monitor_enabled.is_(True),
                SnmpInterface.present.is_(True),
            )
        )
        graph = _interface_graph(session, item, since=since) if item else None
    else:
        item = session.scalar(
            select(SnmpMetric).where(
                SnmpMetric.id == item_id,
                SnmpMetric.target_id == target_id,
                SnmpMetric.enabled.is_(True),
            )
        )
        graph = _metric_graph(session, item, since=since) if item else None
    return choices, graph, selected
