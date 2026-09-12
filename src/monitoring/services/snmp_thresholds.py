from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from math import isfinite

from sqlalchemy import select
from sqlalchemy.orm import Session

from monitoring.models import (
    IncidentSeverity,
    IncidentSourceKind,
    MonitorTarget,
    SnmpConfig,
    SnmpInterface,
    SnmpInterfaceSample,
    SnmpMetric,
    SnmpSample,
    SnmpSupply,
    SnmpThreshold,
    SnmpUpsLine,
    SnmpUpsState,
)
from monitoring.services.incidents import IncidentNotification, IncidentService


class ThresholdLevel(StrEnum):
    NORMAL = "normal"
    WARNING = "warning"
    CRITICAL = "critical"


class ThresholdOperator(StrEnum):
    GT = "gt"
    LT = "lt"


INTERFACE_FIELDS = {
    "rx_bps": ("RX", "Mbit/s"),
    "tx_bps": ("TX", "Mbit/s"),
    "errors_delta": ("Ошибки", "за интервал"),
    "discards_delta": ("Отбросы", "за интервал"),
}

UPS_STATE_FIELDS = {
    "battery_charge_percent": ("ИБП · Заряд батареи", "%"),
    "estimated_runtime_minutes": ("ИБП · Автономность", "мин"),
    "battery_voltage": ("ИБП · Напряжение батареи", "В"),
    "battery_temperature": ("ИБП · Температура батареи", "°C"),
}
UPS_LINE_FIELDS = {
    "voltage": ("Напряжение", "В"),
    "current": ("Ток", "А"),
    "load_percent": ("Нагрузка", "%"),
}
MAX_UPS_THRESHOLD_LINES = 3


@dataclass(frozen=True, slots=True)
class ThresholdSourceOption:
    value: str
    label: str
    unit: str


def evaluate_level(
    value: float,
    *,
    operator: str,
    warning: float | None,
    critical: float | None,
) -> ThresholdLevel:
    def crossed(limit: float | None) -> bool:
        if limit is None:
            return False
        if operator == ThresholdOperator.GT:
            return value > limit
        if operator == ThresholdOperator.LT:
            return value < limit
        raise ValueError("Неизвестный оператор порога")

    if crossed(critical):
        return ThresholdLevel.CRITICAL
    if crossed(warning):
        return ThresholdLevel.WARNING
    return ThresholdLevel.NORMAL


def validate_threshold_values(
    *,
    operator: str,
    warning: float | None,
    critical: float | None,
) -> None:
    if operator not in {ThresholdOperator.GT, ThresholdOperator.LT}:
        raise ValueError("Допустимы только условия > и <")
    if warning is None and critical is None:
        raise ValueError("Укажите Warning или Critical")
    if any(value is not None and not isfinite(value) for value in (warning, critical)):
        raise ValueError("Значения Warning и Critical должны быть конечными числами")
    if warning is not None and critical is not None:
        if operator == ThresholdOperator.GT and critical < warning:
            raise ValueError("Для условия > Critical должен быть не меньше Warning")
        if operator == ThresholdOperator.LT and critical > warning:
            raise ValueError("Для условия < Critical должен быть не больше Warning")


def _counter_total(*values: int | None) -> int | None:
    if any(value is None for value in values):
        return None
    return sum(int(value) for value in values if value is not None)


def safe_counter_delta(current: int | None, previous: int | None) -> float | None:
    if current is None or previous is None or current < previous:
        return None
    return float(current - previous)


def _same_observation(collected_at: datetime, observed_at: datetime) -> bool:
    """Compare DB timestamps consistently across PostgreSQL and SQLite tests."""
    collected = (
        collected_at
        if collected_at.tzinfo is not None
        else collected_at.replace(tzinfo=UTC)
    )
    observed = (
        observed_at
        if observed_at.tzinfo is not None
        else observed_at.replace(tzinfo=UTC)
    )
    return collected.astimezone(UTC) == observed.astimezone(UTC)


def format_threshold_value(threshold: SnmpThreshold, value: float) -> str:
    """Keep interface traffic values readable in incidents and notifications."""
    if threshold.source_kind == "interface" and threshold.field in {"rx_bps", "tx_bps"}:
        return f"{value:.2f}"
    if threshold.source_kind == "supply":
        return f"{value:.1f}".rstrip("0").rstrip(".")
    return f"{value:g}"


def _ups_source_field(direction: str, field: str, line_index: int) -> str:
    return f"{direction}_{field}:{line_index}"


def _ups_source_form_field(field: str) -> str:
    return field.replace(":", ".")


def _ups_source_storage_field(field: str) -> str:
    return field.replace(".", ":")


class SnmpThresholdService:
    def __init__(self, incident_service: IncidentService | None = None) -> None:
        self.incident_service = incident_service or IncidentService()

    @staticmethod
    def source_key(threshold_id: int) -> str:
        return f"threshold:{threshold_id}"

    def source_options(
        self, session: Session, target_id: int
    ) -> tuple[ThresholdSourceOption, ...]:
        result: list[ThresholdSourceOption] = []
        metrics = session.scalars(
            select(SnmpMetric)
            .where(
                SnmpMetric.target_id == target_id,
                SnmpMetric.enabled.is_(True),
            )
            .order_by(SnmpMetric.id)
        ).all()
        for metric in metrics:
            # Only metrics that have produced numeric samples are useful for thresholds.
            if (
                session.scalar(
                    select(SnmpSample.id)
                    .where(SnmpSample.metric_id == metric.id)
                    .limit(1)
                )
                is None
            ):
                continue
            name = (
                getattr(metric, "name", None)
                or getattr(metric, "label", None)
                or metric.oid
            )
            unit = getattr(metric, "unit", None) or ""
            result.append(
                ThresholdSourceOption(
                    value=f"metric:{metric.id}:value",
                    label=f"SNMP · {name}",
                    unit=unit,
                )
            )

        interfaces = session.scalars(
            select(SnmpInterface)
            .where(
                SnmpInterface.target_id == target_id,
                SnmpInterface.monitor_enabled.is_(True),
            )
            .order_by(SnmpInterface.if_index)
        ).all()
        for interface in interfaces:
            name = interface.if_name or interface.if_descr or f"ifIndex {interface.if_index}"
            for field, (label, unit) in INTERFACE_FIELDS.items():
                result.append(
                    ThresholdSourceOption(
                        value=f"interface:{interface.id}:{field}",
                        label=f"Интерфейс · {name} · {label}",
                        unit=unit,
                    )
                )

        supplies = session.scalars(
            select(SnmpSupply)
            .where(
                SnmpSupply.target_id == target_id,
                SnmpSupply.present.is_(True),
            )
            .order_by(SnmpSupply.hr_device_index, SnmpSupply.supply_index)
        ).all()
        for supply in supplies:
            if supply.percent_remaining is None:
                continue
            name = supply.display_name
            value_label = "свободно" if supply.supply_class == 4 else "остаток"
            result.append(
                ThresholdSourceOption(
                    value=f"supply:{supply.id}:percent",
                    label=f"Расходник · {name} · {value_label}",
                    unit="%",
                )
            )
        config = session.get(SnmpConfig, target_id)
        state = session.get(SnmpUpsState, target_id)
        if config is not None and config.enabled and config.ups_enabled and state is not None:
            for field, (label, unit) in UPS_STATE_FIELDS.items():
                if getattr(state, field) is not None:
                    result.append(
                        ThresholdSourceOption(
                            value=f"ups:{target_id}:{field}", label=label, unit=unit
                        )
                    )
            lines = session.scalars(
                select(SnmpUpsLine)
                .where(SnmpUpsLine.target_id == target_id)
                .order_by(SnmpUpsLine.direction, SnmpUpsLine.line_index)
            ).all()
            for line in lines:
                direction = "Вход" if line.direction == "input" else "Выход"
                for field, (label, unit) in UPS_LINE_FIELDS.items():
                    if getattr(line, field) is None:
                        continue
                    source_field = _ups_source_field(line.direction, field, line.line_index)
                    result.append(
                        ThresholdSourceOption(
                            value=f"ups:{target_id}:{_ups_source_form_field(source_field)}",
                            label=f"ИБП · {direction} L{line.line_index} · {label}",
                            unit=unit,
                        )
                    )
        return tuple(result)

    @staticmethod
    def parse_source(
        session: Session,
        target_id: int,
        source: str,
    ) -> tuple[str, int | None, int | None, int | None, str]:
        parts = source.split(":")
        if len(parts) != 3 or not parts[1].isdigit():
            raise ValueError("Некорректный источник порога")
        kind, raw_id, field = parts
        item_id = int(raw_id)
        if kind == "metric":
            if field != "value":
                raise ValueError("Некорректная метрика")
            metric = session.scalar(
                select(SnmpMetric).where(
                    SnmpMetric.id == item_id,
                    SnmpMetric.target_id == target_id,
                    SnmpMetric.enabled.is_(True),
                )
            )
            if metric is None:
                raise ValueError("SNMP-метрика не найдена")
            return "metric", metric.id, None, None, "value"
        if kind == "interface":
            if field not in INTERFACE_FIELDS:
                raise ValueError("Некорректная метрика интерфейса")
            interface = session.scalar(
                select(SnmpInterface).where(
                    SnmpInterface.id == item_id,
                    SnmpInterface.target_id == target_id,
                    SnmpInterface.monitor_enabled.is_(True),
                )
            )
            if interface is None:
                raise ValueError("Интерфейс не найден или не выбран для мониторинга")
            return "interface", None, interface.id, None, field
        if kind == "supply":
            if field != "percent":
                raise ValueError("Некорректная метрика расходника")
            supply = session.scalar(
                select(SnmpSupply).where(
                    SnmpSupply.id == item_id,
                    SnmpSupply.target_id == target_id,
                    SnmpSupply.present.is_(True),
                )
            )
            if supply is None:
                raise ValueError("Расходник Printer-MIB не найден")
            if supply.percent_remaining is None:
                raise ValueError("Для расходника пока нельзя вычислить процент остатка")
            return "supply", None, None, supply.id, "percent"
        if kind == "ups":
            if item_id != target_id:
                raise ValueError("Некорректный источник ИБП")
            config = session.get(SnmpConfig, target_id)
            state = session.get(SnmpUpsState, target_id)
            if config is None or not config.enabled or not config.ups_enabled or state is None:
                raise ValueError("Мониторинг ИБП не настроен")
            storage_field = _ups_source_storage_field(field)
            if storage_field in UPS_STATE_FIELDS:
                if getattr(state, storage_field) is None:
                    raise ValueError("Параметр ИБП пока не получил данные")
                return "ups", None, None, None, storage_field
            if ":" not in storage_field:
                raise ValueError("Некорректный параметр ИБП")
            prefix, raw_line_index = storage_field.rsplit(":", 1)
            if not raw_line_index.isdecimal() or not 1 <= int(raw_line_index) <= MAX_UPS_THRESHOLD_LINES:
                raise ValueError("Некорректная фаза ИБП")
            direction, separator, line_field = prefix.partition("_")
            if direction not in {"input", "output"} or not separator or line_field not in UPS_LINE_FIELDS:
                raise ValueError("Некорректный параметр ИБП")
            line = session.scalar(
                select(SnmpUpsLine).where(
                    SnmpUpsLine.target_id == target_id,
                    SnmpUpsLine.direction == direction,
                    SnmpUpsLine.line_index == int(raw_line_index),
                )
            )
            if line is None or getattr(line, line_field) is None:
                raise ValueError("Параметр ИБП пока не получил данные")
            return "ups", None, None, None, storage_field
        raise ValueError("Некорректный источник порога")

    @staticmethod
    def _threshold_value(
        session: Session,
        threshold: SnmpThreshold,
        *,
        observed_at: datetime,
    ) -> float | None:
        if threshold.source_kind == "metric" and threshold.metric_id is not None:
            metric = session.get(SnmpMetric, threshold.metric_id)
            if metric is None or not metric.enabled:
                return None
            sample = session.scalar(
                select(SnmpSample)
                .where(SnmpSample.metric_id == threshold.metric_id)
                .order_by(SnmpSample.collected_at.desc(), SnmpSample.id.desc())
                .limit(1)
            )
            if sample is None or not _same_observation(sample.collected_at, observed_at):
                return None
            return float(sample.value)

        if threshold.source_kind == "supply" and threshold.supply_id is not None:
            supply = session.get(SnmpSupply, threshold.supply_id)
            if supply is None or not supply.present or supply.percent_remaining is None:
                return None
            if supply.last_polled_at is None or not _same_observation(
                supply.last_polled_at, observed_at
            ):
                return None
            return float(supply.percent_remaining)

        if threshold.source_kind == "ups":
            config = session.get(SnmpConfig, threshold.target_id)
            state = session.get(SnmpUpsState, threshold.target_id)
            if (
                config is None
                or not config.enabled
                or not config.ups_enabled
                or state is None
                or state.last_polled_at is None
                or not _same_observation(state.last_polled_at, observed_at)
            ):
                return None
            if threshold.field in UPS_STATE_FIELDS:
                value = getattr(state, threshold.field)
                return float(value) if value is not None else None
            if ":" not in threshold.field:
                return None
            prefix, raw_line_index = threshold.field.rsplit(":", 1)
            direction, separator, line_field = prefix.partition("_")
            if not separator or not raw_line_index.isdecimal() or line_field not in UPS_LINE_FIELDS:
                return None
            line = session.scalar(
                select(SnmpUpsLine).where(
                    SnmpUpsLine.target_id == threshold.target_id,
                    SnmpUpsLine.direction == direction,
                    SnmpUpsLine.line_index == int(raw_line_index),
                )
            )
            if line is None or line.last_polled_at is None or not _same_observation(
                line.last_polled_at, observed_at
            ):
                return None
            value = getattr(line, line_field)
            return float(value) if value is not None else None

        if threshold.source_kind != "interface" or threshold.interface_id is None:
            return None
        interface = session.get(SnmpInterface, threshold.interface_id)
        if interface is None or not interface.monitor_enabled or not interface.present:
            return None
        samples = session.scalars(
            select(SnmpInterfaceSample)
            .where(SnmpInterfaceSample.interface_id == threshold.interface_id)
            .order_by(
                SnmpInterfaceSample.collected_at.desc(),
                SnmpInterfaceSample.id.desc(),
            )
            .limit(2)
        ).all()
        if not samples:
            return None
        current = samples[0]
        if not _same_observation(current.collected_at, observed_at):
            return None
        if threshold.field == "rx_bps":
            return (
                float(current.rx_bps) / 1_000_000
                if current.rx_bps is not None
                else None
            )
        if threshold.field == "tx_bps":
            return (
                float(current.tx_bps) / 1_000_000
                if current.tx_bps is not None
                else None
            )
        if len(samples) < 2:
            return None
        # A baseline/reboot/reset sample deliberately has no calculated traffic
        # rates.  Its raw error/discard counters must not be compared with an old
        # sample across that discontinuity.
        if current.rx_bps is None and current.tx_bps is None:
            return None
        previous = samples[1]
        if threshold.field == "errors_delta":
            return safe_counter_delta(
                _counter_total(current.in_errors, current.out_errors),
                _counter_total(previous.in_errors, previous.out_errors),
            )
        if threshold.field == "discards_delta":
            return safe_counter_delta(
                _counter_total(current.in_discards, current.out_discards),
                _counter_total(previous.in_discards, previous.out_discards),
            )
        return None

    @staticmethod
    def _source_label(session: Session, threshold: SnmpThreshold) -> tuple[str, str]:
        if threshold.source_kind == "metric" and threshold.metric_id is not None:
            metric = session.get(SnmpMetric, threshold.metric_id)
            if metric is None:
                return "SNMP metric", ""
            name = (
                getattr(metric, "name", None)
                or getattr(metric, "label", None)
                or metric.oid
            )
            return name, getattr(metric, "unit", None) or ""

        if threshold.source_kind == "supply" and threshold.supply_id is not None:
            supply = session.get(SnmpSupply, threshold.supply_id)
            if supply is None:
                return "Расходник", "%"
            name = supply.display_name
            value_label = "свободно" if supply.supply_class == 4 else "остаток"
            return f"{name} · {value_label}", "%"

        if threshold.source_kind == "ups":
            if threshold.field in UPS_STATE_FIELDS:
                return UPS_STATE_FIELDS[threshold.field]
            if ":" in threshold.field:
                prefix, raw_line_index = threshold.field.rsplit(":", 1)
                direction, separator, line_field = prefix.partition("_")
                if separator and raw_line_index.isdecimal() and line_field in UPS_LINE_FIELDS:
                    direction_label = "Вход" if direction == "input" else "Выход"
                    field_label, unit = UPS_LINE_FIELDS[line_field]
                    return f"ИБП · {direction_label} L{raw_line_index} · {field_label}", unit
            return "ИБП", ""

        interface = (
            session.get(SnmpInterface, threshold.interface_id)
            if threshold.interface_id is not None
            else None
        )
        name = (
            interface.if_name or interface.if_descr or f"ifIndex {interface.if_index}"
            if interface is not None
            else "Интерфейс"
        )
        field_label, unit = INTERFACE_FIELDS.get(
            threshold.field, (threshold.field, "")
        )
        return f"{name} · {field_label}", unit

    def evaluate_target(
        self,
        session: Session,
        target_id: int,
        *,
        observed_at: datetime | None = None,
    ) -> list[IncidentNotification]:
        target = session.get(MonitorTarget, target_id)
        if target is None:
            return []
        now = observed_at or datetime.now(UTC)
        events: list[IncidentNotification] = []
        thresholds = session.scalars(
            select(SnmpThreshold)
            .where(
                SnmpThreshold.target_id == target_id,
                SnmpThreshold.enabled.is_(True),
            )
            .order_by(SnmpThreshold.id)
        ).all()
        for threshold in thresholds:
            value = self._threshold_value(
                session,
                threshold,
                observed_at=now,
            )
            # No fresh/valid data means no transition. In particular SNMP failure,
            # baseline, reboot or counter reset must not close an active incident.
            if value is None:
                continue

            level = evaluate_level(
                value,
                operator=threshold.operator,
                warning=threshold.warning_value,
                critical=threshold.critical_value,
            )
            threshold.last_value = value
            threshold.last_evaluated_at = now
            threshold.current_level = level.value

            label, unit = self._source_label(session, threshold)
            operator_label = ">" if threshold.operator == ThresholdOperator.GT else "<"
            level_label = {
                ThresholdLevel.NORMAL: "Норма",
                ThresholdLevel.WARNING: "Warning",
                ThresholdLevel.CRITICAL: "Critical",
            }[level]
            value_text = f"{format_threshold_value(threshold, value)}{(' ' + unit) if unit else ''}"
            limit = (
                threshold.critical_value
                if level == ThresholdLevel.CRITICAL
                else threshold.warning_value
                if level == ThresholdLevel.WARNING
                else None
            )
            if limit is None:
                message = f"{label}: {value_text}. Значение вернулось в норму."
            else:
                message = (
                    f"{label}: {value_text}; {level_label} при "
                    f"{operator_label} {format_threshold_value(threshold, limit)}"
                    f"{(' ' + unit) if unit else ''}."
                )

            severity = (
                IncidentSeverity.CRITICAL
                if level == ThresholdLevel.CRITICAL
                else IncidentSeverity.WARNING
                if level == ThresholdLevel.WARNING
                else None
            )
            _incident, incident_events = self.incident_service.set_source_state(
                session,
                target,
                source_kind=IncidentSourceKind.SNMP,
                source_key=self.source_key(threshold.id),
                severity=severity,
                message=message,
                observed_at=now,
            )
            events.extend(incident_events)
        return events

    def reset_threshold(
        self,
        session: Session,
        threshold: SnmpThreshold,
        *,
        message: str,
        disable: bool = False,
    ) -> None:
        target = session.get(MonitorTarget, threshold.target_id)
        if target is not None:
            self.incident_service.resolve_source_silently(
                session,
                target,
                source_kind=IncidentSourceKind.SNMP,
                source_key=self.source_key(threshold.id),
                message=message,
                observed_at=datetime.now(UTC),
            )
        threshold.current_level = ThresholdLevel.NORMAL
        threshold.last_value = None
        threshold.last_evaluated_at = None
        if disable:
            threshold.enabled = False

    def reset_target(self, session: Session, target_id: int, *, message: str) -> None:
        rows = session.scalars(
            select(SnmpThreshold).where(SnmpThreshold.target_id == target_id)
        ).all()
        for threshold in rows:
            self.reset_threshold(session, threshold, message=message)

    def reset_for_interface(
        self,
        session: Session,
        interface_id: int,
        *,
        message: str,
        disable: bool = False,
    ) -> None:
        rows = session.scalars(
            select(SnmpThreshold).where(SnmpThreshold.interface_id == interface_id)
        ).all()
        for threshold in rows:
            self.reset_threshold(session, threshold, message=message, disable=disable)

    def reset_for_supply(
        self,
        session: Session,
        supply_id: int,
        *,
        message: str,
        disable: bool = False,
    ) -> None:
        rows = session.scalars(
            select(SnmpThreshold).where(SnmpThreshold.supply_id == supply_id)
        ).all()
        for threshold in rows:
            self.reset_threshold(session, threshold, message=message, disable=disable)

    def reset_for_metric(
        self, session: Session, metric_id: int, *, message: str
    ) -> None:
        rows = session.scalars(
            select(SnmpThreshold).where(SnmpThreshold.metric_id == metric_id)
        ).all()
        for threshold in rows:
            self.reset_threshold(session, threshold, message=message)
