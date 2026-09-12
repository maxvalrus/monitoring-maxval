"""Small RFC 1628 UPS-MIB adapter used by the existing SNMP polling service."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal, InvalidOperation

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from monitoring.models import (
    IncidentSeverity,
    IncidentSourceKind,
    MonitorTarget,
    SnmpUpsEvent,
    SnmpUpsLine,
    SnmpUpsSample,
    SnmpUpsState,
)
from monitoring.services.incidents import IncidentNotification, IncidentService
from monitoring.services.snmp_client import SnmpVarBind

UPS_ROOT = "1.3.6.1.2.1.33"
APC_POWERNET_ROOT = "1.3.6.1.4.1.318.1.1.1"
UPS_SCALAR_OIDS = {
    "manufacturer": f"{UPS_ROOT}.1.1.1.0", "model": f"{UPS_ROOT}.1.1.2.0",
    "battery_status": f"{UPS_ROOT}.1.2.1.0", "seconds_on_battery": f"{UPS_ROOT}.1.2.2.0",
    "estimated_runtime_minutes": f"{UPS_ROOT}.1.2.3.0", "battery_charge_percent": f"{UPS_ROOT}.1.2.4.0",
    "battery_voltage": f"{UPS_ROOT}.1.2.5.0", "battery_temperature": f"{UPS_ROOT}.1.2.7.0",
    "output_source": f"{UPS_ROOT}.1.4.1.0", "output_frequency": f"{UPS_ROOT}.1.4.2.0",
    "output_lines": f"{UPS_ROOT}.1.4.3.0", "input_lines": f"{UPS_ROOT}.1.3.2.0",
}
APC_SCALAR_OIDS = {
    "model": f"{APC_POWERNET_ROOT}.1.1.1.1.0",
    "battery_status": f"{APC_POWERNET_ROOT}.2.1.1.0",
    "battery_charge_percent": f"{APC_POWERNET_ROOT}.2.2.1.0",
    "battery_temperature": f"{APC_POWERNET_ROOT}.2.2.2.0",
    "estimated_runtime_minutes": f"{APC_POWERNET_ROOT}.2.2.3.0",
    "battery_replace_needed": f"{APC_POWERNET_ROOT}.2.2.4.0",
    "battery_voltage": f"{APC_POWERNET_ROOT}.2.2.8.0",
    "input_voltage": f"{APC_POWERNET_ROOT}.3.2.1.0",
    "input_frequency": f"{APC_POWERNET_ROOT}.3.2.4.0",
    "last_transfer_reason": f"{APC_POWERNET_ROOT}.3.2.5.0",
    "output_source": f"{APC_POWERNET_ROOT}.4.1.1.0",
    "output_voltage": f"{APC_POWERNET_ROOT}.4.2.1.0",
    "output_frequency": f"{APC_POWERNET_ROOT}.4.2.2.0",
    "output_load_percent": f"{APC_POWERNET_ROOT}.4.2.3.0",
    "output_current": f"{APC_POWERNET_ROOT}.4.2.4.0",
    "last_self_test_result": f"{APC_POWERNET_ROOT}.7.2.3.0",
    "last_self_test_at": f"{APC_POWERNET_ROOT}.7.2.4.0",
}
# Smart-UPS high-precision values are tenths.  They are preferred whenever the
# agent exposes them, with the basic PowerNet scalar as a safe fallback.
APC_HIGH_PRECISION_OIDS = {
    "battery_charge_percent": f"{APC_POWERNET_ROOT}.2.3.1.0",
    "battery_temperature": f"{APC_POWERNET_ROOT}.2.3.2.0",
    "output_voltage": f"{APC_POWERNET_ROOT}.4.3.1.0",
    "output_frequency": f"{APC_POWERNET_ROOT}.4.3.2.0",
    "output_load_percent": f"{APC_POWERNET_ROOT}.4.3.3.0",
    "output_current": f"{APC_POWERNET_ROOT}.4.3.4.0",
}
MAX_UPS_LINES = 3
BATTERY_LABELS = {1: "Неизвестно", 2: "Норма", 3: "Низкий заряд", 4: "Батарея разряжена"}
OUTPUT_LABELS = {1: "Другое", 2: "Выход отключён", 3: "От сети", 4: "Bypass", 5: "От батареи", 6: "AVR Boost", 7: "AVR Trim"}
APC_BATTERY_LABELS = {1: "Неизвестно", 2: "Норма", 3: "Низкий заряд", 4: "Неисправность батареи"}
APC_OUTPUT_LABELS = {
    1: "Неизвестно", 2: "От сети", 3: "От батареи", 4: "AVR Boost",
    5: "Режим сна", 6: "Software bypass", 7: "Выход отключён", 8: "Перезагрузка",
    9: "Bypass", 10: "Аппаратный bypass", 11: "Ожидание питания", 12: "AVR Trim",
}
APC_TRANSFER_REASON_LABELS = {
    1: "Перехода не было", 2: "Высокое входное напряжение", 3: "Пониженное входное напряжение",
    4: "Пропадание входного питания", 5: "Кратковременная просадка", 6: "Глубокая просадка",
    7: "Кратковременный скачок", 8: "Сильный скачок", 9: "Самотест", 10: "Изменение напряжения",
}
APC_SELF_TEST_LABELS = {1: "Успешно", 2: "Ошибка", 3: "Недействительный тест", 4: "Выполняется"}


def battery_status_label(value: int | None, profile: str | None = None) -> str:
    labels = APC_BATTERY_LABELS if profile == "apc_powernet" else BATTERY_LABELS
    return labels.get(value, "Нет данных")


def output_source_label(value: int | None, profile: str | None = None) -> str:
    labels = APC_OUTPUT_LABELS if profile == "apc_powernet" else OUTPUT_LABELS
    return labels.get(value, "Нет данных")


def _number(item: SnmpVarBind | None) -> Decimal | None:
    if item is None or item.error or item.value is None:
        return None
    try:
        return Decimal(item.value)
    except InvalidOperation:
        return None


def _integer(item: SnmpVarBind | None) -> int | None:
    value = _number(item)
    return int(value) if value is not None and value == value.to_integral_value() else None


def ups_line_oids() -> tuple[str, ...]:
    result: list[str] = []
    # UPS-MIB input: frequency, voltage, current, true power.
    # Output: voltage, current, power, percent load.  A small fixed phase cap avoids walk.
    for index in range(1, MAX_UPS_LINES + 1):
        result.extend((f"{UPS_ROOT}.1.3.3.1.2.{index}", f"{UPS_ROOT}.1.3.3.1.3.{index}", f"{UPS_ROOT}.1.3.3.1.4.{index}", f"{UPS_ROOT}.1.3.3.1.5.{index}", f"{UPS_ROOT}.1.4.4.1.2.{index}", f"{UPS_ROOT}.1.4.4.1.3.{index}", f"{UPS_ROOT}.1.4.4.1.4.{index}", f"{UPS_ROOT}.1.4.4.1.5.{index}"))
    return tuple(result)


def ups_poll_oids() -> tuple[str, ...]:
    # One existing SNMP GET pipeline serves both RFC 1628 and APC PowerNet.
    # Unsupported optional OIDs become ordinary per-varbind NoSuchObject values.
    return tuple(dict.fromkeys(
        tuple(UPS_SCALAR_OIDS.values()) + ups_line_oids()
        + tuple(APC_SCALAR_OIDS.values()) + tuple(APC_HIGH_PRECISION_OIDS.values())
    ))


def _oid(base: str, index: int) -> str:
    return f"{base}.{index}"


class SnmpUpsService:
    """Persist normalized UPS data and reuse ordinary SNMP incidents."""

    def save_poll(self, session: Session, target: MonitorTarget, values: dict[str, SnmpVarBind], *, observed_at: datetime) -> list[IncidentNotification]:
        # Identity alone is not enough: some agents expose it while their RFC 1628
        # runtime branch is absent. A real status/source makes the standard profile.
        basic = [values.get(oid) for oid in (UPS_SCALAR_OIDS["battery_status"], UPS_SCALAR_OIDS["output_source"])]
        if not any(item is not None and item.error is None and item.value is not None for item in basic):
            return self._save_apc_poll(session, target, values, observed_at)
        state = session.get(SnmpUpsState, target.id)
        if state is None:
            state = SnmpUpsState(target_id=target.id)
            session.add(state)
            session.flush()
        old_battery, old_source = state.battery_status, state.output_source
        state.profile = "rfc1628"
        for field in ("manufacturer", "model"):
            item = values.get(UPS_SCALAR_OIDS[field])
            if item is not None and not item.error and item.value is not None:
                setattr(state, field, item.value[:255])
        for field in ("battery_status", "seconds_on_battery", "output_source", "input_lines", "output_lines"):
            value = _integer(values.get(UPS_SCALAR_OIDS[field]))
            if value is not None:
                setattr(state, field, value)
        # RFC 1628: runtime is minutes; battery V and frequency/current are tenths.
        normalized = {
            "estimated_runtime_minutes": (_number(values.get(UPS_SCALAR_OIDS["estimated_runtime_minutes"])), Decimal("1")),
            "battery_charge_percent": (_number(values.get(UPS_SCALAR_OIDS["battery_charge_percent"])), Decimal("1")),
            "battery_voltage": (_number(values.get(UPS_SCALAR_OIDS["battery_voltage"])), Decimal("10")),
            "battery_temperature": (_number(values.get(UPS_SCALAR_OIDS["battery_temperature"])), Decimal("1")),
        }
        for field, (value, divisor) in normalized.items():
            if value is not None:
                value = value / divisor
                setattr(state, field, value)
                self._add_sample(session, target.id, field, value, observed_at)
        output_frequency = _number(values.get(UPS_SCALAR_OIDS["output_frequency"]))
        state.last_polled_at, state.last_error = observed_at, None
        self._save_lines(session, state, values, observed_at, output_frequency)
        for key, old, current in (("battery_status", old_battery, state.battery_status), ("output_source", old_source, state.output_source)):
            if current is not None and old != current:
                session.add(SnmpUpsEvent(target_id=target.id, event_key=key, value=current, collected_at=observed_at))
        return self._apply_incidents(session, target, state, observed_at)

    def _save_apc_poll(self, session: Session, target: MonitorTarget, values: dict[str, SnmpVarBind], observed_at: datetime) -> list[IncidentNotification]:
        """Persist one APC PowerNet snapshot through the ordinary UPS entities."""
        basic = [values.get(APC_SCALAR_OIDS[key]) for key in ("battery_status", "output_source", "battery_charge_percent")]
        if not any(item is not None and item.error is None and item.value is not None for item in basic):
            return []
        state = session.get(SnmpUpsState, target.id)
        if state is None:
            state = SnmpUpsState(target_id=target.id)
            session.add(state)
            session.flush()
        old_battery, old_source = state.battery_status, state.output_source
        state.profile = "apc_powernet"
        state.manufacturer = "APC"
        model = values.get(APC_SCALAR_OIDS["model"])
        if model is not None and not model.error and model.value is not None:
            state.model = model.value[:255]
        for field in ("battery_status", "output_source"):
            value = _integer(values.get(APC_SCALAR_OIDS[field]))
            if value is not None:
                setattr(state, field, value)
        runtime_ticks = _number(values.get(APC_SCALAR_OIDS["estimated_runtime_minutes"]))
        if runtime_ticks is not None:
            # upsAdvBatteryRunTimeRemaining is TimeTicks (hundredths of a second).
            value = runtime_ticks / Decimal("6000")
            state.estimated_runtime_minutes = value
            self._add_sample(session, target.id, "estimated_runtime_minutes", value, observed_at)
        battery_voltage = _number(values.get(APC_SCALAR_OIDS["battery_voltage"]))
        if battery_voltage is not None:
            # The basic PowerNet scalar is already expressed in Volts.
            state.battery_voltage = battery_voltage
            self._add_sample(session, target.id, "battery_voltage", state.battery_voltage, observed_at)
        self._save_apc_battery_values(session, state, values, observed_at)
        self._save_apc_lines(session, state, values, observed_at)
        replace = _integer(values.get(APC_SCALAR_OIDS["battery_replace_needed"]))
        if replace is not None:
            state.battery_replace_needed = replace == 2
        reason = _integer(values.get(APC_SCALAR_OIDS["last_transfer_reason"]))
        if reason is not None:
            state.last_transfer_reason = APC_TRANSFER_REASON_LABELS.get(reason, "Нет данных")
        for field, labels in (("last_self_test_result", APC_SELF_TEST_LABELS),):
            value = _integer(values.get(APC_SCALAR_OIDS[field]))
            if value is not None:
                setattr(state, field, labels.get(value, "Нет данных"))
        tested_at = values.get(APC_SCALAR_OIDS["last_self_test_at"])
        if tested_at is not None and not tested_at.error and tested_at.value is not None:
            state.last_self_test_at = tested_at.value[:100]
        state.last_polled_at, state.last_error = observed_at, None
        for key, old, current in (("battery_status", old_battery, state.battery_status), ("output_source", old_source, state.output_source)):
            if current is not None and old != current:
                session.add(SnmpUpsEvent(target_id=target.id, event_key=key, value=current, collected_at=observed_at))
        return self._apply_incidents(session, target, state, observed_at)

    def _save_apc_battery_values(self, session: Session, state: SnmpUpsState, values: dict[str, SnmpVarBind], observed_at: datetime) -> None:
        for field in ("battery_charge_percent", "battery_temperature"):
            high_precision = _number(values.get(APC_HIGH_PRECISION_OIDS[field]))
            value = high_precision / Decimal("10") if high_precision is not None else _number(values.get(APC_SCALAR_OIDS[field]))
            if value is not None:
                setattr(state, field, value)
                self._add_sample(session, state.target_id, field, value, observed_at)

    def _save_apc_lines(self, session: Session, state: SnmpUpsState, values: dict[str, SnmpVarBind], observed_at: datetime) -> None:
        input_values = {
            "voltage": _number(values.get(APC_SCALAR_OIDS["input_voltage"])),
            "frequency": _number(values.get(APC_SCALAR_OIDS["input_frequency"])),
        }
        output_values: dict[str, Decimal | None] = {}
        for field in ("voltage", "frequency", "load_percent", "current"):
            key = f"output_{field}"
            high_precision = _number(values.get(APC_HIGH_PRECISION_OIDS[key]))
            output_values[field] = high_precision / Decimal("10") if high_precision is not None else _number(values.get(APC_SCALAR_OIDS[key]))
        for direction, raw in (("input", input_values), ("output", output_values)):
            if not any(value is not None for value in raw.values()):
                continue
            if direction == "input":
                state.input_lines = 1
            else:
                state.output_lines = 1
            line = next((item for item in state.lines if item.direction == direction and item.line_index == 1), None)
            if line is None:
                line = SnmpUpsLine(target_id=state.target_id, direction=direction, line_index=1)
                session.add(line)
            for field, value in raw.items():
                if value is not None:
                    setattr(line, field, value)
                    self._add_sample(session, state.target_id, f"{direction}_{field}:1", value, observed_at)
            line.last_polled_at = observed_at

    def _save_lines(self, session: Session, state: SnmpUpsState, values: dict[str, SnmpVarBind], observed_at: datetime, output_frequency: Decimal | None) -> None:
        existing = {(line.direction, line.line_index): line for line in state.lines}
        directions = (("input", state.input_lines or 0), ("output", state.output_lines or 0))
        for direction, count in directions:
            for index in range(1, min(count, MAX_UPS_LINES) + 1):
                line = existing.get((direction, index))
                if line is None:
                    line = SnmpUpsLine(target_id=state.target_id, direction=direction, line_index=index)
                    session.add(line)
                if direction == "input":
                    raw = {"frequency": _number(values.get(_oid(f"{UPS_ROOT}.1.3.3.1.2", index))), "voltage": _number(values.get(_oid(f"{UPS_ROOT}.1.3.3.1.3", index))), "current": _number(values.get(_oid(f"{UPS_ROOT}.1.3.3.1.4", index))), "power": _number(values.get(_oid(f"{UPS_ROOT}.1.3.3.1.5", index)))}
                else:
                    raw = {"voltage": _number(values.get(_oid(f"{UPS_ROOT}.1.4.4.1.2", index))), "current": _number(values.get(_oid(f"{UPS_ROOT}.1.4.4.1.3", index))), "power": _number(values.get(_oid(f"{UPS_ROOT}.1.4.4.1.4", index))), "load_percent": _number(values.get(_oid(f"{UPS_ROOT}.1.4.4.1.5", index))), "frequency": output_frequency}
                for field, value in raw.items():
                    if value is not None:
                        value = value / Decimal("10") if field in {"frequency", "current"} else value
                        setattr(line, field, value)
                        self._add_sample(
                            session,
                            state.target_id,
                            f"{direction}_{field}:{index}",
                            value,
                            observed_at,
                        )
                line.last_polled_at = observed_at

    @staticmethod
    def _add_sample(
        session: Session,
        target_id: int,
        metric_key: str,
        value: Decimal,
        observed_at: datetime,
    ) -> None:
        """Do not store a new sample while a UPS value remains unchanged."""
        previous = session.scalar(
            select(SnmpUpsSample.value)
            .where(
                SnmpUpsSample.target_id == target_id,
                SnmpUpsSample.metric_key == metric_key,
            )
            .order_by(SnmpUpsSample.collected_at.desc(), SnmpUpsSample.id.desc())
            .limit(1)
        )
        if previous != value:
            session.add(
                SnmpUpsSample(
                    target_id=target_id,
                    metric_key=metric_key,
                    collected_at=observed_at,
                    value=value,
                )
            )

    def _apply_incidents(self, session: Session, target: MonitorTarget, state: SnmpUpsState, observed_at: datetime) -> list[IncidentNotification]:
        service = IncidentService()
        result: list[IncidentNotification] = []
        battery = IncidentSeverity.CRITICAL if state.battery_status in {3, 4} else None
        if state.profile == "apc_powernet":
            source = IncidentSeverity.CRITICAL if state.output_source in {5, 7, 8, 11} else IncidentSeverity.WARNING if state.output_source in {3, 6, 9, 10} else None
        else:
            source = IncidentSeverity.CRITICAL if state.output_source == 2 else IncidentSeverity.WARNING if state.output_source in {4, 5} else None
        for key, severity, message in (("ups.battery", battery, f"ИБП: {battery_status_label(state.battery_status, state.profile)}"), ("ups.output", source, f"ИБП: {output_source_label(state.output_source, state.profile)}")):
            _incident, events = service.set_source_state(session, target, source_kind=IncidentSourceKind.SNMP, source_key=key, severity=severity, message=message if severity else "ИБП вернулся в норму", observed_at=observed_at)
            result.extend(events)
        return result

    @staticmethod
    def clear_data(session: Session, target_id: int) -> None:
        session.execute(delete(SnmpUpsSample).where(SnmpUpsSample.target_id == target_id))
        session.execute(delete(SnmpUpsEvent).where(SnmpUpsEvent.target_id == target_id))
        state = session.get(SnmpUpsState, target_id)
        if state is not None:
            session.delete(state)

    @staticmethod
    def trim_samples(session: Session, target_id: int, limit: int) -> None:
        """Apply the existing per-target SNMP data cap to UPS numeric history."""
        session.flush()
        overflow = (
            select(SnmpUpsSample.id)
            .where(SnmpUpsSample.target_id == target_id)
            .order_by(SnmpUpsSample.collected_at.desc(), SnmpUpsSample.id.desc())
            .offset(limit)
        )
        session.execute(delete(SnmpUpsSample).where(SnmpUpsSample.id.in_(overflow)))
