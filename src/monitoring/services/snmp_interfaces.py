from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

from monitoring.services.snmp_client import SnmpVarBind
from monitoring.services.snmp_oid_catalog import canonical_oid

MAX_SNMP_INTERFACES = 512
MAX_MONITORED_INTERFACES = 128
INTERFACE_DISCOVERY_MAX_SECONDS = 20

IF_COLUMNS: dict[str, str] = {
    "if_index": "1.3.6.1.2.1.2.2.1.1",
    "if_descr": "1.3.6.1.2.1.2.2.1.2",
    "if_type": "1.3.6.1.2.1.2.2.1.3",
    "if_mtu": "1.3.6.1.2.1.2.2.1.4",
    "if_speed": "1.3.6.1.2.1.2.2.1.5",
    "if_phys_address": "1.3.6.1.2.1.2.2.1.6",
    "if_admin_status": "1.3.6.1.2.1.2.2.1.7",
    "if_oper_status": "1.3.6.1.2.1.2.2.1.8",
    "if_name": "1.3.6.1.2.1.31.1.1.1.1",
    "if_high_speed": "1.3.6.1.2.1.31.1.1.1.15",
    "if_alias": "1.3.6.1.2.1.31.1.1.1.18",
}

IF_ADMIN_STATUS_BASE = IF_COLUMNS["if_admin_status"]
IF_OPER_STATUS_BASE = IF_COLUMNS["if_oper_status"]

IF_IN_OCTETS_BASE = "1.3.6.1.2.1.2.2.1.10"
IF_IN_DISCARDS_BASE = "1.3.6.1.2.1.2.2.1.13"
IF_IN_ERRORS_BASE = "1.3.6.1.2.1.2.2.1.14"
IF_OUT_OCTETS_BASE = "1.3.6.1.2.1.2.2.1.16"
IF_OUT_DISCARDS_BASE = "1.3.6.1.2.1.2.2.1.19"
IF_OUT_ERRORS_BASE = "1.3.6.1.2.1.2.2.1.20"
IF_HC_IN_OCTETS_BASE = "1.3.6.1.2.1.31.1.1.1.6"
IF_HC_OUT_OCTETS_BASE = "1.3.6.1.2.1.31.1.1.1.10"

TRAFFIC_COUNTER_HC64 = "hc64"
TRAFFIC_COUNTER_LEGACY32 = "legacy32"
TRAFFIC_COUNTER_MODES = frozenset({TRAFFIC_COUNTER_HC64, TRAFFIC_COUNTER_LEGACY32})
_COUNTER32_MODULUS = 1 << 32

_ADMIN_STATUS_LABELS = {1: "Up", 2: "Down", 3: "Testing"}
_OPER_STATUS_LABELS = {
    1: "Up",
    2: "Down",
    3: "Testing",
    4: "Unknown",
    5: "Dormant",
    6: "Not present",
    7: "Lower layer down",
}


@dataclass(frozen=True, slots=True)
class SnmpInterfaceSnapshot:
    if_index: int
    if_name: str | None = None
    if_descr: str | None = None
    if_alias: str | None = None
    if_type: int | None = None
    if_mtu: int | None = None
    speed_bps: int | None = None
    phys_address: str | None = None
    admin_status: int | None = None
    oper_status: int | None = None


@dataclass(frozen=True, slots=True)
class SnmpInterfaceTrafficSnapshot:
    counter_mode: str | None
    in_octets: int | None
    out_octets: int | None
    in_errors: int | None
    out_errors: int | None
    in_discards: int | None
    out_discards: int | None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class SnmpInterfacesResult:
    status: str
    message: str
    items: tuple[SnmpInterfaceSnapshot, ...]
    elapsed_ms: int = 0
    truncated: bool = False


def interface_status_label(value: int | None, *, administrative: bool = False) -> str:
    if value is None:
        return "—"
    labels = _ADMIN_STATUS_LABELS if administrative else _OPER_STATUS_LABELS
    return labels.get(value, f"Другое ({value})")


def format_interface_speed(value: int | None) -> str:
    if value is None or value <= 0:
        return "—"
    units = ((1_000_000_000, "Gbit/s"), (1_000_000, "Mbit/s"), (1_000, "Kbit/s"))
    for divisor, label in units:
        if value >= divisor:
            amount = value / divisor
            return f"{amount:.0f} {label}" if amount >= 10 or amount.is_integer() else f"{amount:.1f} {label}"
    return f"{value} bit/s"


def format_interface_rate(value: int | None) -> str:
    if value is None or value < 0:
        return "—"
    return f"{value / 1_000_000:.1f}"


def status_oid(base: str, if_index: int) -> str:
    if if_index <= 0:
        raise ValueError("ifIndex должен быть положительным")
    return f"{base}.{if_index}"


def traffic_poll_oids(
    if_index: int, counter_mode: str | None, *, supports_counter64: bool = True
) -> tuple[str, ...]:
    common = (
        status_oid(IF_IN_ERRORS_BASE, if_index),
        status_oid(IF_OUT_ERRORS_BASE, if_index),
        status_oid(IF_IN_DISCARDS_BASE, if_index),
        status_oid(IF_OUT_DISCARDS_BASE, if_index),
    )
    if counter_mode == TRAFFIC_COUNTER_HC64 and supports_counter64:
        counters = (
            status_oid(IF_HC_IN_OCTETS_BASE, if_index),
            status_oid(IF_HC_OUT_OCTETS_BASE, if_index),
        )
    elif counter_mode == TRAFFIC_COUNTER_LEGACY32:
        counters = (
            status_oid(IF_IN_OCTETS_BASE, if_index),
            status_oid(IF_OUT_OCTETS_BASE, if_index),
        )
    elif supports_counter64:
        counters = (
            status_oid(IF_HC_IN_OCTETS_BASE, if_index),
            status_oid(IF_HC_OUT_OCTETS_BASE, if_index),
            status_oid(IF_IN_OCTETS_BASE, if_index),
            status_oid(IF_OUT_OCTETS_BASE, if_index),
        )
    else:
        # Counter64 and IF-MIB high-capacity octet counters are not part of SNMPv1.
        counters = (
            status_oid(IF_IN_OCTETS_BASE, if_index),
            status_oid(IF_OUT_OCTETS_BASE, if_index),
        )
    return counters + common


def counter_rate_bps(
    new_value: int,
    old_value: int,
    elapsed_seconds: float,
    *,
    counter_mode: str,
    interface_speed_bps: int | None = None,
) -> int | None:
    if new_value < 0 or old_value < 0 or elapsed_seconds <= 0:
        return None
    if new_value >= old_value:
        delta = new_value - old_value
    elif counter_mode == TRAFFIC_COUNTER_LEGACY32:
        high_watermark = _COUNTER32_MODULUS * 9 // 10
        low_watermark = _COUNTER32_MODULUS // 10
        if old_value < high_watermark or new_value > low_watermark:
            return None
        delta = (_COUNTER32_MODULUS - old_value) + new_value
    else:
        return None

    rate = int((delta * 8) / elapsed_seconds)
    if interface_speed_bps and interface_speed_bps > 0 and rate > int(interface_speed_bps * 1.25):
        return None
    return max(rate, 0)


def _column_index(oid: str, base: str) -> int | None:
    normalized = canonical_oid(oid)
    prefix = f"{base}."
    if not normalized.startswith(prefix):
        return None
    suffix = normalized[len(prefix) :]
    if not suffix.isdecimal():
        return None
    value = int(suffix)
    return value if value > 0 else None


def _integer_value(item: SnmpVarBind | None) -> int | None:
    if item is None or item.value is None or item.error is not None:
        return None
    try:
        number = Decimal(item.value)
    except InvalidOperation:
        return None
    if number != number.to_integral_value():
        return None
    return int(number)


def build_traffic_snapshot(
    values: dict[str, SnmpVarBind],
    if_index: int,
    counter_mode: str | None,
) -> SnmpInterfaceTrafficSnapshot:
    def counter(base: str) -> int | None:
        value = _integer_value(values.get(status_oid(base, if_index)))
        return value if value is not None and value >= 0 else None

    def pair(mode: str) -> tuple[int | None, int | None]:
        if mode == TRAFFIC_COUNTER_HC64:
            return counter(IF_HC_IN_OCTETS_BASE), counter(IF_HC_OUT_OCTETS_BASE)
        return counter(IF_IN_OCTETS_BASE), counter(IF_OUT_OCTETS_BASE)

    selected_mode = counter_mode if counter_mode in TRAFFIC_COUNTER_MODES else None
    if selected_mode is not None:
        in_octets, out_octets = pair(selected_mode)
        if in_octets is None or out_octets is None:
            selected_mode = None
    else:
        in_octets, out_octets = pair(TRAFFIC_COUNTER_HC64)
        if in_octets is not None and out_octets is not None:
            selected_mode = TRAFFIC_COUNTER_HC64
        else:
            in_octets, out_octets = pair(TRAFFIC_COUNTER_LEGACY32)
            if in_octets is not None and out_octets is not None:
                selected_mode = TRAFFIC_COUNTER_LEGACY32

    error = None
    if selected_mode is None:
        in_octets = None
        out_octets = None
        candidate_items = (
            values.get(status_oid(IF_HC_IN_OCTETS_BASE, if_index)),
            values.get(status_oid(IF_HC_OUT_OCTETS_BASE, if_index)),
            values.get(status_oid(IF_IN_OCTETS_BASE, if_index)),
            values.get(status_oid(IF_OUT_OCTETS_BASE, if_index)),
        )
        error = next(
            (item.error for item in candidate_items if item is not None and item.error),
            "OID счётчиков трафика не вернули данные",
        )

    return SnmpInterfaceTrafficSnapshot(
        counter_mode=selected_mode,
        in_octets=in_octets,
        out_octets=out_octets,
        in_errors=counter(IF_IN_ERRORS_BASE),
        out_errors=counter(IF_OUT_ERRORS_BASE),
        in_discards=counter(IF_IN_DISCARDS_BASE),
        out_discards=counter(IF_OUT_DISCARDS_BASE),
        error=error,
    )


def _text_value(item: SnmpVarBind | None) -> str | None:
    if item is None or item.value is None or item.error is not None:
        return None
    value = item.value.strip()
    return value or None


def build_interface_snapshots(
    columns: dict[str, tuple[SnmpVarBind, ...]],
) -> tuple[SnmpInterfaceSnapshot, ...]:
    by_index: dict[int, dict[str, SnmpVarBind]] = {}
    for key, base in IF_COLUMNS.items():
        for item in columns.get(key, ()):
            if_index = _column_index(item.oid, base)
            if if_index is not None:
                by_index.setdefault(if_index, {})[key] = item

    result: list[SnmpInterfaceSnapshot] = []
    for if_index in sorted(by_index):
        values = by_index[if_index]
        high_speed_mbps = _integer_value(values.get("if_high_speed"))
        legacy_speed = _integer_value(values.get("if_speed"))
        speed_bps = high_speed_mbps * 1_000_000 if high_speed_mbps else legacy_speed
        result.append(
            SnmpInterfaceSnapshot(
                if_index=if_index,
                if_name=_text_value(values.get("if_name")),
                if_descr=_text_value(values.get("if_descr")),
                if_alias=_text_value(values.get("if_alias")),
                if_type=_integer_value(values.get("if_type")),
                if_mtu=_integer_value(values.get("if_mtu")),
                speed_bps=speed_bps,
                phys_address=_text_value(values.get("if_phys_address")),
                admin_status=_integer_value(values.get("if_admin_status")),
                oper_status=_integer_value(values.get("if_oper_status")),
            )
        )
    return tuple(result)
