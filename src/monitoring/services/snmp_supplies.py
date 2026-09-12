from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

from monitoring.services.snmp_client import SnmpVarBind
from monitoring.services.snmp_oid_catalog import canonical_oid

PRINTER_SUPPLIES_ENTRY_ROOT = "1.3.6.1.2.1.43.11.1.1"
PRINTER_SUPPLIES_COLUMNS: dict[str, str] = {
    "marker_index": f"{PRINTER_SUPPLIES_ENTRY_ROOT}.2",
    "colorant_index": f"{PRINTER_SUPPLIES_ENTRY_ROOT}.3",
    "supply_class": f"{PRINTER_SUPPLIES_ENTRY_ROOT}.4",
    "supply_type": f"{PRINTER_SUPPLIES_ENTRY_ROOT}.5",
    "description": f"{PRINTER_SUPPLIES_ENTRY_ROOT}.6",
    "unit_code": f"{PRINTER_SUPPLIES_ENTRY_ROOT}.7",
    "max_capacity": f"{PRINTER_SUPPLIES_ENTRY_ROOT}.8",
    "level": f"{PRINTER_SUPPLIES_ENTRY_ROOT}.9",
}
PRINTER_SUPPLIES_DISCOVERY_MAX_SECONDS = 20
MAX_PRINTER_SUPPLIES = 64
SUPPLY_UNIT_PERCENT = 19
SUPPLY_CLASS_CONSUMED = 3
SUPPLY_CLASS_RECEPTACLE = 4

SUPPLY_CLASS_LABELS = {
    1: "Другое",
    SUPPLY_CLASS_CONSUMED: "Расходуется",
    SUPPLY_CLASS_RECEPTACLE: "Заполняется",
}
SUPPLY_TYPE_LABELS = {
    1: "Другое",
    2: "Неизвестно",
    3: "Тонер",
    4: "Отработанный тонер",
    5: "Чернила",
    6: "Картридж с чернилами",
    7: "Красящая лента",
    8: "Отработанные чернила",
    9: "Фотобарабан",
    10: "Девелопер",
    11: "Масло фьюзера",
    12: "Твёрдые чернила",
    13: "Восковая лента",
    14: "Отработанный воск",
    15: "Фьюзер",
    16: "Коронатор",
    17: "Фитиль масла фьюзера",
    18: "Узел очистки",
    19: "Чистящая подушка фьюзера",
    20: "Узел переноса",
    21: "Тонер-картридж",
    22: "Маслёнка фьюзера",
}
SUPPLY_UNIT_LABELS = {
    1: "другое",
    2: "неизвестно",
    3: "0.0001 дюйма",
    4: "мкм",
    7: "отпечатков",
    8: "листов",
    11: "часов",
    12: "0.001 унции",
    13: "0.1 г",
    14: "0.01 fl oz",
    15: "0.1 мл",
    16: "футов",
    17: "метров",
    18: "шт.",
    SUPPLY_UNIT_PERCENT: "%",
}


@dataclass(frozen=True, slots=True)
class SnmpSupplySnapshot:
    hr_device_index: int
    supply_index: int
    marker_index: int | None = None
    colorant_index: int | None = None
    supply_class: int | None = None
    supply_type: int | None = None
    description: str | None = None
    unit_code: int | None = None
    max_capacity: int | None = None
    level: int | None = None
    percent_remaining: float | None = None
    level_state: str = "missing"


@dataclass(frozen=True, slots=True)
class SnmpSuppliesResult:
    status: str
    message: str
    items: tuple[SnmpSupplySnapshot, ...]
    elapsed_ms: int = 0
    truncated: bool = False


def supply_oid(column: str, hr_device_index: int, supply_index: int) -> str:
    if column not in PRINTER_SUPPLIES_COLUMNS:
        raise ValueError("Неизвестная колонка Printer-MIB")
    if hr_device_index <= 0 or supply_index <= 0:
        raise ValueError("Индексы Printer-MIB должны быть положительными")
    return f"{PRINTER_SUPPLIES_COLUMNS[column]}.{hr_device_index}.{supply_index}"


def supply_poll_oids(hr_device_index: int, supply_index: int) -> tuple[str, str]:
    return (
        supply_oid("max_capacity", hr_device_index, supply_index),
        supply_oid("level", hr_device_index, supply_index),
    )


def _entry_key(oid: str, base: str) -> tuple[int, int] | None:
    normalized = canonical_oid(oid)
    prefix = f"{base}."
    if not normalized.startswith(prefix):
        return None
    suffix = normalized[len(prefix) :].split(".")
    if len(suffix) != 2 or not all(part.isdecimal() for part in suffix):
        return None
    hr_device_index, supply_index = (int(part) for part in suffix)
    if hr_device_index <= 0 or supply_index <= 0:
        return None
    return hr_device_index, supply_index


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


def _text_value(item: SnmpVarBind | None) -> str | None:
    if item is None or item.value is None or item.error is not None:
        return None
    text = item.value.strip()
    return text or None


def normalize_supply_level(
    *,
    supply_class: int | None,
    unit_code: int | None,
    max_capacity: int | None,
    level: int | None,
) -> tuple[float | None, str]:
    """Convert Printer-MIB level to a safe 0..100 percentage when possible.

    RFC 3805 reserves -1/-2/-3 for other/unknown/some-remaining. Those values
    intentionally produce no percentage so a low-level threshold cannot create a
    false incident from an SNMP sentinel value.
    """
    if level is None:
        return None, "missing"
    if level == -1:
        return None, "other"
    if level == -2:
        return None, "unknown"
    if level == -3:
        return None, "some"
    if level < 0:
        return None, "invalid"
    if unit_code == SUPPLY_UNIT_PERCENT and level <= 100:
        percentage = float(level)
    elif max_capacity is None or max_capacity <= 0:
        return None, "no_capacity"
    else:
        percentage = min(max((level / max_capacity) * 100.0, 0.0), 100.0)
    # For receptacles (for example a waste-toner container), Printer-MIB reports
    # how full the receptacle is. Store the free percentage instead so every
    # supply threshold can consistently alert on a low remaining percentage.
    if supply_class == SUPPLY_CLASS_RECEPTACLE:
        percentage = 100.0 - percentage
    return percentage, "ok"


def build_supply_snapshots(items: tuple[SnmpVarBind, ...]) -> tuple[SnmpSupplySnapshot, ...]:
    entries: dict[tuple[int, int], dict[str, SnmpVarBind]] = {}
    for column, base in PRINTER_SUPPLIES_COLUMNS.items():
        for item in items:
            key = _entry_key(item.oid, base)
            if key is not None:
                entries.setdefault(key, {})[column] = item

    result: list[SnmpSupplySnapshot] = []
    for (hr_device_index, supply_index), values in sorted(entries.items()):
        level = _integer_value(values.get("level"))
        max_capacity = _integer_value(values.get("max_capacity"))
        unit_code = _integer_value(values.get("unit_code"))
        supply_class = _integer_value(values.get("supply_class"))
        percent_remaining, level_state = normalize_supply_level(
            supply_class=supply_class,
            unit_code=unit_code,
            max_capacity=max_capacity,
            level=level,
        )
        result.append(
            SnmpSupplySnapshot(
                hr_device_index=hr_device_index,
                supply_index=supply_index,
                marker_index=_integer_value(values.get("marker_index")),
                colorant_index=_integer_value(values.get("colorant_index")),
                supply_class=supply_class,
                supply_type=_integer_value(values.get("supply_type")),
                description=_text_value(values.get("description")),
                unit_code=unit_code,
                max_capacity=max_capacity,
                level=level,
                percent_remaining=percent_remaining,
                level_state=level_state,
            )
        )
    return tuple(result[:MAX_PRINTER_SUPPLIES])


def supply_type_label(value: int | None) -> str:
    if value is None:
        return "—"
    return SUPPLY_TYPE_LABELS.get(value, f"Тип {value}")


def supply_class_label(value: int | None) -> str:
    if value is None:
        return "—"
    return SUPPLY_CLASS_LABELS.get(value, f"Класс {value}")


def supply_unit_label(value: int | None) -> str:
    if value is None:
        return "—"
    return SUPPLY_UNIT_LABELS.get(value, f"unit {value}")


def supply_level_label(
    *, level: int | None, percent_remaining: float | None, level_state: str
) -> str:
    if percent_remaining is not None:
        rounded = round(percent_remaining, 1)
        return f"{rounded:g}%"
    return {
        "other": "Другое",
        "unknown": "Неизвестно",
        "some": "Есть, точный уровень неизвестен",
        "no_capacity": str(level) if level is not None else "—",
        "invalid": "Некорректное значение",
        "error": "Ошибка",
        "missing": "—",
    }.get(level_state, "—")
