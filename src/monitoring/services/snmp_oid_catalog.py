from __future__ import annotations

import re

OID_PATTERN = re.compile(r"^\.?[0-9]+(?:\.[0-9]+)+$")


def canonical_oid(value: str) -> str:
    oid = value.strip()
    if not OID_PATTERN.fullmatch(oid):
        raise ValueError("OID должен состоять из чисел, разделённых точками")
    return oid.lstrip(".")


SYSTEM_OIDS = {
    "sys_descr": "1.3.6.1.2.1.1.1.0",
    "sys_object_id": "1.3.6.1.2.1.1.2.0",
    "sys_uptime_ticks": "1.3.6.1.2.1.1.3.0",
    "sys_name": "1.3.6.1.2.1.1.5.0",
}

DISCOVERY_BRANCHES: dict[str, tuple[str, ...]] = {
    "standard": (
        "1.3.6.1.2.1.1",
        "1.3.6.1.2.1.2",
        "1.3.6.1.2.1.31",
    ),
    "system": ("1.3.6.1.2.1.1",),
    "interfaces": ("1.3.6.1.2.1.2",),
    "if_mib": ("1.3.6.1.2.1.31",),
}

# Small built-in catalog only. This is intentionally not a MIB parser.
_STANDARD_BASE_NAMES: dict[str, str] = {
    "1.3.6.1.2.1.1.1": "sysDescr",
    "1.3.6.1.2.1.1.2": "sysObjectID",
    "1.3.6.1.2.1.1.3": "sysUpTime",
    "1.3.6.1.2.1.1.5": "sysName",
    "1.3.6.1.2.1.2.2.1.1": "ifIndex",
    "1.3.6.1.2.1.2.2.1.2": "ifDescr",
    "1.3.6.1.2.1.2.2.1.3": "ifType",
    "1.3.6.1.2.1.2.2.1.4": "ifMtu",
    "1.3.6.1.2.1.2.2.1.5": "ifSpeed",
    "1.3.6.1.2.1.2.2.1.6": "ifPhysAddress",
    "1.3.6.1.2.1.2.2.1.7": "ifAdminStatus",
    "1.3.6.1.2.1.2.2.1.8": "ifOperStatus",
    "1.3.6.1.2.1.2.2.1.9": "ifLastChange",
    "1.3.6.1.2.1.2.2.1.10": "ifInOctets",
    "1.3.6.1.2.1.2.2.1.13": "ifInDiscards",
    "1.3.6.1.2.1.2.2.1.14": "ifInErrors",
    "1.3.6.1.2.1.2.2.1.16": "ifOutOctets",
    "1.3.6.1.2.1.2.2.1.19": "ifOutDiscards",
    "1.3.6.1.2.1.2.2.1.20": "ifOutErrors",
    "1.3.6.1.2.1.31.1.1.1.1": "ifName",
    "1.3.6.1.2.1.31.1.1.1.6": "ifHCInOctets",
    "1.3.6.1.2.1.31.1.1.1.10": "ifHCOutOctets",
    "1.3.6.1.2.1.31.1.1.1.15": "ifHighSpeed",
    "1.3.6.1.2.1.31.1.1.1.18": "ifAlias",
}

_SORTED_BASES = tuple(sorted(_STANDARD_BASE_NAMES, key=len, reverse=True))
_SYSTEM_INSTANCES = frozenset(SYSTEM_OIDS.values())

DISCOVERY_CATEGORY_LABELS: dict[str, str] = {
    "system": "Система",
    "interface": "Интерфейс",
    "port_status": "Состояние порта",
    "traffic": "Трафик",
    "errors": "Ошибки",
    "standard": "Прочее стандартное",
    "vendor": "Vendor",
    "unknown": "Неизвестное",
}

_TRAFFIC_BASES = frozenset(
    {
        "1.3.6.1.2.1.2.2.1.10",  # ifInOctets
        "1.3.6.1.2.1.2.2.1.16",  # ifOutOctets
        "1.3.6.1.2.1.31.1.1.1.6",  # ifHCInOctets
        "1.3.6.1.2.1.31.1.1.1.10",  # ifHCOutOctets
    }
)
_ERROR_BASES = frozenset(
    {
        "1.3.6.1.2.1.2.2.1.13",  # ifInDiscards
        "1.3.6.1.2.1.2.2.1.14",  # ifInErrors
        "1.3.6.1.2.1.2.2.1.19",  # ifOutDiscards
        "1.3.6.1.2.1.2.2.1.20",  # ifOutErrors
    }
)
_PORT_STATUS_BASES = frozenset(
    {
        "1.3.6.1.2.1.2.2.1.7",  # ifAdminStatus
        "1.3.6.1.2.1.2.2.1.8",  # ifOperStatus
        "1.3.6.1.2.1.2.2.1.9",  # ifLastChange
    }
)
_RECOMMENDED_BASES = frozenset(
    {
        *SYSTEM_OIDS.values(),
        "1.3.6.1.2.1.2.2.1.2",  # ifDescr
        "1.3.6.1.2.1.2.2.1.5",  # ifSpeed
        "1.3.6.1.2.1.2.2.1.7",  # ifAdminStatus
        "1.3.6.1.2.1.2.2.1.8",  # ifOperStatus
        "1.3.6.1.2.1.2.2.1.10",  # ifInOctets fallback
        "1.3.6.1.2.1.2.2.1.13",  # ifInDiscards
        "1.3.6.1.2.1.2.2.1.14",  # ifInErrors
        "1.3.6.1.2.1.2.2.1.16",  # ifOutOctets fallback
        "1.3.6.1.2.1.2.2.1.19",  # ifOutDiscards
        "1.3.6.1.2.1.2.2.1.20",  # ifOutErrors
        "1.3.6.1.2.1.31.1.1.1.1",  # ifName
        "1.3.6.1.2.1.31.1.1.1.6",  # ifHCInOctets
        "1.3.6.1.2.1.31.1.1.1.10",  # ifHCOutOctets
        "1.3.6.1.2.1.31.1.1.1.15",  # ifHighSpeed
        "1.3.6.1.2.1.31.1.1.1.18",  # ifAlias
    }
)


def _matches_base(oid: str, bases: frozenset[str]) -> bool:
    return any(oid == base or oid.startswith(f"{base}.") for base in bases)


def _in_branch(oid: str, branch: str) -> bool:
    return oid == branch or oid.startswith(f"{branch}.")


def discovery_oid_category(oid: str) -> str:
    """Return a compact UI category for a discovered OID."""
    if _in_branch(oid, "1.3.6.1.2.1.1"):
        return "system"
    if _matches_base(oid, _TRAFFIC_BASES):
        return "traffic"
    if _matches_base(oid, _ERROR_BASES):
        return "errors"
    if _matches_base(oid, _PORT_STATUS_BASES):
        return "port_status"
    if _in_branch(oid, "1.3.6.1.2.1.2") or _in_branch(oid, "1.3.6.1.2.1.31"):
        return "interface"
    if _in_branch(oid, "1.3.6.1.4.1"):
        return "vendor"
    if _in_branch(oid, "1.3.6.1.2.1"):
        return "standard"
    return "unknown"


def discovery_oid_category_label(oid: str) -> str:
    return DISCOVERY_CATEGORY_LABELS[discovery_oid_category(oid)]


def is_recommended_oid(oid: str) -> bool:
    """Mark a small, practical subset that is useful for first-pass monitoring."""
    return _matches_base(oid, _RECOMMENDED_BASES)


def standard_oid_name(oid: str) -> str | None:
    """Return a compact built-in name such as ``ifName.5`` when known."""
    for base in _SORTED_BASES:
        if oid == base:
            return _STANDARD_BASE_NAMES[base]
        prefix = f"{base}."
        if oid.startswith(prefix):
            suffix = oid[len(prefix) :]
            return f"{_STANDARD_BASE_NAMES[base]}.{suffix}"
    return None


def is_system_oid(oid: str) -> bool:
    return oid in _SYSTEM_INSTANCES
