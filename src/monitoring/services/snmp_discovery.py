from __future__ import annotations

import time
from dataclasses import dataclass
from secrets import token_urlsafe
from threading import Lock

from monitoring.services.snmp_oid_catalog import (
    DISCOVERY_BRANCHES,
    canonical_oid,
    discovery_oid_category,
    discovery_oid_category_label,
    is_recommended_oid,
)

MAX_DISCOVERY_RESULTS = 5000
DISCOVERY_MAX_SECONDS = 30
DISCOVERY_TTL_SECONDS = 600
DISCOVERY_MAX_SESSIONS = 8
DISCOVERY_DEFAULT_PAGE_SIZE = 100
DISCOVERY_MAX_VALUE_CHARS = 2000


@dataclass(frozen=True, slots=True)
class SnmpDiscoveryItem:
    oid: str
    name: str | None
    value: str | None
    detected_type: str
    error: str | None
    is_system: bool = False
    is_monitored: bool = False

    @property
    def selectable(self) -> bool:
        return not self.is_system and not self.is_monitored and self.error is None

    @property
    def category(self) -> str:
        return discovery_oid_category(self.oid)

    @property
    def category_label(self) -> str:
        return discovery_oid_category_label(self.oid)

    @property
    def recommended(self) -> bool:
        return is_recommended_oid(self.oid)


@dataclass(frozen=True, slots=True)
class SnmpDiscoveryResult:
    status: str
    message: str
    items: tuple[SnmpDiscoveryItem, ...]
    roots: tuple[str, ...]
    truncated: bool = False
    elapsed_ms: int = 0


@dataclass(frozen=True, slots=True)
class _StoredDiscovery:
    token: str
    target_id: int
    user_id: int
    created_monotonic: float
    result: SnmpDiscoveryResult


class SnmpDiscoveryStore:
    """Short-lived process-local storage for manual discovery results.

    Monitoring Maxval currently runs a single app process/scheduler. Discovery is
    configuration-time data, so losing it on restart is harmless and avoids
    persisting thousands of unused OIDs in PostgreSQL.
    """

    def __init__(
        self,
        *,
        ttl_seconds: int = DISCOVERY_TTL_SECONDS,
        max_sessions: int = DISCOVERY_MAX_SESSIONS,
    ) -> None:
        self._ttl_seconds = ttl_seconds
        self._max_sessions = max_sessions
        self._entries: dict[str, _StoredDiscovery] = {}
        self._lock = Lock()

    def put(self, *, target_id: int, user_id: int, result: SnmpDiscoveryResult) -> str:
        with self._lock:
            now = time.monotonic()
            self._purge_locked(now)
            while len(self._entries) >= self._max_sessions:
                oldest = min(self._entries.values(), key=lambda item: item.created_monotonic)
                self._entries.pop(oldest.token, None)
            token = token_urlsafe(18)
            self._entries[token] = _StoredDiscovery(token, target_id, user_id, now, result)
            return token

    def get(
        self, token: str | None, *, target_id: int, user_id: int
    ) -> SnmpDiscoveryResult | None:
        if not token:
            return None
        with self._lock:
            now = time.monotonic()
            self._purge_locked(now)
            entry = self._entries.get(token)
            if entry is None or entry.target_id != target_id or entry.user_id != user_id:
                return None
            return entry.result

    def _purge_locked(self, now: float) -> None:
        expired = [
            token
            for token, entry in self._entries.items()
            if now - entry.created_monotonic > self._ttl_seconds
        ]
        for token in expired:
            self._entries.pop(token, None)


def discovery_roots(mode: str, custom_oid: str = "") -> tuple[str, ...]:
    if mode == "custom":
        return (canonical_oid(custom_oid),)
    roots = DISCOVERY_BRANCHES.get(mode)
    if roots is None:
        raise ValueError("Неизвестная область SNMP Discovery")
    return roots


discovery_store = SnmpDiscoveryStore()
