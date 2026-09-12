from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session, sessionmaker

from monitoring.config import Settings
from monitoring.models import (
    AppSetting,
    MonitorTarget,
    SnmpConfig,
    SnmpInterface,
    SnmpInterfaceSample,
    SnmpMetric,
    SnmpSample,
    SnmpStatus,
    SnmpSupply,
)
from monitoring.services.incidents import IncidentNotification
from monitoring.services.secrets import decrypt_secret, encrypt_secret
from monitoring.services.snmp_client import (
    SnmpClient,
    SnmpClientError,
    SnmpRequest,
    SnmpVarBind,
)
from monitoring.services.snmp_discovery import (
    DISCOVERY_MAX_SECONDS,
    DISCOVERY_MAX_VALUE_CHARS,
    MAX_DISCOVERY_RESULTS,
    SnmpDiscoveryItem,
    SnmpDiscoveryResult,
)
from monitoring.services.snmp_formula import (
    CompiledSnmpFormula,
    FormulaError,
    compile_snmp_formula,
)
from monitoring.services.snmp_interfaces import (
    IF_ADMIN_STATUS_BASE,
    IF_COLUMNS,
    IF_OPER_STATUS_BASE,
    INTERFACE_DISCOVERY_MAX_SECONDS,
    MAX_SNMP_INTERFACES,
    SnmpInterfaceSnapshot,
    SnmpInterfacesResult,
    build_interface_snapshots,
    build_traffic_snapshot,
    counter_rate_bps,
    status_oid,
    traffic_poll_oids,
)
from monitoring.services.snmp_oid_catalog import (
    SYSTEM_OIDS,
    canonical_oid,
    is_system_oid,
    standard_oid_name,
)
from monitoring.services.snmp_supplies import (
    MAX_PRINTER_SUPPLIES,
    PRINTER_SUPPLIES_COLUMNS,
    PRINTER_SUPPLIES_DISCOVERY_MAX_SECONDS,
    SnmpSuppliesResult,
    SnmpSupplySnapshot,
    build_supply_snapshots,
    normalize_supply_level,
    supply_oid,
    supply_poll_oids,
)
from monitoring.services.snmp_thresholds import SnmpThresholdService
from monitoring.services.snmp_ups import SnmpUpsService, ups_poll_oids

MAX_MANUAL_OIDS_PER_TARGET = 32
MAX_SNMP_SAMPLES_PER_TARGET = 1000
MIN_SNMP_SAMPLES_PER_TARGET = 100
MAX_CONFIGURABLE_SNMP_SAMPLES_PER_TARGET = 100000
SNMP_GET_CHUNK_SIZE = 16
SUPPORTED_SNMP_VERSIONS = frozenset({"v1", "v2c"})
NUMERIC_TYPES = frozenset(
    {"Integer", "Integer32", "Gauge32", "Counter32", "Counter64", "TimeTicks"}
)


@dataclass(frozen=True, slots=True)
class SnmpSettingsForm:
    enabled: bool
    port: int
    community: str
    timeout_seconds: int
    retries: int
    ups_enabled: bool = False
    version: str = "v2c"


@dataclass(frozen=True, slots=True)
class SnmpMetricForm:
    name: str
    oid: str
    unit: str
    enabled: bool
    source_kind: str = "oid"
    formula: str = ""


@dataclass(frozen=True, slots=True)
class _MetricPoll:
    id: int
    oid: str | None
    formula: CompiledSnmpFormula | None


@dataclass(frozen=True, slots=True)
class SnmpTestResult:
    status: str
    message: str
    values: dict[str, str]


@dataclass(frozen=True, slots=True)
class _PollRequest:
    target_id: int
    request: SnmpRequest
    metrics: tuple[_MetricPoll, ...]
    interface_ids: tuple[tuple[int, int, str | None], ...]
    supply_ids: tuple[tuple[int, int, int], ...]
    ups_enabled: bool


def _oid_sort_key(oid: str) -> tuple[int, ...]:
    return tuple(int(part) for part in oid.split("."))


def _safe_error(message: str) -> str:
    return message[:500]


def _numeric_value(value: SnmpVarBind) -> Decimal | None:
    if value.detected_type not in NUMERIC_TYPES or value.value is None:
        return None
    try:
        number = Decimal(value.value)
    except InvalidOperation:
        return None
    return number if number == number.to_integral_value() else None


def _format_numeric_value(value: Decimal) -> str:
    """Keep a readable decimal representation without scientific notation."""
    rendered = format(value, "f").rstrip("0").rstrip(".")
    return rendered or "0"


def snmp_sample_limit(session: Session) -> int:
    """Return the validated per-target cap for numeric SNMP history."""
    setting = session.get(AppSetting, "snmp_sample_max_per_target")
    try:
        limit = int(setting.value) if setting is not None else MAX_SNMP_SAMPLES_PER_TARGET
    except ValueError:
        return MAX_SNMP_SAMPLES_PER_TARGET
    if not MIN_SNMP_SAMPLES_PER_TARGET <= limit <= MAX_CONFIGURABLE_SNMP_SAMPLES_PER_TARGET:
        return MAX_SNMP_SAMPLES_PER_TARGET
    return limit


def trim_snmp_samples_for_target(session: Session, target_id: int) -> None:
    """Keep numeric SNMP history for one target within its configured cap."""
    # Production sessions intentionally use autoflush=False.  Flush pending samples
    # so both an automatic poll and an immediate settings update apply the cap to the
    # data that is actually about to be committed, not only to the previous poll.
    session.flush()
    overflow_ids = (
        select(SnmpSample.id)
        .join(SnmpMetric, SnmpMetric.id == SnmpSample.metric_id)
        .where(SnmpMetric.target_id == target_id)
        .order_by(SnmpSample.collected_at.desc(), SnmpSample.id.desc())
        .offset(snmp_sample_limit(session))
    )
    session.execute(delete(SnmpSample).where(SnmpSample.id.in_(overflow_ids)))


class SnmpService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        settings: Settings,
        client: SnmpClient,
        network_semaphore: asyncio.Semaphore,
    ) -> None:
        self._session_factory = session_factory
        self._settings = settings
        self._client = client
        self._network_semaphore = network_semaphore

    def save_settings(self, session: Session, target_id: int, form: SnmpSettingsForm) -> SnmpConfig:
        target = session.get(MonitorTarget, target_id)
        if target is None:
            raise LookupError("Объект не найден")
        if not 1 <= form.port <= 65535:
            raise ValueError("SNMP-порт должен быть от 1 до 65535")
        if not 1 <= form.timeout_seconds <= 60:
            raise ValueError("Timeout SNMP должен быть от 1 до 60 секунд")
        if not 0 <= form.retries <= 10:
            raise ValueError("Retries SNMP должен быть от 0 до 10")
        if form.version not in SUPPORTED_SNMP_VERSIONS:
            raise ValueError("Поддерживаются только SNMP v1 и v2c")
        config = session.get(SnmpConfig, target_id)
        if config is None:
            config = SnmpConfig(target_id=target_id)
            session.add(config)
        config.enabled = form.enabled
        config.version = form.version
        config.port = form.port
        config.timeout_seconds = form.timeout_seconds
        config.retries = form.retries
        config.ups_enabled = form.ups_enabled
        if form.community:
            if len(form.community) > 256:
                raise ValueError("Community SNMP не должен превышать 256 символов")
            config.community_encrypted = encrypt_secret(self._settings, form.community)
        elif form.enabled and not config.community_encrypted:
            raise ValueError("Укажите community для включения SNMP")
        return config

    def add_metric(self, session: Session, target_id: int, form: SnmpMetricForm) -> SnmpMetric:
        return self._save_metric(session, target_id, form)

    def update_metric(self, session: Session, metric_id: int, form: SnmpMetricForm) -> SnmpMetric:
        metric = session.get(SnmpMetric, metric_id)
        if metric is None:
            raise LookupError("SNMP-метрика не найдена")
        return self._save_metric(session, metric.target_id, form, metric=metric)

    def _save_metric(
        self,
        session: Session,
        target_id: int,
        form: SnmpMetricForm,
        *,
        metric: SnmpMetric | None = None,
    ) -> SnmpMetric:
        if session.get(MonitorTarget, target_id) is None:
            raise LookupError("Объект не найден")
        name = form.name.strip()
        unit = form.unit.strip()
        if not name or len(name) > 160:
            raise ValueError("Название метрики должно содержать от 1 до 160 символов")
        if len(unit) > 80:
            raise ValueError("Единица измерения не должна превышать 80 символов")
        source_kind = form.source_kind.strip().lower() or "oid"
        if source_kind not in {"oid", "formula"}:
            raise ValueError("Источник метрики должен быть OID или формулой")
        oid: str | None = None
        formula: str | None = None
        if source_kind == "oid":
            oid = canonical_oid(form.oid)
            duplicate = session.scalar(
                select(SnmpMetric.id).where(
                    SnmpMetric.target_id == target_id,
                    SnmpMetric.oid == oid,
                    SnmpMetric.id != (metric.id if metric is not None else 0),
                )
            )
            if duplicate is not None:
                raise ValueError("Этот OID уже добавлен для объекта")
        else:
            try:
                formula = compile_snmp_formula(form.formula).expression
            except FormulaError as exc:
                raise ValueError(str(exc)) from exc
        if metric is None:
            count = (
                session.scalar(
                    select(func.count(SnmpMetric.id)).where(SnmpMetric.target_id == target_id)
                )
                or 0
            )
            if count >= MAX_MANUAL_OIDS_PER_TARGET:
                raise ValueError(f"Можно добавить не более {MAX_MANUAL_OIDS_PER_TARGET} OID")
            metric = SnmpMetric(
                target_id=target_id,
                oid=oid,
                source_kind=source_kind,
                formula=formula,
                name=name,
                unit=unit or None,
                display_order=count + 1,
            )
            session.add(metric)
        else:
            metric.oid = oid
            metric.source_kind = source_kind
            metric.formula = formula
            metric.name = name
            metric.unit = unit or None
        metric.enabled = form.enabled
        return metric

    async def poll_target(self, target_id: int) -> list[IncidentNotification]:
        try:
            poll_request = await asyncio.to_thread(self._load_poll_request, target_id)
        except RuntimeError as exc:
            await asyncio.to_thread(self._save_transport_error, target_id, str(exc))
            return []
        if poll_request is None:
            return []
        try:
            values = await self._get_values(
                poll_request.request, self._requested_oids(poll_request)
            )
        except SnmpClientError as exc:
            await asyncio.to_thread(self._save_transport_error, target_id, str(exc))
            return []
        return await asyncio.to_thread(self._save_poll_values, target_id, poll_request, values)

    async def test_target(self, target_id: int) -> SnmpTestResult:
        try:
            poll_request = await asyncio.to_thread(self._load_poll_request, target_id)
        except RuntimeError as exc:
            return SnmpTestResult("error", str(exc), {})
        if poll_request is None:
            return SnmpTestResult("disabled", "SNMP для объекта не включён", {})
        try:
            values = await self._get_values(poll_request.request, tuple(SYSTEM_OIDS.values()))
        except SnmpClientError as exc:
            return SnmpTestResult("error", str(exc), {})
        system = self._system_values(values)
        if not system:
            return SnmpTestResult("error", "System OID не вернули данных", {})
        return SnmpTestResult("ok", "SNMP доступен", system)

    async def discover_target(
        self,
        target_id: int,
        roots: Sequence[str],
        *,
        max_results: int = MAX_DISCOVERY_RESULTS,
    ) -> SnmpDiscoveryResult:
        started = time.monotonic()
        try:
            poll_request = await asyncio.to_thread(self._load_poll_request, target_id)
        except RuntimeError as exc:
            return SnmpDiscoveryResult("error", str(exc), (), tuple(roots))
        if poll_request is None:
            return SnmpDiscoveryResult("disabled", "SNMP для объекта не включён", (), tuple(roots))

        normalized_roots = tuple(canonical_oid(root) for root in roots)
        discovered: dict[str, SnmpVarBind] = {}
        truncated = False
        partial_error: str | None = None
        try:
            async with asyncio.timeout(DISCOVERY_MAX_SECONDS):
                async with self._network_semaphore:
                    for root in normalized_roots:
                        if len(discovered) >= max_results:
                            truncated = True
                            break
                        walk = await self._client.walk(
                            poll_request.request, root, max_results=max_results
                        )
                        for item in walk.items:
                            oid = canonical_oid(item.oid)
                            discovered.setdefault(oid, item)
                            if len(discovered) >= max_results:
                                truncated = True
                                break
                        truncated = truncated or walk.truncated
                        if truncated:
                            break
        except TimeoutError:
            truncated = True
            partial_error = (
                f"Сканирование остановлено по лимиту времени {DISCOVERY_MAX_SECONDS} сек."
            )
        except SnmpClientError as exc:
            if not discovered:
                return SnmpDiscoveryResult(
                    "error",
                    str(exc),
                    (),
                    normalized_roots,
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                )
            partial_error = str(exc)

        items = tuple(
            SnmpDiscoveryItem(
                oid=oid,
                name=standard_oid_name(oid),
                value=(
                    item.value
                    if item.value is None or len(item.value) <= DISCOVERY_MAX_VALUE_CHARS
                    else f"{item.value[:DISCOVERY_MAX_VALUE_CHARS]}…"
                ),
                detected_type=item.detected_type,
                error=item.error,
                is_system=is_system_oid(oid),
            )
            for oid, item in sorted(discovered.items(), key=lambda pair: _oid_sort_key(pair[0]))
        )
        elapsed_ms = int((time.monotonic() - started) * 1000)
        if partial_error:
            message = f"Discovery завершён частично: {partial_error}"
            status = "partial"
        elif truncated:
            message = (
                f"Сканирование остановлено после {len(items)} OID. "
                "Уточните ветку для более точного поиска."
            )
            status = "ok"
        else:
            message = f"Найдено OID: {len(items)}"
            status = "ok"
        return SnmpDiscoveryResult(
            status, message, items, normalized_roots, truncated=truncated, elapsed_ms=elapsed_ms
        )

    async def discover_supplies_target(self, target_id: int) -> SnmpSuppliesResult:
        started = time.monotonic()
        try:
            poll_request = await asyncio.to_thread(self._load_poll_request, target_id)
        except RuntimeError as exc:
            return SnmpSuppliesResult("error", str(exc), ())
        if poll_request is None:
            return SnmpSuppliesResult("disabled", "SNMP для объекта не включён", ())

        discovered: list[SnmpVarBind] = []
        truncated = False
        try:
            async with asyncio.timeout(PRINTER_SUPPLIES_DISCOVERY_MAX_SECONDS):
                async with self._network_semaphore:
                    for root_oid in PRINTER_SUPPLIES_COLUMNS.values():
                        walk = await self._client.walk(
                            poll_request.request,
                            root_oid,
                            max_results=MAX_PRINTER_SUPPLIES,
                        )
                        discovered.extend(walk.items)
                        truncated = truncated or walk.truncated
        except TimeoutError:
            return SnmpSuppliesResult(
                "error",
                "Поиск расходников остановлен по лимиту времени "
                f"{PRINTER_SUPPLIES_DISCOVERY_MAX_SECONDS} сек.",
                (),
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )
        except SnmpClientError as exc:
            return SnmpSuppliesResult(
                "error",
                str(exc),
                (),
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )

        snapshots = build_supply_snapshots(tuple(discovered))
        if not snapshots:
            return SnmpSuppliesResult(
                "error",
                "Printer-MIB не вернул расходников",
                (),
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )
        await asyncio.to_thread(self._save_supply_inventory, target_id, snapshots)
        message = f"Обнаружено расходников: {len(snapshots)}"
        if truncated:
            message += f". Достигнут лимит {MAX_PRINTER_SUPPLIES} позиций."
        return SnmpSuppliesResult(
            "ok",
            message,
            snapshots,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            truncated=truncated,
        )

    def _save_supply_inventory(
        self, target_id: int, snapshots: tuple[SnmpSupplySnapshot, ...]
    ) -> None:
        now = datetime.now(UTC)
        with self._session_factory() as session:
            existing = {
                (item.hr_device_index, item.supply_index): item
                for item in session.scalars(
                    select(SnmpSupply).where(SnmpSupply.target_id == target_id)
                ).all()
            }
            for item in existing.values():
                item.present = False
            for snapshot in snapshots:
                key = (snapshot.hr_device_index, snapshot.supply_index)
                item = existing.get(key)
                if item is None:
                    item = SnmpSupply(
                        target_id=target_id,
                        hr_device_index=snapshot.hr_device_index,
                        supply_index=snapshot.supply_index,
                        first_seen_at=now,
                    )
                    session.add(item)
                else:
                    old_identity = (
                        (item.description or "").strip(),
                        item.supply_type,
                        item.supply_class,
                    )
                    new_identity = (
                        (snapshot.description or "").strip(),
                        snapshot.supply_type,
                        snapshot.supply_class,
                    )
                    if (
                        any(value not in {None, ""} for value in old_identity)
                        and old_identity != new_identity
                    ):
                        SnmpThresholdService().reset_for_supply(
                            session,
                            item.id,
                            message="Идентификатор расходника Printer-MIB изменился",
                            disable=True,
                        )
                item.marker_index = snapshot.marker_index
                item.colorant_index = snapshot.colorant_index
                item.supply_class = snapshot.supply_class
                item.supply_type = snapshot.supply_type
                item.description = snapshot.description
                item.unit_code = snapshot.unit_code
                item.max_capacity = snapshot.max_capacity
                item.level = snapshot.level
                item.percent_remaining = snapshot.percent_remaining
                item.level_state = snapshot.level_state
                item.present = True
                item.last_seen_at = now
                item.last_polled_at = now
                item.last_error = None
            session.commit()

    async def discover_interfaces_target(self, target_id: int) -> SnmpInterfacesResult:
        started = time.monotonic()
        try:
            poll_request = await asyncio.to_thread(self._load_poll_request, target_id)
        except RuntimeError as exc:
            return SnmpInterfacesResult("error", str(exc), ())
        if poll_request is None:
            return SnmpInterfacesResult("disabled", "SNMP для объекта не включён", ())

        columns: dict[str, tuple[SnmpVarBind, ...]] = {}
        truncated = False
        try:
            async with asyncio.timeout(INTERFACE_DISCOVERY_MAX_SECONDS):
                async with self._network_semaphore:
                    for key, root_oid in IF_COLUMNS.items():
                        walk = await self._client.walk(
                            poll_request.request, root_oid, max_results=MAX_SNMP_INTERFACES
                        )
                        columns[key] = walk.items
                        truncated = truncated or walk.truncated
        except TimeoutError:
            return SnmpInterfacesResult(
                "error",
                f"Обнаружение интерфейсов остановлено по лимиту времени {INTERFACE_DISCOVERY_MAX_SECONDS} сек.",
                (),
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )
        except SnmpClientError as exc:
            return SnmpInterfacesResult(
                "error", str(exc), (), elapsed_ms=int((time.monotonic() - started) * 1000)
            )

        snapshots = build_interface_snapshots(columns)
        if len(snapshots) > MAX_SNMP_INTERFACES:
            snapshots = snapshots[:MAX_SNMP_INTERFACES]
            truncated = True
        if not snapshots:
            return SnmpInterfacesResult(
                "error",
                "IF-MIB не вернул интерфейсов",
                (),
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )
        await asyncio.to_thread(self._save_interface_inventory, target_id, snapshots)
        message = f"Обнаружено интерфейсов: {len(snapshots)}"
        if truncated:
            message += f". Достигнут лимит {MAX_SNMP_INTERFACES} интерфейсов."
        return SnmpInterfacesResult(
            "ok",
            message,
            snapshots,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            truncated=truncated,
        )

    def _save_interface_inventory(
        self, target_id: int, snapshots: tuple[SnmpInterfaceSnapshot, ...]
    ) -> None:
        now = datetime.now(UTC)
        with self._session_factory() as session:
            existing = {
                item.if_index: item
                for item in session.scalars(
                    select(SnmpInterface).where(SnmpInterface.target_id == target_id)
                ).all()
            }
            for item in existing.values():
                item.present = False
            for snapshot in snapshots:
                item = existing.get(snapshot.if_index)
                if item is None:
                    item = SnmpInterface(
                        target_id=target_id,
                        if_index=snapshot.if_index,
                        first_seen_at=now,
                    )
                    session.add(item)
                else:
                    old_identity = (item.if_name or item.if_descr or "").strip()
                    new_identity = (snapshot.if_name or snapshot.if_descr or "").strip()
                    if old_identity and new_identity and old_identity != new_identity:
                        SnmpThresholdService().reset_for_interface(
                            session,
                            item.id,
                            message="Идентификатор SNMP-интерфейса изменился",
                            disable=True,
                        )
                        item.monitor_enabled = False
                        self._clear_interface_traffic_runtime(item)
                        session.execute(
                            delete(SnmpInterfaceSample).where(
                                SnmpInterfaceSample.interface_id == item.id
                            )
                        )
                item.if_name = snapshot.if_name
                item.if_descr = snapshot.if_descr
                item.if_alias = snapshot.if_alias
                item.if_type = snapshot.if_type
                item.if_mtu = snapshot.if_mtu
                item.speed_bps = snapshot.speed_bps
                item.phys_address = snapshot.phys_address
                item.admin_status = snapshot.admin_status
                item.oper_status = snapshot.oper_status
                item.present = True
                item.last_seen_at = now
                item.last_polled_at = now
                item.last_error = None
            seen_indexes = {snapshot.if_index for snapshot in snapshots}
            for if_index, item in existing.items():
                if if_index not in seen_indexes:
                    self._clear_interface_traffic_runtime(item)
            session.commit()

    @staticmethod
    def _clear_interface_traffic_runtime(
        interface: SnmpInterface, *, clear_stats: bool = True
    ) -> None:
        interface.traffic_counter_mode = None
        interface.in_octets = None
        interface.out_octets = None
        interface.traffic_at = None
        interface.traffic_uptime_ticks = None
        interface.rx_bps = None
        interface.tx_bps = None
        interface.traffic_error = None
        if clear_stats:
            interface.in_errors = None
            interface.out_errors = None
            interface.in_discards = None
            interface.out_discards = None

    async def _get_values(
        self, request: SnmpRequest, oids: Sequence[str]
    ) -> dict[str, SnmpVarBind]:
        values: dict[str, SnmpVarBind] = {}
        async with self._network_semaphore:
            for position in range(0, len(oids), SNMP_GET_CHUNK_SIZE):
                response = await self._client.get(
                    request, oids[position : position + SNMP_GET_CHUNK_SIZE]
                )
                values.update({canonical_oid(item.oid): item for item in response})
        return values

    @staticmethod
    def _requested_oids(poll_request: _PollRequest) -> tuple[str, ...]:
        interface_oids = tuple(
            oid
            for _interface_id, if_index, counter_mode in poll_request.interface_ids
            for oid in (
                status_oid(IF_ADMIN_STATUS_BASE, if_index),
                status_oid(IF_OPER_STATUS_BASE, if_index),
                *traffic_poll_oids(
                    if_index,
                    counter_mode,
                    supports_counter64=poll_request.request.version != "v1",
                ),
            )
        )
        supply_oids = tuple(
            oid
            for _supply_id, hr_device_index, supply_index in poll_request.supply_ids
            for oid in supply_poll_oids(hr_device_index, supply_index)
        )
        requested = (
            tuple(SYSTEM_OIDS.values())
            + tuple(metric.oid for metric in poll_request.metrics if metric.oid is not None)
            + tuple(
                oid
                for metric in poll_request.metrics
                if metric.formula is not None
                for oid in metric.formula.source_oids
            )
            + interface_oids
            + supply_oids
            + (ups_poll_oids() if poll_request.ups_enabled else ())
        )
        return tuple(dict.fromkeys(requested))

    def _load_poll_request(self, target_id: int) -> _PollRequest | None:
        with self._session_factory() as session:
            target = session.get(MonitorTarget, target_id)
            config = session.get(SnmpConfig, target_id)
            if target is None or config is None or not config.enabled:
                return None
            community = decrypt_secret(
                self._settings, config.community_encrypted, label="Community SNMP"
            )
            if not community:
                return None
            metrics = session.execute(
                select(
                    SnmpMetric.id,
                    SnmpMetric.oid,
                    SnmpMetric.source_kind,
                    SnmpMetric.formula,
                )
                .where(SnmpMetric.target_id == target_id, SnmpMetric.enabled.is_(True))
                .order_by(SnmpMetric.id)
            ).all()
            interfaces = session.execute(
                select(
                    SnmpInterface.id,
                    SnmpInterface.if_index,
                    SnmpInterface.traffic_counter_mode,
                )
                .where(
                    SnmpInterface.target_id == target_id,
                    SnmpInterface.monitor_enabled.is_(True),
                    SnmpInterface.present.is_(True),
                )
                .order_by(SnmpInterface.if_index)
            ).all()
            supplies = session.execute(
                select(
                    SnmpSupply.id,
                    SnmpSupply.hr_device_index,
                    SnmpSupply.supply_index,
                )
                .where(
                    SnmpSupply.target_id == target_id,
                    SnmpSupply.present.is_(True),
                )
                .order_by(SnmpSupply.hr_device_index, SnmpSupply.supply_index)
            ).all()
            return _PollRequest(
                target_id=target_id,
                request=SnmpRequest(
                    address=target.address,
                    port=config.port,
                    community=community,
                    timeout_seconds=config.timeout_seconds,
                    retries=config.retries,
                    version=config.version,
                ),
                metrics=tuple(
                    _MetricPoll(
                        id=int(metric_id),
                        oid=str(oid) if source_kind == "oid" and oid else None,
                        formula=(
                            compile_snmp_formula(str(formula))
                            if source_kind == "formula" and formula
                            else None
                        ),
                    )
                    for metric_id, oid, source_kind, formula in metrics
                ),
                interface_ids=tuple(
                    (
                        int(interface_id),
                        int(if_index),
                        str(counter_mode) if counter_mode else None,
                    )
                    for interface_id, if_index, counter_mode in interfaces
                ),
                supply_ids=tuple(
                    (int(supply_id), int(hr_device_index), int(supply_index))
                    for supply_id, hr_device_index, supply_index in supplies
                ),
                ups_enabled=config.ups_enabled,
            )

    @staticmethod
    def _system_values(values: dict[str, SnmpVarBind]) -> dict[str, str]:
        result: dict[str, str] = {}
        for field, oid in SYSTEM_OIDS.items():
            item = values.get(oid)
            if item is not None and item.value is not None and item.error is None:
                result[field] = item.value
        return result

    def _save_transport_error(self, target_id: int, error: str) -> None:
        with self._session_factory() as session:
            config = session.get(SnmpConfig, target_id)
            if config is None or not config.enabled:
                return
            config.last_status = SnmpStatus.ERROR
            config.last_attempt_at = datetime.now(UTC)
            config.last_error = _safe_error(error)
            session.commit()

    def _save_poll_values(
        self,
        target_id: int,
        poll_request: _PollRequest,
        values: dict[str, SnmpVarBind],
    ) -> list[IncidentNotification]:
        now = datetime.now(UTC)
        with self._session_factory() as session:
            config = session.get(SnmpConfig, target_id)
            if config is None or not config.enabled:
                # SNMP may be disabled while an in-flight request is completing.
                # The scheduler always expects an iterable notification result.
                return []
            system = self._system_values(values)
            config.last_attempt_at = now
            if not system:
                config.last_status = SnmpStatus.ERROR
                config.last_error = "System OID не вернули данных"
                session.commit()
                return []
            config.last_status = SnmpStatus.OK
            config.last_success_at = now
            config.last_error = None
            config.system_data_at = now
            if "sys_name" in system:
                config.sys_name = system["sys_name"]
            if "sys_descr" in system:
                config.sys_descr = system["sys_descr"]
            if "sys_object_id" in system:
                config.sys_object_id = system["sys_object_id"]
            uptime = values.get(SYSTEM_OIDS["sys_uptime_ticks"])
            uptime_number = _numeric_value(uptime) if uptime is not None else None
            if uptime_number is not None:
                config.sys_uptime_ticks = int(uptime_number)
            metrics = {
                metric.id: metric
                for metric in session.scalars(
                    select(SnmpMetric).where(SnmpMetric.target_id == target_id)
                ).all()
            }
            numeric_values = {
                oid: number
                for oid, item in values.items()
                if not item.error and (number := _numeric_value(item)) is not None
            }
            for requested_metric in poll_request.metrics:
                metric = metrics.get(requested_metric.id)
                if metric is None:
                    continue
                if requested_metric.formula is not None:
                    try:
                        number = requested_metric.formula.evaluate(numeric_values)
                    except FormulaError as exc:
                        metric.detected_type = "Formula"
                        metric.last_error = _safe_error(str(exc))
                        continue
                    metric.detected_type = "Formula"
                    metric.last_error = None
                    metric.last_numeric_value = number
                    metric.last_value = _format_numeric_value(number)
                    metric.last_collected_at = now
                    session.add(SnmpSample(metric_id=metric.id, collected_at=now, value=number))
                    continue
                if requested_metric.oid is None:
                    metric.last_error = "Источник метрики не настроен"
                    continue
                item = values.get(requested_metric.oid)
                if item is None:
                    metric.last_error = "OID не вернул данные"
                    continue
                metric.detected_type = item.detected_type
                if item.error:
                    metric.last_error = _safe_error(item.error)
                    continue
                metric.last_error = None
                metric.last_value = item.value
                metric.last_collected_at = now
                number = _numeric_value(item)
                metric.last_numeric_value = number
                if number is not None:
                    session.add(SnmpSample(metric_id=metric.id, collected_at=now, value=number))
            supplies = {
                item.id: item
                for item in session.scalars(
                    select(SnmpSupply).where(SnmpSupply.target_id == target_id)
                ).all()
            }
            for supply_id, hr_device_index, supply_index in poll_request.supply_ids:
                supply = supplies.get(supply_id)
                if supply is None:
                    continue
                level_item = values.get(supply_oid("level", hr_device_index, supply_index))
                max_item = values.get(supply_oid("max_capacity", hr_device_index, supply_index))
                if level_item is None:
                    supply.last_polled_at = now
                    supply.last_error = "OID уровня расходника не вернул данные"
                    supply.percent_remaining = None
                    supply.level_state = "error"
                    continue
                if level_item.error:
                    supply.last_polled_at = now
                    supply.last_error = _safe_error(level_item.error)
                    supply.percent_remaining = None
                    supply.level_state = "error"
                    continue
                level_number = _numeric_value(level_item)
                if level_number is None:
                    supply.last_polled_at = now
                    supply.last_error = "Уровень расходника не является целым числом"
                    supply.percent_remaining = None
                    supply.level_state = "error"
                    continue
                supply.level = int(level_number)
                if max_item is not None and not max_item.error:
                    max_number = _numeric_value(max_item)
                    if max_number is not None:
                        supply.max_capacity = int(max_number)
                percent_remaining, level_state = normalize_supply_level(
                    supply_class=supply.supply_class,
                    unit_code=supply.unit_code,
                    max_capacity=supply.max_capacity,
                    level=supply.level,
                )
                supply.percent_remaining = percent_remaining
                supply.level_state = level_state
                supply.last_polled_at = now
                supply.last_error = None

            ups_events: list[IncidentNotification] = []
            if poll_request.ups_enabled:
                target = session.get(MonitorTarget, target_id)
                if target is not None:
                    ups_events = SnmpUpsService().save_poll(
                        session, target, values, observed_at=now
                    )

            interfaces = {
                item.id: item
                for item in session.scalars(
                    select(SnmpInterface).where(SnmpInterface.target_id == target_id)
                ).all()
            }
            uptime_item = values.get(SYSTEM_OIDS["sys_uptime_ticks"])
            uptime_value = _numeric_value(uptime_item) if uptime_item is not None else None
            current_uptime = int(uptime_value) if uptime_value is not None else None
            for interface_id, if_index, counter_mode in poll_request.interface_ids:
                interface = interfaces.get(interface_id)
                if interface is None:
                    continue
                admin_item = values.get(status_oid(IF_ADMIN_STATUS_BASE, if_index))
                oper_item = values.get(status_oid(IF_OPER_STATUS_BASE, if_index))
                errors = [
                    item.error
                    for item in (admin_item, oper_item)
                    if item is not None and item.error
                ]
                if admin_item is None or oper_item is None:
                    interface.last_error = "OID состояния интерфейса не вернули данные"
                    continue
                if errors:
                    interface.last_error = _safe_error(errors[0] or "Ошибка OID интерфейса")
                    continue
                admin_value = _numeric_value(admin_item)
                oper_value = _numeric_value(oper_item)
                interface.admin_status = int(admin_value) if admin_value is not None else None
                interface.oper_status = int(oper_value) if oper_value is not None else None
                interface.last_polled_at = now
                interface.last_error = None
                traffic = build_traffic_snapshot(values, if_index, counter_mode)
                interface.in_errors = traffic.in_errors
                interface.out_errors = traffic.out_errors
                interface.in_discards = traffic.in_discards
                interface.out_discards = traffic.out_discards
                if (
                    traffic.error
                    or traffic.counter_mode is None
                    or traffic.in_octets is None
                    or traffic.out_octets is None
                ):
                    self._clear_interface_traffic_runtime(interface, clear_stats=False)
                    interface.traffic_error = _safe_error(
                        traffic.error or "Ошибка счётчиков трафика интерфейса"
                    )
                    continue

                mode_changed = (
                    interface.traffic_counter_mode is not None
                    and interface.traffic_counter_mode != traffic.counter_mode
                )
                previous_in = int(interface.in_octets) if interface.in_octets is not None else None
                previous_out = (
                    int(interface.out_octets) if interface.out_octets is not None else None
                )
                previous_at = interface.traffic_at
                previous_uptime = interface.traffic_uptime_ticks
                rebooted = (
                    current_uptime is not None
                    and previous_uptime is not None
                    and current_uptime < previous_uptime
                )
                rx_bps = tx_bps = None
                if (
                    not mode_changed
                    and not rebooted
                    and previous_in is not None
                    and previous_out is not None
                    and previous_at is not None
                ):
                    if current_uptime is not None and previous_uptime is not None:
                        elapsed_seconds = (current_uptime - previous_uptime) / 100
                    else:
                        normalized_previous_at = (
                            previous_at
                            if previous_at.tzinfo is not None
                            else previous_at.replace(tzinfo=UTC)
                        )
                        elapsed_seconds = (now - normalized_previous_at).total_seconds()
                    rx_bps = counter_rate_bps(
                        traffic.in_octets,
                        previous_in,
                        elapsed_seconds,
                        counter_mode=traffic.counter_mode,
                        interface_speed_bps=interface.speed_bps,
                    )
                    tx_bps = counter_rate_bps(
                        traffic.out_octets,
                        previous_out,
                        elapsed_seconds,
                        counter_mode=traffic.counter_mode,
                        interface_speed_bps=interface.speed_bps,
                    )
                    if rx_bps is None or tx_bps is None:
                        rx_bps = tx_bps = None

                interface.traffic_counter_mode = traffic.counter_mode
                interface.in_octets = str(traffic.in_octets)
                interface.out_octets = str(traffic.out_octets)
                interface.traffic_at = now
                interface.traffic_uptime_ticks = current_uptime
                interface.rx_bps = rx_bps
                interface.tx_bps = tx_bps
                interface.traffic_error = None
                session.add(
                    SnmpInterfaceSample(
                        interface_id=interface.id,
                        collected_at=now,
                        rx_bps=rx_bps,
                        tx_bps=tx_bps,
                        in_errors=traffic.in_errors,
                        out_errors=traffic.out_errors,
                        in_discards=traffic.in_discards,
                        out_discards=traffic.out_discards,
                    )
                )
            self._trim_samples(session, target_id)
            if poll_request.ups_enabled:
                SnmpUpsService.trim_samples(session, target_id, snmp_sample_limit(session))
            threshold_events = SnmpThresholdService().evaluate_target(
                session,
                target_id,
                observed_at=now,
            )
            session.commit()
            return threshold_events + ups_events

    @staticmethod
    def _trim_samples(session: Session, target_id: int) -> None:
        """Keep the newest numeric SNMP history within the object-level limit."""
        trim_snmp_samples_for_target(session, target_id)

    def clear_data(self, session: Session, target_id: int) -> None:
        config = session.get(SnmpConfig, target_id)
        if config is None:
            return
        SnmpThresholdService().reset_target(
            session,
            target_id,
            message="SNMP-данные очищены администратором",
        )
        metric_ids = select(SnmpMetric.id).where(SnmpMetric.target_id == target_id)
        session.execute(delete(SnmpSample).where(SnmpSample.metric_id.in_(metric_ids)))
        interface_ids = select(SnmpInterface.id).where(SnmpInterface.target_id == target_id)
        session.execute(
            delete(SnmpInterfaceSample).where(SnmpInterfaceSample.interface_id.in_(interface_ids))
        )
        metrics = session.scalars(select(SnmpMetric).where(SnmpMetric.target_id == target_id)).all()
        for metric in metrics:
            metric.detected_type = None
            metric.last_value = None
            metric.last_numeric_value = None
            metric.last_collected_at = None
            metric.last_error = None
        config.last_status = SnmpStatus.NEVER
        config.last_attempt_at = None
        config.last_success_at = None
        config.last_error = None
        config.sys_name = None
        config.sys_descr = None
        config.sys_object_id = None
        config.sys_uptime_ticks = None
        config.system_data_at = None
        supplies = session.scalars(
            select(SnmpSupply).where(SnmpSupply.target_id == target_id)
        ).all()
        for supply in supplies:
            supply.max_capacity = None
            supply.level = None
            supply.percent_remaining = None
            supply.level_state = "never"
            supply.last_polled_at = None
            supply.last_error = None
        SnmpUpsService.clear_data(session, target_id)

        interfaces = session.scalars(
            select(SnmpInterface).where(SnmpInterface.target_id == target_id)
        ).all()
        for interface in interfaces:
            interface.admin_status = None
            interface.oper_status = None
            interface.last_polled_at = None
            interface.last_error = None
            self._clear_interface_traffic_runtime(interface)
