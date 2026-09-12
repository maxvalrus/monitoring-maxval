import os
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Lock

from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from monitoring.models import (
    AppSetting,
    MonitorTarget,
    PortalMetric,
    Site,
    SnmpConfig,
    SnmpInterface,
    SnmpMetric,
    SnmpStatus,
    SnmpSupply,
)
from monitoring.services.scheduler_metrics import SchedulerHealthSnapshot

_cpu_lock = Lock()
_last_cpu_sample: tuple[int, int] | None = None


@dataclass(frozen=True, slots=True)
class PortalWorkload:
    active_targets: int
    snmp_targets: int
    snmp_errors: int
    snmp_metrics: int
    snmp_interfaces: int
    snmp_supplies: int
    snmp_error_details: tuple["SnmpErrorDetail", ...]
    database_size_bytes: int | None
    database_connections: int | None
    database_max_connections: int | None


@dataclass(frozen=True, slots=True)
class PortalHealth:
    level: str
    label: str
    detail: str


@dataclass(frozen=True, slots=True)
class SnmpErrorDetail:
    target_id: int
    target_name: str
    error: str


@dataclass(frozen=True, slots=True)
class PortalDashboard:
    current: PortalMetric
    collected_at: datetime
    receive_rate: float
    send_rate: float
    packet_receive_rate: float
    packet_send_rate: float
    cpu_points: str
    memory_points: str
    disk_points: str
    network_points: str
    cpu_chart: "ChartData"
    memory_chart: "ChartData"
    disk_chart: "ChartData"
    network_chart: "ChartData"
    memory_used_bytes: int
    memory_total_bytes: int
    disk_used_bytes: int
    disk_total_bytes: int
    scheduler: SchedulerHealthSnapshot | None
    workload: PortalWorkload
    health: PortalHealth


@dataclass(frozen=True, slots=True)
class ChartData:
    points: str
    values: tuple[float, ...]
    timestamps: tuple[str, ...]
    scale_max: float


def chart_scale_max(values: list[float], *, ceiling: float | None = None) -> float:
    if ceiling is not None:
        return max(float(ceiling), 1.0)
    maximum = max((max(0.0, float(value)) for value in values), default=0.0)
    if maximum <= 1.0:
        return 1.0
    magnitude = 10 ** int(len(str(int(maximum))) - 1)
    for multiplier in (1, 2, 5, 10):
        candidate = multiplier * magnitude
        if candidate >= maximum:
            return float(candidate)
    return float(10 * magnitude)


def collect_system_metric() -> PortalMetric:
    _, _, memory_percent = _memory_usage()
    disk = shutil.disk_usage("/")
    network = _network_totals()
    now = datetime.now(UTC)
    return PortalMetric(
        cpu_percent=_cpu_percent(),
        memory_percent=memory_percent,
        disk_percent=round((disk.used / disk.total * 100) if disk.total else 0.0, 1),
        uptime_seconds=_uptime_seconds(),
        bytes_sent=network[0],
        bytes_received=network[1],
        packets_sent=network[2],
        packets_received=network[3],
        collected_at=now,
    )


def _cpu_percent() -> float:
    global _last_cpu_sample
    try:
        fields = Path("/proc/stat").read_text(encoding="utf-8").splitlines()[0].split()[1:]
        values = [int(value) for value in fields]
        total = sum(values)
        idle = values[3] + (values[4] if len(values) > 4 else 0)
    except (OSError, ValueError, IndexError):
        cores = max(1, os.cpu_count() or 1)
        return round(min(100.0, os.getloadavg()[0] / cores * 100), 1)
    with _cpu_lock:
        previous = _last_cpu_sample
        _last_cpu_sample = (total, idle)
    if previous is None or total <= previous[0]:
        cores = max(1, os.cpu_count() or 1)
        return round(min(100.0, os.getloadavg()[0] / cores * 100), 1)
    total_delta = total - previous[0]
    idle_delta = idle - previous[1]
    return round(max(0.0, min(100.0, (total_delta - idle_delta) * 100 / total_delta)), 1)


def _memory_usage() -> tuple[int, int, float]:
    try:
        values = {}
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, raw = line.split(":", 1)
            values[key] = int(raw.strip().split()[0])
        total_kib = values["MemTotal"]
        available_kib = values.get("MemAvailable", values.get("MemFree", 0))
        used_kib = max(0, total_kib - available_kib)
        percent = round(used_kib * 100 / total_kib, 1) if total_kib else 0.0
        return used_kib * 1024, total_kib * 1024, percent
    except (OSError, ValueError, KeyError):
        return 0, 0, 0.0


def _uptime_seconds() -> int:
    try:
        return max(0, int(float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0])))
    except (OSError, ValueError, IndexError):
        return 0


def _network_totals() -> tuple[int, int, int, int]:
    sent = received = packets_sent = packets_received = 0
    try:
        lines = Path("/proc/net/dev").read_text(encoding="utf-8").splitlines()[2:]
        for line in lines:
            interface, raw = line.split(":", 1)
            if interface.strip() == "lo":
                continue
            fields = raw.split()
            received += int(fields[0])
            packets_received += int(fields[1])
            sent += int(fields[8])
            packets_sent += int(fields[9])
    except (OSError, ValueError, IndexError):
        return 0, 0, 0, 0
    return sent, received, packets_sent, packets_received


def save_system_metric(session: Session) -> PortalMetric:
    metric = collect_system_metric()
    session.add(metric)
    session.commit()
    return metric


def metric_interval_seconds(session: Session) -> int:
    setting = session.get(AppSetting, "portal_metric_interval_seconds")
    try:
        value = int(setting.value) if setting is not None else 60
    except ValueError:
        value = 60
    return max(60, min(3600, value))


def cleanup_portal_metrics(session: Session, *, now: datetime | None = None) -> int:
    setting = session.get(AppSetting, "portal_metric_retention_hours")
    try:
        hours = int(setting.value) if setting is not None else 168
    except ValueError:
        hours = 168
    hours = max(24, min(8760, hours))
    threshold = (now or datetime.now(UTC)) - timedelta(hours=hours)
    result = session.execute(
        delete(PortalMetric)
        .where(PortalMetric.collected_at < threshold)
        .execution_options(synchronize_session=False)
    )
    session.commit()
    return result.rowcount or 0


def portal_dashboard(
    session: Session,
    *,
    hours: int = 24,
    scheduler: SchedulerHealthSnapshot | None = None,
) -> PortalDashboard:
    threshold = datetime.now(UTC) - timedelta(hours=max(1, min(168, hours)))
    history = list(
        reversed(
            session.scalars(
                select(PortalMetric)
                .where(PortalMetric.collected_at >= threshold)
                .order_by(PortalMetric.collected_at.desc(), PortalMetric.id.desc())
                .limit(120)
            ).all()
        )
    )
    if not history:
        current = collect_system_metric()
        history = [current]
    else:
        current = history[-1]

    receive_rate = send_rate = packet_receive_rate = packet_send_rate = 0.0
    if len(history) >= 2:
        previous = history[-2]
        elapsed = max(1.0, (current.collected_at - previous.collected_at).total_seconds())
        receive_rate = max(0.0, (current.bytes_received - previous.bytes_received) / elapsed)
        send_rate = max(0.0, (current.bytes_sent - previous.bytes_sent) / elapsed)
        packet_receive_rate = max(
            0.0, (current.packets_received - previous.packets_received) / elapsed
        )
        packet_send_rate = max(0.0, (current.packets_sent - previous.packets_sent) / elapsed)

    network_rates: list[float] = []
    for previous, item in zip(history, history[1:], strict=False):
        elapsed = max(1.0, (item.collected_at - previous.collected_at).total_seconds())
        network_rates.append(
            max(
                0.0,
                (
                    item.bytes_received
                    + item.bytes_sent
                    - previous.bytes_received
                    - previous.bytes_sent
                )
                / elapsed,
            )
        )
    if not network_rates:
        network_rates = [0.0]

    history_times = [item.collected_at for item in history]
    network_times = [item.collected_at for item in history[1:]] or [current.collected_at]
    cpu_chart = chart_data([item.cpu_percent for item in history], history_times, ceiling=100)
    memory_chart = chart_data([item.memory_percent for item in history], history_times, ceiling=100)
    disk_chart = chart_data([item.disk_percent for item in history], history_times, ceiling=100)
    network_chart = chart_data(network_rates, network_times)

    memory_used, memory_total, _ = _memory_usage()
    disk = shutil.disk_usage("/")
    workload = portal_workload(session)
    health = portal_health(current, scheduler, workload)

    return PortalDashboard(
        current=current,
        collected_at=current.collected_at,
        receive_rate=receive_rate,
        send_rate=send_rate,
        packet_receive_rate=packet_receive_rate,
        packet_send_rate=packet_send_rate,
        cpu_points=cpu_chart.points,
        memory_points=memory_chart.points,
        disk_points=disk_chart.points,
        network_points=network_chart.points,
        cpu_chart=cpu_chart,
        memory_chart=memory_chart,
        disk_chart=disk_chart,
        network_chart=network_chart,
        memory_used_bytes=memory_used,
        memory_total_bytes=memory_total,
        disk_used_bytes=disk.used,
        disk_total_bytes=disk.total,
        scheduler=scheduler,
        workload=workload,
        health=health,
    )


def portal_workload(session: Session) -> PortalWorkload:
    active_target_filter = (MonitorTarget.enabled.is_(True), Site.enabled.is_(True))
    active_targets = (
        select(func.count(MonitorTarget.id))
        .join(Site, Site.id == MonitorTarget.site_id)
        .where(*active_target_filter)
        .scalar_subquery()
    )
    snmp_targets = (
        select(func.count(SnmpConfig.target_id))
        .join(MonitorTarget, MonitorTarget.id == SnmpConfig.target_id)
        .join(Site, Site.id == MonitorTarget.site_id)
        .where(SnmpConfig.enabled.is_(True), *active_target_filter)
        .scalar_subquery()
    )
    snmp_errors = (
        select(func.count(SnmpConfig.target_id))
        .join(MonitorTarget, MonitorTarget.id == SnmpConfig.target_id)
        .join(Site, Site.id == MonitorTarget.site_id)
        .where(
            SnmpConfig.enabled.is_(True),
            SnmpConfig.last_status == SnmpStatus.ERROR.value,
            *active_target_filter,
        )
        .scalar_subquery()
    )
    snmp_metrics = (
        select(func.count(SnmpMetric.id))
        .join(MonitorTarget, MonitorTarget.id == SnmpMetric.target_id)
        .join(Site, Site.id == MonitorTarget.site_id)
        .join(SnmpConfig, SnmpConfig.target_id == MonitorTarget.id)
        .where(
            SnmpConfig.enabled.is_(True),
            SnmpMetric.enabled.is_(True),
            *active_target_filter,
        )
        .scalar_subquery()
    )
    snmp_interfaces = (
        select(func.count(SnmpInterface.id))
        .join(MonitorTarget, MonitorTarget.id == SnmpInterface.target_id)
        .join(Site, Site.id == MonitorTarget.site_id)
        .join(SnmpConfig, SnmpConfig.target_id == MonitorTarget.id)
        .where(
            SnmpConfig.enabled.is_(True),
            SnmpInterface.monitor_enabled.is_(True),
            SnmpInterface.present.is_(True),
            *active_target_filter,
        )
        .scalar_subquery()
    )
    snmp_supplies = (
        select(func.count(SnmpSupply.id))
        .join(MonitorTarget, MonitorTarget.id == SnmpSupply.target_id)
        .join(Site, Site.id == MonitorTarget.site_id)
        .join(SnmpConfig, SnmpConfig.target_id == MonitorTarget.id)
        .where(
            SnmpConfig.enabled.is_(True),
            SnmpSupply.present.is_(True),
            *active_target_filter,
        )
        .scalar_subquery()
    )
    row = session.execute(
        select(
            active_targets,
            snmp_targets,
            snmp_errors,
            snmp_metrics,
            snmp_interfaces,
            snmp_supplies,
        )
    ).one()
    snmp_error_details = tuple(
        SnmpErrorDetail(
            target_id=target_id,
            target_name=target_name,
            error=last_error or "SNMP polling завершился ошибкой",
        )
        for target_id, target_name, last_error in session.execute(
            select(MonitorTarget.id, MonitorTarget.name, SnmpConfig.last_error)
            .join(SnmpConfig, SnmpConfig.target_id == MonitorTarget.id)
            .join(Site, Site.id == MonitorTarget.site_id)
            .where(
                SnmpConfig.enabled.is_(True),
                SnmpConfig.last_status == SnmpStatus.ERROR.value,
                *active_target_filter,
            )
            .order_by(SnmpConfig.last_attempt_at.desc(), MonitorTarget.id)
            .limit(8)
        ).all()
    )
    database_size, database_connections, database_max_connections = _database_stats(session)
    return PortalWorkload(
        active_targets=int(row[0] or 0),
        snmp_targets=int(row[1] or 0),
        snmp_errors=int(row[2] or 0),
        snmp_metrics=int(row[3] or 0),
        snmp_interfaces=int(row[4] or 0),
        snmp_supplies=int(row[5] or 0),
        snmp_error_details=snmp_error_details,
        database_size_bytes=database_size,
        database_connections=database_connections,
        database_max_connections=database_max_connections,
    )


def _database_stats(session: Session) -> tuple[int | None, int | None, int | None]:
    bind = session.get_bind()
    if bind.dialect.name != "postgresql":
        return None, None, None
    try:
        row = session.execute(
            text(
                "SELECT pg_database_size(current_database()), "
                "(SELECT count(*) FROM pg_stat_activity "
                "WHERE datname = current_database()), "
                "current_setting('max_connections')::int"
            )
        ).one()
    except (SQLAlchemyError, TypeError, ValueError):
        return None, None, None
    return int(row[0]), int(row[1] or 0), int(row[2])


def portal_health(
    metric: PortalMetric,
    scheduler: SchedulerHealthSnapshot | None,
    workload: PortalWorkload | None = None,
) -> PortalHealth:
    connection_ratio = None
    if (
        workload is not None
        and workload.database_connections is not None
        and workload.database_max_connections
    ):
        connection_ratio = workload.database_connections / workload.database_max_connections

    if metric.disk_percent >= 90:
        return PortalHealth(
            "critical", "Мало места на диске", f"Занято {metric.disk_percent:.1f}%"
        )
    if metric.memory_percent >= 97:
        return PortalHealth(
            "critical", "Высокая память", f"Используется {metric.memory_percent:.1f}%"
        )
    if connection_ratio is not None and connection_ratio >= 0.95:
        return PortalHealth(
            "critical",
            "Почти исчерпаны подключения БД",
            f"Используется {workload.database_connections} из {workload.database_max_connections}",
        )
    if scheduler is not None and scheduler.running and scheduler.missed_interval_count > 0:
        return PortalHealth(
            "critical",
            "Scheduler отстаёт",
            f"Пропущен интервал у {scheduler.missed_interval_count} объект(ов)",
        )
    if (
        scheduler is not None
        and scheduler.running
        and scheduler.headroom_percent is not None
        and scheduler.headroom_percent <= 0
    ):
        return PortalHealth(
            "critical", "Нет запаса scheduler", "Последний пакет занял доступное окно"
        )
    if metric.disk_percent >= 80:
        return PortalHealth(
            "warning", "Заполняется диск", f"Занято {metric.disk_percent:.1f}%"
        )
    if metric.memory_percent >= 90:
        return PortalHealth(
            "warning", "Высокая память", f"Используется {metric.memory_percent:.1f}%"
        )
    if metric.cpu_percent >= 95:
        return PortalHealth(
            "warning", "Высокая загрузка CPU", f"CPU {metric.cpu_percent:.1f}%"
        )
    if connection_ratio is not None and connection_ratio >= 0.8:
        return PortalHealth(
            "warning",
            "Много подключений к БД",
            f"Используется {workload.database_connections} из {workload.database_max_connections}",
        )
    if scheduler is not None and scheduler.running:
        if scheduler.scheduler_errors_5m > 0:
            return PortalHealth(
                "warning",
                "Ошибки scheduler",
                f"Ошибок за 5 минут: {scheduler.scheduler_errors_5m}",
            )
        if scheduler.delayed_count > 0:
            return PortalHealth(
                "warning",
                "Есть задержки проверок",
                f"Более 60 секунд ждут {scheduler.delayed_count} объект(ов)",
            )
        if scheduler.headroom_percent is not None and scheduler.headroom_percent < 30:
            return PortalHealth(
                "warning",
                "Малый запас scheduler",
                f"Запас {scheduler.headroom_percent:.1f}%",
            )
        return PortalHealth(
            "normal", "Система в норме", "Очередь и ресурсы без критичных отклонений"
        )
    if scheduler is not None:
        return PortalHealth(
            "neutral", "Scheduler выключен", "Автоматические проверки сейчас не запущены"
        )
    return PortalHealth(
        "neutral", "Нет данных scheduler", "Runtime-метрики scheduler недоступны"
    )


def format_short_duration(seconds: float | int | None) -> str:
    if seconds is None:
        return "—"
    value = max(0.0, float(seconds))
    if value < 1:
        return f"{value * 1000:.0f} мс"
    if value < 60:
        return f"{value:.1f} с" if value < 10 else f"{value:.0f} с"
    if value < 3600:
        minutes, remainder = divmod(int(value), 60)
        return f"{minutes} мин. {remainder} с"
    hours, remainder = divmod(int(value), 3600)
    minutes = remainder // 60
    return f"{hours} ч. {minutes} мин."


def chart_points(values: list[float], *, ceiling: float | None = None) -> str:
    if not values:
        values = [0.0]
    width = 320.0
    height = 74.0
    maximum = chart_scale_max(values, ceiling=ceiling)
    if len(values) == 1:
        y_coordinate = height - min(max(values[0], 0), maximum) * height / maximum
        # A one-point SVG polyline is invisible.  Histories with deduplicated
        # stable values should still show their current level as a flat line.
        return f"0.0,{y_coordinate:.1f} {width:.1f},{y_coordinate:.1f}"
    divisor = max(1, len(values) - 1)
    points = []
    for index, value in enumerate(values):
        x_coordinate = index * width / divisor
        y_coordinate = height - min(max(value, 0), maximum) * height / maximum
        points.append(f"{x_coordinate:.1f},{y_coordinate:.1f}")
    return " ".join(points)


def chart_data(
    values: list[float],
    timestamps: list[datetime],
    *,
    ceiling: float | None = None,
) -> ChartData:
    normalized_values = [max(0.0, float(value)) for value in values] or [0.0]
    normalized_times = list(timestamps)
    if not normalized_times:
        normalized_times = [datetime.now(UTC)]
    if len(normalized_times) != len(normalized_values):
        normalized_times = [normalized_times[-1]] * len(normalized_values)
    scale_max = chart_scale_max(normalized_values, ceiling=ceiling)
    return ChartData(
        points=chart_points(normalized_values, ceiling=scale_max),
        values=tuple(normalized_values),
        timestamps=tuple(item.astimezone(UTC).isoformat() for item in normalized_times),
        scale_max=scale_max,
    )


def format_bytes(value: float) -> str:
    amount = max(0.0, float(value))
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if amount < 1024 or unit == "ТБ":
            return f"{amount:.0f} {unit}" if unit == "Б" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} ТБ"


def format_duration(seconds: int) -> str:
    days, remainder = divmod(max(0, seconds), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    if days:
        return f"{days} дн. {hours} ч."
    if hours:
        return f"{hours} ч. {minutes} мин."
    return f"{minutes} мин."
