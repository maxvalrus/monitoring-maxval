import asyncio
import logging
import time
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select

from monitoring.db import SessionLocal
from monitoring.models import (
    CheckStatus,
    Incident,
    MonitorTarget,
    Site,
    SnmpConfig,
    SnmpStatus,
    SnmpUpsState,
    TargetCheck,
    WorkSchedule,
)
from monitoring.notifications import Notifier
from monitoring.services.audit import write_audit
from monitoring.services.communication import create_incident_notifications
from monitoring.services.incidents import IncidentNotification
from monitoring.services.maintenance import cleanup_all_history
from monitoring.services.monitoring import MonitoringService
from monitoring.services.push import send_push_to_user
from monitoring.services.scheduler_metrics import (
    DueTargetTiming,
    SchedulerHealthSnapshot,
    SchedulerRuntimeMetrics,
)
from monitoring.services.site_entry import blocked_site_ids, blocking_gate_for_target
from monitoring.services.snmp import SnmpService, SnmpTestResult
from monitoring.services.snmp_discovery import SnmpDiscoveryResult
from monitoring.services.snmp_interfaces import SnmpInterfacesResult
from monitoring.services.snmp_supplies import SnmpSuppliesResult
from monitoring.services.system_metrics import metric_interval_seconds, save_system_metric
from monitoring.services.work_schedules import schedule_is_working, schedule_timezone

logger = logging.getLogger(__name__)

@dataclass(frozen=True, slots=True)
class ManualTargetCheckResult:
    status: str
    latency_ms: float | None
    message: str | None
    off_hours: bool
    saved: bool


@dataclass(frozen=True, slots=True)
class ScheduledTarget:
    target: MonitorTarget
    checks: tuple[TargetCheck, ...]


class CheckScheduler:
    def __init__(
        self,
        monitoring: MonitoringService,
        poll_seconds: int,
        notifier: Notifier | None = None,
        snmp_service: SnmpService | None = None,
    ) -> None:
        self.monitoring = monitoring
        self.poll_seconds = poll_seconds
        self.notifier = notifier
        self.snmp_service = snmp_service
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._manual_task: asyncio.Task[None] | None = None
        self._check_lock = asyncio.Lock()
        self._next_cleanup_at = 0.0
        self._next_metric_at = 0.0
        parallel_limit = getattr(monitoring, "max_parallel_checks", 1)
        if not isinstance(parallel_limit, int):
            parallel_limit = 1
        self.metrics = SchedulerRuntimeMetrics(
            poll_seconds=poll_seconds,
            parallel_limit=parallel_limit,
        )

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="check-scheduler")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            await self._task
            self._task = None
        if self._manual_task is not None and not self._manual_task.done():
            await self._manual_task

    def trigger_all(self) -> bool:
        if self._manual_task is not None and not self._manual_task.done():
            return False
        self._manual_task = asyncio.create_task(
            self._run_manual_checks(),
            name="manual-check-all",
        )
        return True

    async def run_target_now(self, target_id: int) -> ManualTargetCheckResult:
        async with self._check_lock:
            with SessionLocal() as session:
                row = session.execute(
                    select(MonitorTarget, Site, WorkSchedule)
                    .join(Site, Site.id == MonitorTarget.site_id)
                    .outerjoin(WorkSchedule, WorkSchedule.id == Site.schedule_id)
                    .where(
                        MonitorTarget.id == target_id,
                        MonitorTarget.enabled.is_(True),
                        Site.enabled.is_(True),
                    )
                ).one_or_none()
                if row is None:
                    raise LookupError("Объект не найден или отключён")
                target, _site, schedule = row
                working = schedule_is_working(
                    schedule, datetime.now(UTC), schedule_timezone(session)
                )
                gate = blocking_gate_for_target(session, target)
                if gate is not None:
                    return ManualTargetCheckResult(
                        status="unknown",
                        latency_ms=None,
                        message=(
                            "Не проверено: нет связи с площадкой "
                            f"(точка входа {gate.entry_target_name})"
                        ),
                        off_hours=not working,
                        saved=False,
                    )
                checks = tuple(
                    session.scalars(
                        select(TargetCheck)
                        .where(
                            TargetCheck.target_id == target.id,
                            TargetCheck.enabled.is_(True),
                            TargetCheck.is_primary.is_(False),
                        )
                        .order_by(TargetCheck.display_order, TargetCheck.id)
                    ).all()
                )

            started = time.monotonic()
            outcome = await self.monitoring.check_target(target)
            try:
                events: list[IncidentNotification] = []
                if working:
                    events = await asyncio.to_thread(self._save_result, target.id, outcome)
                    for event in events:
                        await self._send_notification(event)
                    if outcome.status == CheckStatus.UP:
                        await self._run_secondary_checks(target, checks)
                    snmp_events = await self._poll_snmp_after_primary(target.id, outcome)
                    for event in snmp_events:
                        await self._send_notification(event)
                return ManualTargetCheckResult(
                    status=outcome.status.value,
                    latency_ms=outcome.latency_ms,
                    message=outcome.message,
                    off_hours=not working,
                    saved=working,
                )
            finally:
                self.metrics.record_network_check(
                    time.monotonic() - started,
                    outcome.status,
                )

    async def test_snmp_now(self, target_id: int) -> SnmpTestResult:
        if self.snmp_service is None:
            return SnmpTestResult("disabled", "SNMP Core не настроен", {})
        async with self._check_lock:
            with SessionLocal() as session:
                target = session.scalar(
                    select(MonitorTarget)
                    .join(Site, Site.id == MonitorTarget.site_id)
                    .where(
                        MonitorTarget.id == target_id,
                        MonitorTarget.enabled.is_(True),
                        Site.enabled.is_(True),
                    )
                )
                if target is None:
                    raise LookupError("Объект не найден или отключён")
            outcome = await self.monitoring.check_target(target)
            if outcome.status != CheckStatus.UP:
                return SnmpTestResult(
                    "skipped",
                    "SNMP не проверялся: основная проверка объекта неуспешна",
                    {},
                )
            return await self.snmp_service.test_target(target_id)

    async def discover_snmp_now(
        self, target_id: int, roots: tuple[str, ...]
    ) -> SnmpDiscoveryResult:
        if self.snmp_service is None:
            return SnmpDiscoveryResult(
                "disabled", "SNMP Core не настроен", (), roots
            )
        async with self._check_lock:
            with SessionLocal() as session:
                target = session.scalar(
                    select(MonitorTarget)
                    .join(Site, Site.id == MonitorTarget.site_id)
                    .where(
                        MonitorTarget.id == target_id,
                        MonitorTarget.enabled.is_(True),
                        Site.enabled.is_(True),
                    )
                )
                if target is None:
                    raise LookupError("Объект не найден или отключён")
            outcome = await self.monitoring.check_target(target)
        if outcome.status != CheckStatus.UP:
            return SnmpDiscoveryResult(
                "skipped",
                "SNMP Discovery не выполнен: основная проверка объекта неуспешна",
                (),
                roots,
            )
        # Discovery is read-only and can take much longer than a normal check. Do not
        # hold the scheduler-wide check lock while walking the MIB tree. Network load
        # is still bounded by the shared SNMP/network semaphore.
        return await self.snmp_service.discover_target(target_id, roots)

    async def discover_snmp_supplies_now(self, target_id: int) -> SnmpSuppliesResult:
        if self.snmp_service is None:
            return SnmpSuppliesResult("disabled", "SNMP Core не настроен", ())
        async with self._check_lock:
            with SessionLocal() as session:
                target = session.scalar(
                    select(MonitorTarget)
                    .join(Site, Site.id == MonitorTarget.site_id)
                    .where(
                        MonitorTarget.id == target_id,
                        MonitorTarget.enabled.is_(True),
                        Site.enabled.is_(True),
                    )
                )
                if target is None:
                    raise LookupError("Объект не найден или отключён")
            outcome = await self.monitoring.check_target(target)
        if outcome.status != CheckStatus.UP:
            return SnmpSuppliesResult(
                "skipped",
                "Расходники не опрашивались: основная проверка объекта неуспешна",
                (),
            )
        return await self.snmp_service.discover_supplies_target(target_id)

    async def discover_snmp_interfaces_now(self, target_id: int) -> SnmpInterfacesResult:
        if self.snmp_service is None:
            return SnmpInterfacesResult("disabled", "SNMP Core не настроен", ())
        async with self._check_lock:
            with SessionLocal() as session:
                target = session.scalar(
                    select(MonitorTarget)
                    .join(Site, Site.id == MonitorTarget.site_id)
                    .where(
                        MonitorTarget.id == target_id,
                        MonitorTarget.enabled.is_(True),
                        Site.enabled.is_(True),
                    )
                )
                if target is None:
                    raise LookupError("Объект не найден или отключён")
            outcome = await self.monitoring.check_target(target)
        if outcome.status != CheckStatus.UP:
            return SnmpInterfacesResult(
                "skipped",
                "Интерфейсы не опрашивались: основная проверка объекта неуспешна",
                (),
            )
        # IF-MIB discovery is manual and may take longer than a normal check. Keep the
        # global scheduler lock only around the primary availability check.
        return await self.snmp_service.discover_interfaces_target(target_id)

    async def poll_snmp_interfaces_now(self, target_id: int) -> SnmpTestResult:
        """Run the normal SNMP GET for selected interfaces after a live availability check."""
        if self.snmp_service is None:
            return SnmpTestResult("disabled", "SNMP Core не настроен", {})
        async with self._check_lock:
            with SessionLocal() as session:
                target = session.scalar(
                    select(MonitorTarget)
                    .join(Site, Site.id == MonitorTarget.site_id)
                    .where(
                        MonitorTarget.id == target_id,
                        MonitorTarget.enabled.is_(True),
                        Site.enabled.is_(True),
                    )
                )
                if target is None:
                    raise LookupError("Объект не найден или отключён")
            outcome = await self.monitoring.check_target(target)
            if outcome.status != CheckStatus.UP:
                return SnmpTestResult(
                    "skipped",
                    "Интерфейсы не опрашивались: основная проверка объекта неуспешна",
                    {},
                )
            snmp_events = await self.snmp_service.poll_target(target_id)
            with SessionLocal() as session:
                config = session.get(SnmpConfig, target_id)
                if config is None or not config.enabled:
                    return SnmpTestResult("disabled", "SNMP для объекта не включён", {})
                if config.last_status != SnmpStatus.OK:
                    return SnmpTestResult(
                        "error",
                        config.last_error or "SNMP polling завершился ошибкой",
                        {},
                    )
        for event in snmp_events:
            await self._send_notification(event)
        return SnmpTestResult("ok", "Данные выбранных интерфейсов обновлены", {})

    async def poll_snmp_supplies_now(self, target_id: int) -> SnmpTestResult:
        """Run the normal SNMP GET and deliver supply-threshold notifications."""
        if self.snmp_service is None:
            return SnmpTestResult("disabled", "SNMP Core не настроен", {})
        async with self._check_lock:
            with SessionLocal() as session:
                target = session.scalar(
                    select(MonitorTarget)
                    .join(Site, Site.id == MonitorTarget.site_id)
                    .where(
                        MonitorTarget.id == target_id,
                        MonitorTarget.enabled.is_(True),
                        Site.enabled.is_(True),
                    )
                )
                if target is None:
                    raise LookupError("Объект не найден или отключён")
            outcome = await self.monitoring.check_target(target)
            if outcome.status != CheckStatus.UP:
                return SnmpTestResult(
                    "skipped",
                    "Расходники не опрашивались: основная проверка объекта неуспешна",
                    {},
                )
            snmp_events = await self.snmp_service.poll_target(target_id)
            with SessionLocal() as session:
                config = session.get(SnmpConfig, target_id)
                if config is None or not config.enabled:
                    return SnmpTestResult("disabled", "SNMP для объекта не включён", {})
                if config.last_status != SnmpStatus.OK:
                    return SnmpTestResult(
                        "error",
                        config.last_error or "SNMP polling завершился ошибкой",
                        {},
                    )
        for event in snmp_events:
            await self._send_notification(event)
        return SnmpTestResult("ok", "Уровни расходников обновлены", {})

    async def poll_snmp_ups_now(self, target_id: int) -> SnmpTestResult:
        """Run the existing SNMP UPS-MIB poll after a live primary check."""
        if self.snmp_service is None:
            return SnmpTestResult("disabled", "SNMP Core не настроен", {})
        async with self._check_lock:
            with SessionLocal() as session:
                target = session.scalar(
                    select(MonitorTarget)
                    .join(Site, Site.id == MonitorTarget.site_id)
                    .where(
                        MonitorTarget.id == target_id,
                        MonitorTarget.enabled.is_(True),
                        Site.enabled.is_(True),
                    )
                )
                if target is None:
                    raise LookupError("Объект не найден или отключён")
                config = session.get(SnmpConfig, target_id)
                if config is None or not config.enabled:
                    return SnmpTestResult("disabled", "SNMP для объекта не включён", {})
                if not config.ups_enabled:
                    return SnmpTestResult("disabled", "Мониторинг ИБП для объекта выключен", {})
            outcome = await self.monitoring.check_target(target)
            if outcome.status != CheckStatus.UP:
                return SnmpTestResult(
                    "skipped",
                    "ИБП не опрашивался: основная проверка объекта неуспешна",
                    {},
                )
            snmp_events = await self.snmp_service.poll_target(target_id)
            with SessionLocal() as session:
                config = session.get(SnmpConfig, target_id)
                if config is None or config.last_status != SnmpStatus.OK:
                    return SnmpTestResult(
                        "error",
                        config.last_error if config is not None else "SNMP polling завершился ошибкой",
                        {},
                    )
                if session.get(SnmpUpsState, target_id) is None:
                    return SnmpTestResult(
                        "ok", "SNMP обновлён, но UPS-MIB не вернул доступных данных", {}
                    )
        for event in snmp_events:
            await self._send_notification(event)
        return SnmpTestResult("ok", "Данные ИБП обновлены", {})

    async def _run(self) -> None:
        logger.info("Check scheduler started")
        while not self._stop.is_set():
            try:
                loop = asyncio.get_running_loop()
                if loop.time() >= self._next_metric_at:
                    interval = await asyncio.to_thread(self._collect_metric)
                    self._next_metric_at = loop.time() + interval
                if loop.time() >= self._next_cleanup_at:
                    deleted_checks, deleted_metrics, deleted_audit, deleted_notifications, deleted_snmp_samples = await asyncio.to_thread(
                        self._cleanup_history
                    )
                    logger.info(
                        "History cleanup removed %s check results, %s portal metrics "
                        "%s audit records, %s notifications and %s SNMP samples",
                        deleted_checks,
                        deleted_metrics,
                        deleted_audit,
                        deleted_notifications,
                        deleted_snmp_samples,
                    )
                    self._next_cleanup_at = loop.time() + 86400
                async with self._check_lock:
                    scheduled_targets, timings = await asyncio.to_thread(self._load_due_targets)
                    self.metrics.record_scan(timings)
                    self.metrics.set_batch_shortest_interval(
                        min((item.target.interval_seconds for item in scheduled_targets), default=None)
                    )
                    try:
                        if scheduled_targets:
                            await self._run_site_gated_batch(scheduled_targets)
                    finally:
                        self.metrics.finish_batch()
            except Exception as exc:
                self.metrics.record_scheduler_error(exc)
                logger.exception("Unexpected scheduler iteration failure")

            with suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=self.poll_seconds)
        logger.info("Check scheduler stopped")

    def _load_due_targets(self) -> tuple[list[ScheduledTarget], list[DueTargetTiming]]:
        with SessionLocal() as session:
            rows = self.monitoring.get_due_targets_with_lag(session)
            target_ids = [target.id for target, _lag in rows]
            checks_by_target = self._secondary_checks_by_target(session, target_ids)
        scheduled = [
            ScheduledTarget(target, checks_by_target.get(target.id, ()))
            for target, _lag in rows
        ]
        timings = [
            DueTargetTiming(
                target_id=target.id,
                lag_seconds=lag_seconds,
                interval_seconds=target.interval_seconds,
            )
            for target, lag_seconds in rows
        ]
        return scheduled, timings

    async def _run_site_gated_batch(
        self, scheduled_targets: list[ScheduledTarget]
    ) -> None:
        """Check due site entries first so a new DOWN blocks siblings this batch."""
        entries = [item for item in scheduled_targets if item.target.is_site_entry]
        regular = [item for item in scheduled_targets if not item.target.is_site_entry]
        if entries:
            await asyncio.gather(*(self._check_and_save(item) for item in entries))
        if not regular:
            return

        blocked = await asyncio.to_thread(
            self._load_blocked_site_ids, {item.target.site_id for item in regular}
        )
        allowed: list[ScheduledTarget] = []
        for item in regular:
            if item.target.site_id in blocked:
                # Suppression is intentional, not overdue work in Portal Health.
                self.metrics.mark_target_complete(item.target.id)
            else:
                allowed.append(item)
        if allowed:
            await asyncio.gather(*(self._check_and_save(item) for item in allowed))

    @staticmethod
    def _load_blocked_site_ids(site_ids: set[int]) -> set[int]:
        with SessionLocal() as session:
            return blocked_site_ids(session, site_ids)

    @staticmethod
    def _secondary_checks_by_target(
        session, target_ids: list[int]
    ) -> dict[int, tuple[TargetCheck, ...]]:
        if not target_ids:
            return {}
        checks = session.scalars(
            select(TargetCheck)
            .where(
                TargetCheck.target_id.in_(target_ids),
                TargetCheck.enabled.is_(True),
                TargetCheck.is_primary.is_(False),
            )
            .order_by(TargetCheck.target_id, TargetCheck.display_order, TargetCheck.id)
        ).all()
        grouped: dict[int, list[TargetCheck]] = {}
        for check in checks:
            grouped.setdefault(check.target_id, []).append(check)
        return {target_id: tuple(items) for target_id, items in grouped.items()}

    def health_snapshot(self) -> SchedulerHealthSnapshot:
        return self.metrics.snapshot(
            running=self._task is not None and not self._task.done(),
            manual_running=self._manual_task is not None and not self._manual_task.done(),
        )

    def _load_active_targets(self) -> list[ScheduledTarget]:
        with SessionLocal() as session:
            targets = self.monitoring.get_active_targets(session)
            checks_by_target = self._secondary_checks_by_target(
                session, [target.id for target in targets]
            )
        return [
            ScheduledTarget(target, checks_by_target.get(target.id, ()))
            for target in targets
        ]

    async def _run_manual_checks(self) -> None:
        try:
            async with self._check_lock:
                targets = await asyncio.to_thread(self._load_active_targets)
                logger.info("Manual check started for %s targets", len(targets))
                if targets:
                    await self._run_site_gated_batch(targets)
                logger.info("Manual check finished for %s targets", len(targets))
        except Exception:
            logger.exception("Manual check failed")

    @staticmethod
    def _cleanup_history() -> tuple[int, int, int, int, int]:
        with SessionLocal() as session:
            return cleanup_all_history(session)

    @staticmethod
    def _collect_metric() -> int:
        with SessionLocal() as session:
            interval = metric_interval_seconds(session)
            save_system_metric(session)
            return interval

    async def _check_and_save(
        self, scheduled: ScheduledTarget | MonitorTarget
    ) -> None:
        if not isinstance(scheduled, ScheduledTarget):
            scheduled = ScheduledTarget(scheduled, ())
        target = scheduled.target
        started = time.monotonic()
        outcome = await self.monitoring.check_target(target)
        self.metrics.record_network_check(time.monotonic() - started, outcome.status)
        try:
            events = await asyncio.to_thread(self._save_result, target.id, outcome)
            for event in events:
                await self._send_notification(event)
            if outcome.status == CheckStatus.UP:
                await self._run_secondary_checks(target, scheduled.checks)
            snmp_events = await self._poll_snmp_after_primary(target.id, outcome)
            for event in snmp_events:
                await self._send_notification(event)
        finally:
            self.metrics.mark_target_complete(target.id)

    async def _run_secondary_checks(
        self, target: MonitorTarget, checks: tuple[TargetCheck, ...]
    ) -> None:
        if not checks:
            return

        async def run_one(check: TargetCheck) -> None:
            started = time.monotonic()
            outcome = await self.monitoring.check_target_check(target, check)
            try:
                events = await asyncio.to_thread(
                    self._save_target_check_result,
                    target.id,
                    check.id,
                    check.config_version or 1,
                    outcome,
                )
                for event in events:
                    await self._send_notification(event)
            finally:
                self.metrics.record_network_check(
                    time.monotonic() - started, outcome.status
                )

        await asyncio.gather(*(run_one(check) for check in checks))

    async def _poll_snmp_after_primary(
        self, target_id: int, outcome
    ) -> list[IncidentNotification]:
        if self.snmp_service is not None and outcome.status == CheckStatus.UP:
            return await self.snmp_service.poll_target(target_id)
        return []

    def _save_result(self, target_id: int, outcome) -> list[IncidentNotification]:
        with SessionLocal() as session:
            return self.monitoring.save_result(session, target_id, outcome)

    def _save_target_check_result(
        self,
        target_id: int,
        check_id: int,
        expected_config_version: int,
        outcome,
    ) -> list[IncidentNotification]:
        with SessionLocal() as session:
            return self.monitoring.save_target_check_result(
                session,
                target_id,
                check_id,
                outcome,
                expected_config_version=expected_config_version,
            )

    async def _send_notification(self, event: IncidentNotification) -> None:
        # Internal notifications are always created. External channels are gated by
        # the global "notifications_enabled" setting inside each delivery channel.
        user_ids: list[int] = []
        target_name = f"Инцидент #{event.incident_id}"
        site_name = "Мониторинг"
        message = None
        target_id: int | None = None
        source_kind = "availability"
        severity = None
        with SessionLocal() as session:
            incident = session.get(Incident, event.incident_id)
            if incident is not None and incident.target is not None:
                target_name = incident.target.name
                site_name = incident.target.site.name
                message = incident.last_message
                target_id = incident.target_id
                source_kind = getattr(incident, "source_kind", "availability")
                severity = getattr(incident, "severity", None)
                if source_kind == "check" and incident.check_id is not None:
                    check = session.get(TargetCheck, incident.check_id)
                    if check is not None:
                        target_name = f"{target_name} · {check.name}"
            user_ids = create_incident_notifications(
                session,
                incident_id=event.incident_id,
                kind=event.kind.value,
                target_name=target_name,
                site_name=site_name,
                message=message,
                target_id=target_id,
                source_kind=source_kind,
                severity=severity,
            )
            session.commit()

        push_category = "incident_opened" if event.kind.value == "opened" else "incident_recovered"
        if source_kind == "snmp":
            if event.kind.value == "opened":
                level = "Critical" if severity == "critical" else "Warning"
                push_title = f"SNMP {level}: {target_name}"
                push_body = f"{site_name}. {message or 'Порог SNMP превышен.'}"
            else:
                push_title = f"SNMP в норме: {target_name}"
                push_body = f"{site_name}. Значение вернулось в норму."
        elif source_kind == "check":
            push_title = (
                f"Сервис недоступен: {target_name}"
                if event.kind.value == "opened"
                else f"Сервис восстановлен: {target_name}"
            )
            push_body = f"{site_name}. {message or 'Состояние сервисной проверки изменилось.'}"
        else:
            push_title = f"Недоступен: {target_name}" if event.kind.value == "opened" else f"Восстановлен: {target_name}"
            push_body = f"{site_name}. {message or 'Открыт новый инцидент.'}" if event.kind.value == "opened" else f"{site_name}. Объект снова доступен."
        event_url = (
            f"/incidents?focus_id={event.incident_id}#incident-{event.incident_id}"
        )
        for user_id in user_ids:
            await asyncio.to_thread(
                send_push_to_user,
                user_id,
                category=push_category,
                title=push_title,
                body=push_body,
                url=event_url,
            )

        action = None
        if self.notifier is not None:
            try:
                sent = await self.notifier.send(event.notification)
                if sent:
                    action = "notification.email_sent"
            except Exception:
                action = "notification.email_failed"
                logger.exception("Email notification failed for incident %s", event.incident_id)
        if action:
            with SessionLocal() as session:
                write_audit(
                    session,
                    action,
                    entity_type="incident",
                    entity_id=event.incident_id,
                    details={"event": event.kind.value},
                )
                session.commit()
