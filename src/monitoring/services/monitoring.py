import asyncio
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from monitoring.checks.base import CheckOutcome, CheckTarget
from monitoring.checks.directory import scan_directory
from monitoring.checks.registry import CheckerRegistry
from monitoring.config import Settings
from monitoring.models import (
    CheckResult,
    CheckStatus,
    MonitorTarget,
    Site,
    TargetCheck,
    TargetCheckResult,
    WorkSchedule,
)
from monitoring.services.incidents import IncidentNotification, IncidentService
from monitoring.services.secrets import decrypt_secret
from monitoring.services.tls_monitoring import evaluate_tls_certificate
from monitoring.services.work_schedules import schedule_is_working, schedule_timezone


class MonitoringService:
    def __init__(
        self,
        registry: CheckerRegistry,
        timeout_seconds: float,
        max_parallel_checks: int,
        incident_service: IncidentService | None = None,
        network_semaphore: asyncio.Semaphore | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.registry = registry
        self.timeout_seconds = timeout_seconds
        self.max_parallel_checks = max(1, max_parallel_checks)
        self._semaphore = network_semaphore or asyncio.Semaphore(self.max_parallel_checks)
        self.incident_service = incident_service or IncidentService()
        self.settings = settings

    def get_due_targets(self, session: Session) -> list[MonitorTarget]:
        return [target for target, _lag in self.get_due_targets_with_lag(session)]

    def get_due_targets_with_lag(
        self, session: Session
    ) -> list[tuple[MonitorTarget, float]]:
        latest = (
            select(
                CheckResult.target_id.label("target_id"),
                func.max(CheckResult.checked_at).label("last_checked_at"),
            )
            .group_by(CheckResult.target_id)
            .subquery()
        )
        rows = session.execute(
            select(MonitorTarget, latest.c.last_checked_at, WorkSchedule)
            .join(Site, Site.id == MonitorTarget.site_id)
            .outerjoin(WorkSchedule, WorkSchedule.id == Site.schedule_id)
            .outerjoin(latest, MonitorTarget.id == latest.c.target_id)
            .where(MonitorTarget.enabled.is_(True), Site.enabled.is_(True))
        ).all()

        now = datetime.now(UTC)
        timezone_name = schedule_timezone(session)
        due: list[tuple[MonitorTarget, float]] = []
        for target, last_checked_at, schedule in rows:
            if not schedule_is_working(schedule, now, timezone_name):
                continue
            if last_checked_at is None:
                due.append((target, 0.0))
                continue
            if last_checked_at.tzinfo is None:
                last_checked_at = last_checked_at.replace(tzinfo=UTC)
            elapsed = (now - last_checked_at).total_seconds()
            if elapsed >= target.interval_seconds:
                due.append((target, max(0.0, elapsed - target.interval_seconds)))
        return due

    def get_active_targets(self, session: Session) -> list[MonitorTarget]:
        now = datetime.now(UTC)
        timezone_name = schedule_timezone(session)
        rows = session.execute(
            select(MonitorTarget, WorkSchedule)
            .join(Site, Site.id == MonitorTarget.site_id)
            .outerjoin(WorkSchedule, WorkSchedule.id == Site.schedule_id)
            .where(MonitorTarget.enabled.is_(True), Site.enabled.is_(True))
            .order_by(MonitorTarget.id)
        ).all()
        return [
            target
            for target, schedule in rows
            if schedule_is_working(schedule, now, timezone_name)
        ]

    async def check_target(self, target: MonitorTarget) -> CheckOutcome:
        try:
            checker = self.registry.get(target.checker_type)
        except LookupError as exc:
            return CheckOutcome(CheckStatus.UNKNOWN, message=str(exc))

        async with self._semaphore:
            return await checker.check(
                CheckTarget(address=target.address, port=target.port),
                timeout_seconds=self.timeout_seconds,
            )

    async def check_target_check(
        self, target: MonitorTarget, check: TargetCheck
    ) -> CheckOutcome:
        if check.checker_type == "directory":
            return await self._check_directory(check)
        try:
            checker = self.registry.get(check.checker_type)
        except LookupError as exc:
            return CheckOutcome(CheckStatus.UNKNOWN, message=str(exc))

        timeout = check.timeout_seconds or self.timeout_seconds
        attempts = max(1, check.retries + 1)
        outcome = CheckOutcome(CheckStatus.UNKNOWN, message="Проверка не выполнена")
        for _attempt in range(attempts):
            async with self._semaphore:
                outcome = await checker.check(
                    CheckTarget(
                        address=check.address_override or target.address,
                        port=check.port,
                        path=check.path or "/",
                        http_expected_status=(
                            check.http_expected_status
                            if check.checker_type in {"http", "https"}
                            else None
                        ),
                        http_content_contains=(
                            check.http_content_contains
                            if check.checker_type in {"http", "https"}
                            else None
                        ),
                        http_content_not_contains=(
                            check.http_content_not_contains
                            if check.checker_type in {"http", "https"}
                            else None
                        ),
                        http_max_response_ms=(
                            check.http_max_response_ms
                            if check.checker_type in {"http", "https"}
                            else None
                        ),
                        dns_name=(check.dns_name if check.checker_type == "dns" else None),
                        dns_record_type=(
                            check.dns_record_type if check.checker_type == "dns" else None
                        ),
                        dns_expected_address=(
                            check.dns_expected_address
                            if check.checker_type == "dns"
                            else None
                        ),
                        dns_max_response_ms=(
                            check.dns_max_response_ms
                            if check.checker_type == "dns"
                            else None
                        ),
                    ),
                    timeout_seconds=timeout,
                )
            if outcome.status == CheckStatus.UP:
                break
        return outcome

    async def _check_directory(self, check: TargetCheck) -> CheckOutcome:
        """Run metadata-only directory freshness through the usual retry policy."""
        if not check.directory_path or check.directory_period_hours is None:
            return CheckOutcome(CheckStatus.DOWN, message="Не настроен путь к каталогу")
        password = ""
        if check.directory_password_encrypted:
            if self.settings is None:
                return CheckOutcome(CheckStatus.DOWN, message="Проверка каталога недоступна")
            try:
                password = decrypt_secret(
                    self.settings,
                    check.directory_password_encrypted,
                    label="Пароль SMB",
                )
            except RuntimeError:
                return CheckOutcome(CheckStatus.DOWN, message="Проверка каталога недоступна")
        timeout = check.timeout_seconds or self.timeout_seconds
        outcome = CheckOutcome(CheckStatus.UNKNOWN, message="Проверка не выполнена")
        for _attempt in range(max(1, check.retries + 1)):
            async with self._semaphore:
                scan = await scan_directory(
                    path=check.directory_path,
                    pattern=check.directory_pattern or "*",
                    period_hours=check.directory_period_hours,
                    show_last=check.directory_show_last or 0,
                    timeout_seconds=timeout,
                    username=check.directory_username,
                    password=password,
                )
            outcome = scan.outcome
            if outcome.status == CheckStatus.UP:
                break
        return outcome

    async def probe_http_status(
        self,
        *,
        checker_type: str,
        address: str,
        port: int,
        path: str,
        timeout_seconds: float | None,
    ) -> CheckOutcome:
        """Fetch one current HTTP/HTTPS response without saving a check result."""
        if checker_type not in {"http", "https"}:
            raise ValueError("Текущий код можно получить только для HTTP или HTTPS")
        try:
            checker = self.registry.get(checker_type)
        except LookupError as exc:
            return CheckOutcome(CheckStatus.UNKNOWN, message=str(exc))
        async with self._semaphore:
            return await checker.check(
                CheckTarget(address=address, port=port, path=path),
                timeout_seconds=timeout_seconds or self.timeout_seconds,
            )

    def save_result(
        self, session: Session, target_id: int, outcome: CheckOutcome
    ) -> list[IncidentNotification]:
        target = session.get(MonitorTarget, target_id)
        if target is None:
            raise LookupError(f"Target {target_id} not found")
        site = session.get(Site, target.site_id)
        schedule = session.get(WorkSchedule, site.schedule_id) if site is not None else None
        if site is None or not site.enabled or not target.enabled:
            return []
        if not schedule_is_working(schedule, datetime.now(UTC), schedule_timezone(session)):
            return []
        result = CheckResult(
            target_id=target_id,
            status=outcome.status.value,
            latency_ms=outcome.latency_ms,
            message=outcome.message,
        )
        session.add(result)
        session.flush()
        events = self.incident_service.process_result(session, target, result)
        session.commit()
        return events

    def save_target_check_result(
        self,
        session: Session,
        target_id: int,
        check_id: int,
        outcome: CheckOutcome,
        *,
        expected_config_version: int | None = None,
    ) -> list[IncidentNotification]:
        target = session.get(MonitorTarget, target_id)
        check = session.get(TargetCheck, check_id)
        if target is None or check is None or check.target_id != target_id:
            if expected_config_version is not None:
                return []
            raise LookupError("Проверка объекта не найдена")
        if (
            expected_config_version is not None
            and check.config_version != expected_config_version
        ):
            return []
        site = session.get(Site, target.site_id)
        schedule = session.get(WorkSchedule, site.schedule_id) if site is not None else None
        if site is None or not site.enabled or not target.enabled or not check.enabled:
            return []
        if not schedule_is_working(schedule, datetime.now(UTC), schedule_timezone(session)):
            return []
        result = TargetCheckResult(
            check_id=check.id,
            config_version=check.config_version,
            status=outcome.status.value,
            latency_ms=outcome.latency_ms,
            message=outcome.message,
        )
        tls_evaluation = None
        if (
            check.checker_type == "https"
            and check.tls_monitor_enabled
            and outcome.tls_not_after is not None
        ):
            tls_evaluation = evaluate_tls_certificate(
                not_after=outcome.tls_not_after,
                warning_days=check.tls_warning_days or 30,
                critical_days=check.tls_critical_days if check.tls_critical_days is not None else 7,
                now=result.checked_at,
            )
            result.tls_not_after = tls_evaluation.not_after
            result.tls_days_remaining = tls_evaluation.days_remaining
            result.tls_health = tls_evaluation.health.value
        session.add(result)
        session.flush()
        if check.checker_type == "directory" and outcome.directory_accessible:
            files = list(outcome.directory_files or ())
            if check.directory_last_files != files:
                check.directory_last_files = files
            check.directory_recent_count = outcome.directory_recent_count
            check.directory_latest_file_at = outcome.directory_latest_file_at
            check.directory_scanned_at = result.checked_at
        events = self.incident_service.process_target_check_result(
            session, target, check, result
        )
        # Only a certificate obtained from this just-completed HTTPS request may
        # mutate expiry incidents. A DOWN result without metadata leaves the prior
        # TLS state untouched rather than creating a fake recovery.
        if tls_evaluation is not None:
            events.extend(
                self.incident_service.apply_check_tls_health(
                    session,
                    target,
                    check,
                    tls_evaluation,
                    observed_at=result.checked_at,
                )
            )
        session.commit()
        return events
