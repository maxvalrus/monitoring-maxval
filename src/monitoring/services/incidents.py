from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy import select
from sqlalchemy.orm import Session

from monitoring.models import (
    AppSetting,
    CheckResult,
    CheckStatus,
    Incident,
    IncidentSeverity,
    IncidentSourceKind,
    IncidentStatus,
    MonitorTarget,
    TargetCheck,
    TargetCheckResult,
)
from monitoring.models.mixins import utc_now
from monitoring.notifications import Notification
from monitoring.services.directory_monitoring import DIRECTORY_CHECKER_TYPE
from monitoring.services.tls_monitoring import TlsEvaluation, TlsHealth, tls_reason
from monitoring.services.unstable_link import (
    record_confirmed_down,
    record_recovered_up,
    record_unconfirmed_down,
)


class IncidentEventKind(StrEnum):
    OPENED = "opened"
    RECOVERED = "recovered"


@dataclass(frozen=True, slots=True)
class IncidentNotification:
    incident_id: int
    kind: IncidentEventKind
    notification: Notification


def integer_setting(session: Session, key: str, default: int) -> int:
    setting = session.get(AppSetting, key)
    try:
        return int(setting.value) if setting is not None else default
    except ValueError:
        return default


def boolean_setting(session: Session, key: str, default: bool = False) -> bool:
    setting = session.get(AppSetting, key)
    return setting.value.casefold() == "true" if setting is not None else default


class IncidentService:
    def process_result(
        self,
        session: Session,
        target: MonitorTarget,
        result: CheckResult,
    ) -> list[IncidentNotification]:
        incident = session.scalar(
            select(Incident)
            .where(
                Incident.target_id == target.id,
                Incident.status == IncidentStatus.OPEN,
                Incident.source_kind == IncidentSourceKind.AVAILABILITY,
                Incident.check_id.is_(None),
            )
            .order_by(Incident.id.desc())
        )
        events: list[IncidentNotification] = []

        if result.status == CheckStatus.DOWN:
            if incident is None and self._confirmed_failure(session, target.id):
                incident = Incident(
                    target_id=target.id,
                    status=IncidentStatus.OPEN,
                    source_kind=IncidentSourceKind.AVAILABILITY,
                    source_key=None,
                    severity=None,
                    failure_count=integer_setting(
                        session, "failures_before_incident", 2
                    ),
                    opened_at=result.checked_at,
                    last_failure_at=result.checked_at,
                    last_message=result.message,
                )
                session.add(incident)
                session.flush()
            elif incident is not None:
                incident.failure_count += 1
                incident.last_failure_at = result.checked_at
                incident.last_message = result.message

            if incident is not None:
                event = self._opening_notification(session, target, incident)
                if event is not None:
                    events.append(event)
            if incident is None:
                record_unconfirmed_down(target)
            else:
                record_confirmed_down(target)

        elif result.status == CheckStatus.UP:
            recovery_from_confirmed_incident = incident is not None
            if incident is not None:
                incident.status = IncidentStatus.RESOLVED
                incident.resolved_at = result.checked_at
                event = self._recovery_notification(session, target, incident)
                if event is not None:
                    events.append(event)
            record_recovered_up(
                target,
                observed_at=result.checked_at,
                recovery_from_confirmed_incident=recovery_from_confirmed_incident,
            )

        return events

    def process_target_check_result(
        self,
        session: Session,
        target: MonitorTarget,
        check: TargetCheck,
        result: TargetCheckResult,
    ) -> list[IncidentNotification]:
        if check.is_primary:
            return []
        incident = session.scalar(
            select(Incident)
            .where(
                Incident.target_id == target.id,
                Incident.check_id == check.id,
                Incident.status == IncidentStatus.OPEN,
                Incident.source_kind == IncidentSourceKind.CHECK,
            )
            .order_by(Incident.id.desc())
        )
        events: list[IncidentNotification] = []
        message = self._check_message(check, result.message)

        if result.status == CheckStatus.DOWN:
            if incident is None and self._confirmed_check_failure(
                session, check.id, result.config_version
            ):
                incident = Incident(
                    target_id=target.id,
                    check_id=check.id,
                    status=IncidentStatus.OPEN,
                    source_kind=IncidentSourceKind.CHECK,
                    source_key=None,
                    severity=IncidentSeverity.CRITICAL,
                    failure_count=integer_setting(session, "failures_before_incident", 2),
                    opened_at=result.checked_at,
                    last_failure_at=result.checked_at,
                    last_message=message,
                )
                session.add(incident)
                session.flush()
            elif incident is not None:
                incident.failure_count += 1
                incident.last_failure_at = result.checked_at
                incident.last_message = message

            if incident is not None:
                event = self._opening_notification(session, target, incident)
                if event is not None:
                    events.append(event)
            if incident is None and check.checker_type != DIRECTORY_CHECKER_TYPE:
                record_unconfirmed_down(check)
            elif incident is not None and check.checker_type != DIRECTORY_CHECKER_TYPE:
                record_confirmed_down(check)
        elif result.status == CheckStatus.UP:
            recovery_from_confirmed_incident = incident is not None
            if incident is not None:
                incident.status = IncidentStatus.RESOLVED
                incident.resolved_at = result.checked_at
                incident.last_message = self._check_message(check, "проверка снова успешна")
                event = self._recovery_notification(session, target, incident)
                if event is not None:
                    events.append(event)
            if check.checker_type != DIRECTORY_CHECKER_TYPE:
                record_recovered_up(
                    check,
                    observed_at=result.checked_at,
                    recovery_from_confirmed_incident=recovery_from_confirmed_incident,
                )
        return events

    def resolve_target_check_silently(
        self,
        session: Session,
        target: MonitorTarget,
        check: TargetCheck,
        *,
        message: str,
        detach: bool = False,
    ) -> list[Incident]:
        """Resolve open incidents for one service check without recovery notifications."""
        incidents = session.scalars(
            select(Incident).where(
                Incident.target_id == target.id,
                Incident.check_id == check.id,
                Incident.status == IncidentStatus.OPEN,
                Incident.source_kind.in_(
                    (IncidentSourceKind.CHECK, IncidentSourceKind.CHECK_TLS)
                ),
            )
        ).all()
        observed_at = utc_now()
        for incident in incidents:
            incident.status = IncidentStatus.RESOLVED
            incident.resolved_at = observed_at
            incident.last_message = message
            if detach:
                incident.check_id = None
        return incidents

    def resolve_check_tls_silently(
        self,
        session: Session,
        target: MonitorTarget,
        check: TargetCheck,
        *,
        message: str,
    ) -> list[Incident]:
        """Resolve certificate-expiry incidents after an administrative change."""
        incidents = session.scalars(
            select(Incident).where(
                Incident.target_id == target.id,
                Incident.check_id == check.id,
                Incident.status == IncidentStatus.OPEN,
                Incident.source_kind == IncidentSourceKind.CHECK_TLS,
            )
        ).all()
        observed_at = utc_now()
        for incident in incidents:
            incident.status = IncidentStatus.RESOLVED
            incident.resolved_at = observed_at
            incident.last_message = message
        return incidents

    def apply_check_tls_health(
        self,
        session: Session,
        target: MonitorTarget,
        check: TargetCheck,
        evaluation: TlsEvaluation,
        *,
        observed_at,
    ) -> list[IncidentNotification]:
        """Apply fresh HTTPS certificate state without changing service availability."""
        incident = session.scalar(
            select(Incident)
            .where(
                Incident.target_id == target.id,
                Incident.check_id == check.id,
                Incident.status == IncidentStatus.OPEN,
                Incident.source_kind == IncidentSourceKind.CHECK_TLS,
            )
            .order_by(Incident.id.desc())
        )
        message = tls_reason(evaluation)
        events: list[IncidentNotification] = []
        if evaluation.health is TlsHealth.OK:
            if incident is not None:
                incident.status = IncidentStatus.RESOLVED
                incident.resolved_at = observed_at
                incident.last_message = message
                event = self._recovery_notification(session, target, incident)
                if event is not None:
                    events.append(event)
            return events

        severity = (
            IncidentSeverity.CRITICAL
            if evaluation.health is TlsHealth.CRITICAL
            else IncidentSeverity.WARNING
        )
        if incident is None:
            incident = Incident(
                target_id=target.id,
                check_id=check.id,
                status=IncidentStatus.OPEN,
                source_kind=IncidentSourceKind.CHECK_TLS,
                source_key=None,
                severity=severity,
                failure_count=1,
                opened_at=observed_at,
                last_failure_at=observed_at,
                last_message=message,
            )
            session.add(incident)
            session.flush()
            event = self._opening_notification(session, target, incident)
            if event is not None:
                events.append(event)
            return events

        previous_severity = incident.severity
        incident.failure_count += 1
        incident.last_failure_at = observed_at
        incident.last_message = message
        incident.severity = severity
        if (
            previous_severity == IncidentSeverity.WARNING
            and severity == IncidentSeverity.CRITICAL
            and not target.notifications_suppressed
        ):
            events.append(self._check_tls_notification(target, incident, escalation=True))
        return events

    @staticmethod
    def _check_message(check: TargetCheck, message: str | None) -> str:
        endpoint = check.effective_address
        if check.checker_type != "icmp":
            endpoint = f"{endpoint}:{check.port}"
        return f"{check.name} · {check.checker_type.upper()} · {endpoint}: {message or 'без сообщения'}"



    def set_source_state(
        self,
        session: Session,
        target: MonitorTarget,
        *,
        source_kind: IncidentSourceKind,
        source_key: str,
        severity: IncidentSeverity | None,
        message: str,
        observed_at,
        notify: bool = True,
    ) -> tuple[Incident | None, list[IncidentNotification]]:
        """Open/update/resolve one ordinary incident identified by source_key."""
        incident = session.scalar(
            select(Incident)
            .where(
                Incident.target_id == target.id,
                Incident.status == IncidentStatus.OPEN,
                Incident.source_kind == source_kind,
                Incident.source_key == source_key,
            )
            .order_by(Incident.id.desc())
        )
        events: list[IncidentNotification] = []

        if severity is None:
            if incident is None:
                return None, events
            incident.status = IncidentStatus.RESOLVED
            incident.resolved_at = observed_at
            incident.last_message = message
            if notify:
                event = self._recovery_notification(session, target, incident)
                if event is not None:
                    events.append(event)
            return incident, events

        if incident is None:
            incident = Incident(
                target_id=target.id,
                status=IncidentStatus.OPEN,
                source_kind=source_kind,
                source_key=source_key,
                severity=severity,
                failure_count=1,
                opened_at=observed_at,
                last_failure_at=observed_at,
                last_message=message,
            )
            session.add(incident)
            session.flush()
            if notify:
                event = self._opening_notification(session, target, incident)
                if event is not None:
                    events.append(event)
            return incident, events

        previous_severity = incident.severity
        incident.failure_count += 1
        incident.last_failure_at = observed_at
        incident.last_message = message
        incident.severity = severity

        # Warning -> Critical is an escalation of the same incident, not a new incident.
        # Emit one extra "opened" notification for the escalation; repeated Critical polls
        # remain deduplicated because severity no longer changes.
        if (
            notify
            and previous_severity == IncidentSeverity.WARNING
            and severity == IncidentSeverity.CRITICAL
            and not target.notifications_suppressed
        ):
            event = self._source_opening_notification(target, incident, escalation=True)
            if event is not None:
                events.append(event)
        return incident, events

    def resolve_source_silently(
        self,
        session: Session,
        target: MonitorTarget,
        *,
        source_kind: IncidentSourceKind,
        source_key: str,
        message: str,
        observed_at,
    ) -> Incident | None:
        incident, _events = self.set_source_state(
            session,
            target,
            source_kind=source_kind,
            source_key=source_key,
            severity=None,
            message=message,
            observed_at=observed_at,
            notify=False,
        )
        return incident

    @staticmethod
    def _source_opening_notification(
        target: MonitorTarget,
        incident: Incident,
        *,
        escalation: bool = False,
    ) -> IncidentNotification | None:
        severity = (
            "Critical"
            if incident.severity == IncidentSeverity.CRITICAL
            else "Warning"
        )
        prefix = "Повышен уровень" if escalation else "Открыт инцидент"
        return IncidentNotification(
            incident_id=incident.id,
            kind=IncidentEventKind.OPENED,
            notification=Notification(
                subject=f"[Мониторинг Maxval] SNMP {severity}: {target.name}",
                body=(
                    f"{prefix} #{incident.id}.\n\n"
                    f"Площадка: {target.site.name}\n"
                    f"Объект: {target.name}\n"
                    f"Уровень: {severity}\n"
                    f"{incident.last_message or 'Порог SNMP превышен'}\n"
                ),
            ),
        )

    @staticmethod
    def _confirmed_check_failure(
        session: Session, check_id: int, config_version: int
    ) -> bool:
        threshold = max(1, min(10, integer_setting(session, "failures_before_incident", 2)))
        statuses = session.scalars(
            select(TargetCheckResult.status)
            .where(
                TargetCheckResult.check_id == check_id,
                TargetCheckResult.config_version == config_version,
            )
            .order_by(TargetCheckResult.checked_at.desc(), TargetCheckResult.id.desc())
            .limit(threshold)
        ).all()
        return len(statuses) == threshold and all(
            status == CheckStatus.DOWN for status in statuses
        )

    @staticmethod
    def _confirmed_failure(session: Session, target_id: int) -> bool:
        threshold = max(1, min(10, integer_setting(session, "failures_before_incident", 2)))
        statuses = session.scalars(
            select(CheckResult.status)
            .where(CheckResult.target_id == target_id)
            .order_by(CheckResult.checked_at.desc(), CheckResult.id.desc())
            .limit(threshold)
        ).all()
        return len(statuses) == threshold and all(
            status == CheckStatus.DOWN for status in statuses
        )

    @staticmethod
    def _opening_notification(
        session: Session,
        target: MonitorTarget,
        incident: Incident,
    ) -> IncidentNotification | None:
        if (
            target.notifications_suppressed
            or incident.open_notification_attempted_at is not None
        ):
            return None
        incident.open_notification_attempted_at = utc_now()
        if incident.source_kind == IncidentSourceKind.SNMP:
            return IncidentService._source_opening_notification(target, incident)
        if incident.source_kind == IncidentSourceKind.CHECK_TLS:
            return IncidentService._check_tls_notification(target, incident)
        site_name = target.site.name
        if incident.source_kind == IncidentSourceKind.CHECK:
            check = session.get(TargetCheck, incident.check_id) if incident.check_id else None
            check_name = check.name if check is not None else "Дополнительная проверка"
            return IncidentNotification(
                incident_id=incident.id,
                kind=IncidentEventKind.OPENED,
                notification=Notification(
                    subject=f"[Мониторинг Maxval] Сервис недоступен: {target.name} · {check_name}",
                    body=(
                        f"Открыт инцидент #{incident.id}.\n\n"
                        f"Площадка: {site_name}\n"
                        f"Объект: {target.name}\n"
                        f"Проверка: {check_name}\n"
                        f"Неудачных проверок подряд: {incident.failure_count}\n"
                        f"Последняя ошибка: {incident.last_message or 'без сообщения'}\n"
                    ),
                ),
            )
        return IncidentNotification(
            incident_id=incident.id,
            kind=IncidentEventKind.OPENED,
            notification=Notification(
                subject=f"[Мониторинг Maxval] Недоступен: {target.name}",
                body=(
                    f"Открыт инцидент #{incident.id}.\n\n"
                    f"Площадка: {site_name}\n"
                    f"Объект: {target.name}\n"
                    f"Адрес: {target.address}:{target.port}\n"
                    f"Неудачных проверок подряд: {incident.failure_count}\n"
                    f"Последняя ошибка: {incident.last_message or 'без сообщения'}\n"
                ),
            ),
        )

    @staticmethod
    def _check_tls_notification(
        target: MonitorTarget,
        incident: Incident,
        *,
        escalation: bool = False,
    ) -> IncidentNotification:
        check_name = incident.check.name if incident.check is not None else "HTTPS"
        severity = "Critical" if incident.severity == IncidentSeverity.CRITICAL else "Warning"
        prefix = "Повышен уровень" if escalation else "Открыт инцидент"
        return IncidentNotification(
            incident_id=incident.id,
            kind=IncidentEventKind.OPENED,
            notification=Notification(
                subject=f"[Мониторинг Maxval] TLS {severity}: {target.name} · {check_name}",
                body=(
                    f"{prefix} #{incident.id}.\n\n"
                    f"Площадка: {target.site.name}\n"
                    f"Объект: {target.name}\n"
                    f"Проверка: {check_name}\n"
                    f"{incident.last_message or 'Срок сертификата требует внимания'}\n"
                ),
            ),
        )

    @staticmethod
    def _recovery_notification(
        session: Session,
        target: MonitorTarget,
        incident: Incident,
    ) -> IncidentNotification | None:
        already_attempted = incident.recovery_notification_attempted_at is not None
        if (
            target.notifications_suppressed
            or incident.open_notification_attempted_at is None
            or already_attempted
        ):
            return None
        incident.recovery_notification_attempted_at = utc_now()
        site_name = target.site.name
        if incident.source_kind == IncidentSourceKind.SNMP:
            return IncidentNotification(
                incident_id=incident.id,
                kind=IncidentEventKind.RECOVERED,
                notification=Notification(
                    subject=f"[Мониторинг Maxval] SNMP в норме: {target.name}",
                    body=(
                        f"SNMP-инцидент #{incident.id} закрыт.\n\n"
                        f"Площадка: {site_name}\n"
                        f"Объект: {target.name}\n"
                        f"{incident.last_message or 'Значение вернулось в норму'}\n"
                    ),
                ),
            )
        if incident.source_kind == IncidentSourceKind.CHECK_TLS:
            check_name = incident.check.name if incident.check is not None else "HTTPS"
            return IncidentNotification(
                incident_id=incident.id,
                kind=IncidentEventKind.RECOVERED,
                notification=Notification(
                    subject=f"[Мониторинг Maxval] TLS в норме: {target.name} · {check_name}",
                    body=(
                        f"TLS-инцидент #{incident.id} закрыт.\n\n"
                        f"Площадка: {site_name}\n"
                        f"Объект: {target.name}\n"
                        f"Проверка: {check_name}\n"
                        f"{incident.last_message or 'Срок сертификата снова в норме'}\n"
                    ),
                ),
            )
        if incident.source_kind == IncidentSourceKind.CHECK:
            check = session.get(TargetCheck, incident.check_id) if incident.check_id else None
            check_name = check.name if check is not None else "Дополнительная проверка"
            return IncidentNotification(
                incident_id=incident.id,
                kind=IncidentEventKind.RECOVERED,
                notification=Notification(
                    subject=f"[Мониторинг Maxval] Сервис восстановлен: {target.name} · {check_name}",
                    body=(
                        f"Инцидент #{incident.id} закрыт.\n\n"
                        f"Площадка: {site_name}\n"
                        f"Объект: {target.name}\n"
                        f"Проверка: {check_name}\n"
                        f"Всего неудачных проверок: {incident.failure_count}\n"
                    ),
                ),
            )
        return IncidentNotification(
            incident_id=incident.id,
            kind=IncidentEventKind.RECOVERED,
            notification=Notification(
                subject=f"[Мониторинг Maxval] Восстановлен: {target.name}",
                body=(
                    f"Инцидент #{incident.id} закрыт.\n\n"
                    f"Площадка: {site_name}\n"
                    f"Объект: {target.name}\n"
                    f"Адрес: {target.address}:{target.port}\n"
                    f"Всего неудачных проверок: {incident.failure_count}\n"
                ),
            ),
        )
