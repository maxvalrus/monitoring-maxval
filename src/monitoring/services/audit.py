import json
from typing import Any

from sqlalchemy.orm import Session

from monitoring.models import AuditLog

ENTITY_NAME_KEY = "_entity_name"


def write_audit(
    session: Session,
    action: str,
    *,
    user_id: int | None = None,
    entity_type: str | None = None,
    entity_id: str | int | None = None,
    entity_name: str | None = None,
    details: dict[str, Any] | None = None,
    ip_address: str | None = None,
) -> AuditLog:
    payload = dict(details or {})
    if entity_name:
        payload[ENTITY_NAME_KEY] = str(entity_name)
    entry = AuditLog(
        user_id=user_id,
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id) if entity_id is not None else None,
        details=json.dumps(payload, ensure_ascii=False, sort_keys=True) if payload else None,
        ip_address=ip_address,
    )
    session.add(entry)
    return entry


def audit_changes(before: dict[str, Any], after: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return only changed fields in an audit-friendly old/new shape."""
    return {
        key: {"old": before.get(key), "new": after.get(key)}
        for key in sorted(before.keys() | after.keys())
        if before.get(key) != after.get(key)
    }


ACTION_LABELS = {
    "auth.login_success": "Успешный вход",
    "auth.login_failed": "Неудачный вход",
    "auth.login_blocked": "Заблокированная попытка входа",
    "auth.block_created": "Создана блокировка входа",
    "auth.logout": "Выход из системы",
    "auth.block_removed": "Снята блокировка входа",
    "user.created": "Создание пользователя",
    "user.updated": "Обновление пользователя",
    "user.deleted": "Удаление пользователя",
    "user.password_changed": "Смена пароля пользователя",
    "user.unblocked": "Разблокировка пользователя",
    "site.created": "Создание площадки",
    "site.updated": "Обновление площадки",
    "site.deleted": "Удаление площадки",
    "site.enabled_changed": "Изменение состояния площадки",
    "site.display_order_changed": "Изменение порядка площадки",
    "site.targets_deleted": "Удаление объектов площадки",
    "target.created": "Создание объекта",
    "target.cloned": "Копирование объекта",
    "target.updated": "Обновление объекта",
    "target.deleted": "Удаление объекта",
    "target.enabled_changed": "Изменение состояния объекта",
    "target.favorite_changed": "Изменение избранного объекта",
    "target.display_order_changed": "Изменение порядка объекта",
    "target_check.created": "Добавление проверки объекта",
    "target_check.updated": "Изменение проверки объекта",
    "target_check.enabled_changed": "Изменение состояния проверки объекта",
    "target_check.deleted": "Удаление проверки объекта",
    "incident.deleted": "Удаление инцидента",
    "incident.resolved_deleted": "Удаление закрытых инцидентов",
    "incident.cleared": "Очистка инцидентов",
    "incident.all_deleted": "Очистка всех инцидентов",
    "setting.updated": "Изменение настройки",
    "setting.smtp_updated": "Изменение SMTP-настроек",
    "schedule.created": "Создание графика работы",
    "schedule.updated": "Обновление графика работы",
    "schedule.deleted": "Удаление графика работы",
    "check.manual_started": "Запуск общего ручного опроса",
    "check.manual_already_running": "Повторный запуск общего ручного опроса",
    "check.target_manual": "Ручная проверка объекта",
    "notification.email_sent": "Отправка уведомления",
    "notification.email_failed": "Ошибка отправки уведомления",
    "notification.test_sent": "Отправка тестового письма",
    "notification.test_failed": "Ошибка тестового письма",
    "chat.deletion_requested": "Запрос очистки истории чата",
    "chat.deletion_confirmed": "Очистка истории чата",
    "chat.deletion_rejected": "Отклонение очистки истории чата",
    "chat.history_restored": "Восстановление скрытой истории чата",
    "notification.preferences_updated": "Изменение настроек Push",
    "push.test_sent": "Отправка тестового Push",
    "push.test_failed": "Ошибка тестового Push",
    "push.subscription_deleted": "Удаление Push-подписки",
    "https.redirect_disabled_expiring_certificate": (
        "Автоматическое отключение HTTP → HTTPS из-за срока сертификата"
    ),
    "snmp.settings_updated": "Изменение настроек SNMP",
    "snmp.metric_created": "Добавление SNMP OID",
    "snmp.metric_updated": "Изменение SNMP OID",
    "snmp.metric_deleted": "Удаление SNMP OID",
    "snmp.metric_order_changed": "Изменение порядка SNMP OID",
    "snmp.data_cleared": "Очистка SNMP-данных",
    "snmp.tested": "Проверка SNMP",
    "snmp.interfaces_discovered": "Обнаружение SNMP-интерфейсов",
    "snmp.supplies_discovered": "Обнаружение расходников Printer-MIB",
    "snmp.supply_name_updated": "Изменение имени расходника Printer-MIB",
    "snmp.interfaces_selection_changed": "Изменение мониторинга SNMP-интерфейсов",
    "snmp.threshold_created": "Добавление SNMP-порога",
    "snmp.threshold_updated": "Изменение SNMP-порога",
    "snmp.threshold_toggled": "Изменение состояния SNMP-порога",
    "snmp.threshold_deleted": "Удаление SNMP-порога",
    "backup.created": "Создание резервной копии",
    "backup.deleted": "Удаление резервной копии",
    "backup.restored": "Восстановление резервной копии",
    "database.integrity_checked": "Проверка целостности базы",
}

ENTITY_LABELS = {
    "user": "Пользователь",
    "site": "Площадка",
    "target": "Объект",
    "target_check": "Проверка объекта",
    "monitor_target": "Объект",
    "incident": "Инцидент",
    "setting": "Настройка",
    "work_schedule": "График работы",
    "schedule": "График работы",
    "monitoring": "Мониторинг",
    "login_block": "Блокировка входа",
    "backup": "Резервная копия",
    "database": "База данных",
    "username": "Логин",
    "chat_message": "Сообщение чата",
    "push_subscription": "Push-подписка",
    "snmp": "SNMP",
    "snmp_supply": "SNMP-расходник",
}

FIELD_LABELS = {
    "name": "Название",
    "description": "Описание",
    "schedule": "График работы",
    "work_schedule_id": "ID графика работы",
    "username": "Логин",
    "role": "Роль",
    "active": "Активен",
    "enabled": "Включён",
    "comment": "Комментарий",
    "value": "Значение",
    "status": "Статус",
    "latency_ms": "Задержка, мс",
    "message": "Сообщение",
    "off_hours": "Вне рабочего времени",
    "kind": "Тип",
    "address": "Адрес",
    "port": "Порт",
    "interval_seconds": "Интервал, сек.",
    "favorite": "Избранный",
    "notifications_suppressed": "Без уведомлений",
    "backup_type": "Тип бэкапа",
    "creation_mode": "Способ создания",
    "filename": "Файл",
    "compatible": "Совместимость",
    "issues": "Проблемы",
    "checks": "Проверок",
    "recipient_id": "ID получателя",
    "notification_id": "ID оповещения",
    "request_id": "ID запроса",
    "restored_requests": "Восстановлено запросов",
    "cutoff_at": "История удалена до",
    "push_chat": "Push: сообщения чата",
    "push_incident": "Push: новые инциденты",
    "push_recovery": "Push: восстановления",
    "timeout_seconds": "Timeout, сек.",
    "checker_type": "Метод проверки",
    "address_override": "Адрес override",
    "path": "Путь",
    "retries": "Повторы",
    "oid": "OID",
    "custom_name": "Пользовательское имя",
    "unit": "Единица измерения",
}
ROLE_LABELS = {
    "admin": "Администратор",
    "viewer": "Наблюдатель",
    "configuration": "Конфигурация",
    "full": "Полная",
    "manual": "Ручная",
    "automatic": "Автоматическая",
}


def _details_payload(details: str | None) -> dict[str, Any] | None:
    if not details:
        return None
    try:
        payload = json.loads(details)
    except (TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def audit_entity_name(details: str | None) -> str | None:
    payload = _details_payload(details)
    if not payload:
        return None
    value = payload.get(ENTITY_NAME_KEY)
    return str(value) if value not in {None, ""} else None


def _display_scalar(value) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "да" if value else "нет"
    if isinstance(value, dict):
        if "name" in value:
            label = str(value.get("name") or "—")
            if value.get("id") is not None:
                return f"{label} (ID {value['id']})"
            return label
        return ", ".join(
            f"{FIELD_LABELS.get(str(k), k)}: {_display_scalar(v)}"
            for k, v in value.items()
            if str(k) != ENTITY_NAME_KEY
        )
    if isinstance(value, list):
        return ", ".join(_display_scalar(v) for v in value) or "—"
    text = str(value)
    return ROLE_LABELS.get(text, text)


def format_audit_details(details: str | None) -> list[str]:
    if not details:
        return ["Подробности не указаны"]
    try:
        payload = json.loads(details)
    except (TypeError, ValueError):
        return [details]
    if not isinstance(payload, dict):
        return [_display_scalar(payload)]
    lines: list[str] = []
    for key, value in payload.items():
        if str(key) == ENTITY_NAME_KEY:
            continue
        label = FIELD_LABELS.get(str(key), str(key))
        if isinstance(value, dict) and "old" in value and "new" in value:
            lines.append(
                f"{label}: {_display_scalar(value.get('old'))} → {_display_scalar(value.get('new'))}"
            )
        else:
            lines.append(f"{label}: {_display_scalar(value)}")
    return lines or ["Подробности не указаны"]


def audit_details_for_table(details: str | None) -> str:
    """Return raw-looking details for the compact table, without internal metadata."""
    if not details:
        return ""
    try:
        payload = json.loads(details)
    except (TypeError, ValueError):
        return details
    if isinstance(payload, dict):
        payload.pop(ENTITY_NAME_KEY, None)
        return json.dumps(payload, ensure_ascii=False, sort_keys=True) if payload else ""
    return details


def format_audit_entry_text(entry, username: str | None, display_datetime) -> str:
    action_label = ACTION_LABELS.get(entry.action, "Неизвестное событие")
    lines = [
        f"Событие: {action_label}",
        f"Код события: {entry.action}",
        f"Время: {display_datetime(entry.created_at)}",
        f"Инициатор: {username or 'система'}",
    ]
    if entry.entity_type or entry.entity_id:
        entity_label = ENTITY_LABELS.get(entry.entity_type or "", entry.entity_type or "Сущность")
        name = audit_entity_name(entry.details)
        entity_text = entity_label
        if name:
            entity_text += f" {name}"
        if entry.entity_id:
            entity_text += f" · ID {entry.entity_id}"
        lines.append(f"Объект изменения: {entity_text}")
    if entry.ip_address:
        lines.append(f"IP: {entry.ip_address}")
    lines.append("")
    if entry.action in {"chat.deletion_requested", "chat.deletion_confirmed", "chat.deletion_rejected"}:
        payload = _details_payload(entry.details) or {}
        cutoff = payload.get("cutoff_at")
        if cutoff:
            try:
                from datetime import datetime
                cutoff_value = datetime.fromisoformat(str(cutoff).replace("Z", "+00:00"))
                lines.append(f"История удалена до: {display_datetime(cutoff_value)}")
            except (TypeError, ValueError):
                lines.append(f"История удалена до: {cutoff}")
        if payload.get("request_id") is not None:
            lines.append(f"ID запроса: {payload['request_id']}")
        if len(lines) and lines[-1] == "":
            lines.append("Подробности не указаны")
    else:
        lines.extend(format_audit_details(entry.details))
    return "\n".join(lines)
