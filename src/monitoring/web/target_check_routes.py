from __future__ import annotations

from typing import Annotated
from urllib.parse import urlsplit

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from monitoring.checks import checker_registry
from monitoring.config import get_settings
from monitoring.models import MonitorTarget, TargetCheck
from monitoring.services.audit import write_audit
from monitoring.services.directory_monitoring import (
    DIRECTORY_CHECKER_TYPE,
    clear_directory_fields,
    clear_directory_runtime,
    normalize_directory_fields,
)
from monitoring.services.dns_monitoring import normalize_dns_fields
from monitoring.services.incidents import IncidentService
from monitoring.services.secrets import encrypt_secret
from monitoring.services.target_checks import (
    check_execution_signature,
    duplicate_check_name_exists,
    ensure_check_capacity,
    next_check_display_order,
    normalize_check_fields,
    normalize_http_deep_fields,
    normalize_tls_monitoring,
)
from monitoring.services.unstable_link import reset_unstable_link
from monitoring.web.admin_routes import redirect_with, require_csrf, safe_return_path
from monitoring.web.dependencies import AdminAuth, DbSession
from monitoring.web.security import client_ip

router = APIRouter()
incident_service = IncidentService()


def _parse_optional_int(value: str) -> int | None:
    clean = value.strip()
    return int(clean) if clean else None


def _parse_optional_float(value: str) -> float | None:
    clean = value.strip()
    return float(clean) if clean else None


def _destination(target_id: int, return_to: str) -> str:
    history_path = f"/targets/{target_id}/history"
    if urlsplit(return_to).path == history_path:
        return safe_return_path(return_to, history_path)
    return safe_return_path(return_to, "/targets")


@router.post("/targets/{target_id}/checks/current-http-status")
async def target_check_current_http_status(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
) -> JSONResponse:
    """Return the response code for the endpoint currently entered in the form."""
    form = await request.form()
    require_csrf(auth, str(form.get("csrf_token", "")))
    target = session.get(MonitorTarget, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Объект не найден")
    try:
        (
            _name,
            checker_type,
            address_override,
            port,
            path,
            timeout_seconds,
            _retries,
        ) = normalize_check_fields(
            checker_registry,
            name="Получение HTTP-кода",
            checker_type=str(form.get("checker_type", "")),
            address_override=str(form.get("address_override", "")),
            port=_parse_optional_int(str(form.get("port", ""))),
            path=str(form.get("path", "/")),
            timeout_seconds=_parse_optional_float(str(form.get("timeout_seconds", ""))),
            retries=0,
        )
        if checker_type not in {"http", "https"}:
            raise ValueError("Текущий код можно получить только для HTTP или HTTPS")
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    scheduler = getattr(request.app.state, "scheduler", None)
    if scheduler is None:
        raise HTTPException(status_code=503, detail="Сервис проверок ещё не готов")
    outcome = await scheduler.monitoring.probe_http_status(
        checker_type=checker_type,
        address=address_override or target.address,
        port=port,
        path=path,
        timeout_seconds=timeout_seconds,
    )
    if outcome.http_status_code is None:
        raise HTTPException(
            status_code=502,
            detail=outcome.message or "Не удалось получить HTTP-код",
        )
    return JSONResponse(
        {
            "status_code": outcome.http_status_code,
            "latency_ms": outcome.latency_ms,
        }
    )


@router.post("/targets/{target_id}/checks")
def target_check_create(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    name: Annotated[str, Form()],
    checker_type: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
    address_override: Annotated[str, Form()] = "",
    port: Annotated[str, Form()] = "",
    path: Annotated[str, Form()] = "/",
    timeout_seconds: Annotated[str, Form()] = "",
    retries: Annotated[int, Form()] = 0,
    expected_status: Annotated[str, Form()] = "",
    content_contains: Annotated[str, Form()] = "",
    content_not_contains: Annotated[str, Form()] = "",
    max_response_ms: Annotated[str, Form()] = "",
    tls_monitor_enabled: Annotated[str, Form()] = "",
    tls_warning_days: Annotated[str, Form()] = "",
    tls_critical_days: Annotated[str, Form()] = "",
    dns_name: Annotated[str, Form()] = "",
    dns_record_type: Annotated[str, Form()] = "A",
    dns_expected_address: Annotated[str, Form()] = "",
    dns_max_response_ms: Annotated[str, Form()] = "",
    directory_path: Annotated[str, Form()] = "",
    directory_pattern: Annotated[str, Form()] = "*",
    directory_period_hours: Annotated[str, Form()] = "24",
    directory_show_last: Annotated[str, Form()] = "0",
    directory_username: Annotated[str, Form()] = "",
    directory_password: Annotated[str, Form()] = "",
    return_to: Annotated[str, Form()] = "",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    target = session.get(MonitorTarget, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Объект не найден")
    destination = _destination(target.id, return_to)
    try:
        ensure_check_capacity(session, target.id)
        fields = normalize_check_fields(
            checker_registry,
            name=name,
            checker_type=checker_type,
            address_override=address_override,
            port=_parse_optional_int(port),
            path=path,
            timeout_seconds=_parse_optional_float(timeout_seconds),
            retries=retries,
        )
        clean_name, clean_type, clean_address, clean_port, clean_path, clean_timeout, clean_retries = fields
        http_fields = normalize_http_deep_fields(
            checker_type=clean_type,
            expected_status=_parse_optional_int(expected_status),
            content_contains=content_contains,
            content_not_contains=content_not_contains,
            max_response_ms=_parse_optional_float(max_response_ms),
        )
        (
            http_expected_status,
            http_content_contains,
            http_content_not_contains,
            http_max_response_ms,
        ) = http_fields
        tls_fields = normalize_tls_monitoring(
            checker_type=clean_type,
            enabled=tls_monitor_enabled == "true",
            warning_days=_parse_optional_int(tls_warning_days),
            critical_days=_parse_optional_int(tls_critical_days),
        )
        tls_enabled, tls_warning, tls_critical = tls_fields
        dns_fields = normalize_dns_fields(
            checker_type=clean_type,
            name=dns_name,
            record_type=dns_record_type,
            expected_address=dns_expected_address,
            max_response_ms=_parse_optional_float(dns_max_response_ms),
        )
        dns_clean_name, dns_record, dns_expected, dns_max = dns_fields
        directory = normalize_directory_fields(
            checker_type=clean_type,
            path=directory_path,
            pattern=directory_pattern,
            period_hours=_parse_optional_float(directory_period_hours),
            show_last=_parse_optional_int(directory_show_last),
            username=directory_username,
        )
        if directory is not None and directory_password and directory.username is None:
            raise ValueError("Пароль SMB можно указать только вместе с пользователем")
        if duplicate_check_name_exists(
            session, target_id=target.id, name=clean_name
        ):
            raise ValueError("Проверка с таким названием уже существует")
    except (TypeError, ValueError) as exc:
        return redirect_with(destination, "error", str(exc))
    check = TargetCheck(
        target_id=target.id,
        name=clean_name,
        checker_type=clean_type,
        address_override=clean_address,
        port=clean_port,
        path=clean_path,
        timeout_seconds=clean_timeout,
        retries=clean_retries,
        enabled=True,
        is_primary=False,
        display_order=next_check_display_order(session, target.id),
        http_expected_status=http_expected_status,
        http_content_contains=http_content_contains,
        http_content_not_contains=http_content_not_contains,
        http_max_response_ms=http_max_response_ms,
        tls_monitor_enabled=tls_enabled,
        tls_warning_days=tls_warning,
        tls_critical_days=tls_critical,
        dns_name=dns_clean_name,
        dns_record_type=dns_record,
        dns_expected_address=dns_expected,
        dns_max_response_ms=dns_max,
    )
    if directory is not None:
        check.directory_path = directory.path
        check.directory_pattern = directory.pattern
        check.directory_period_hours = directory.period_hours
        check.directory_show_last = directory.show_last
        check.directory_username = directory.username
        if directory.username is None:
            check.directory_password_encrypted = ""
        elif directory_password:
            check.directory_password_encrypted = encrypt_secret(
                get_settings(), directory_password
            )
    session.add(check)
    session.flush()
    write_audit(
        session,
        "target_check.created",
        user_id=auth.user.id,
        entity_type="target_check",
        entity_id=check.id,
        entity_name=check.name,
        details={
            "target_id": target.id,
            "checker_type": check.checker_type,
            "address_override": check.address_override,
            "port": check.port,
            "path": check.path,
            "timeout_seconds": check.timeout_seconds,
            "retries": check.retries,
            "http_deep_check": {
                "expected_status": check.http_expected_status,
                "content_contains": check.http_content_contains,
                "content_not_contains": check.http_content_not_contains,
                "max_response_ms": check.http_max_response_ms,
            },
            "tls_monitoring": {
                "enabled": check.tls_monitor_enabled,
                "warning_days": check.tls_warning_days,
                "critical_days": check.tls_critical_days,
            },
            "dns_monitoring": {
                "name": check.dns_name,
                "record_type": check.dns_record_type,
                "expected_address": check.dns_expected_address,
                "max_response_ms": check.dns_max_response_ms,
            },
            "directory": {
                "path": check.directory_path,
                "pattern": check.directory_pattern,
                "period_hours": check.directory_period_hours,
                "show_last": check.directory_show_last,
                "username": check.directory_username,
                "password_configured": bool(check.directory_password_encrypted),
            },
        },
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(destination, "notice", "Сервис добавлен")


@router.post("/targets/{target_id}/checks/{check_id}/update")
def target_check_update(
    target_id: int,
    check_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    name: Annotated[str, Form()],
    checker_type: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
    address_override: Annotated[str, Form()] = "",
    port: Annotated[str, Form()] = "",
    path: Annotated[str, Form()] = "/",
    timeout_seconds: Annotated[str, Form()] = "",
    retries: Annotated[int, Form()] = 0,
    expected_status: Annotated[str, Form()] = "",
    content_contains: Annotated[str, Form()] = "",
    content_not_contains: Annotated[str, Form()] = "",
    max_response_ms: Annotated[str, Form()] = "",
    tls_monitor_enabled: Annotated[str, Form()] = "",
    tls_warning_days: Annotated[str, Form()] = "",
    tls_critical_days: Annotated[str, Form()] = "",
    dns_name: Annotated[str, Form()] = "",
    dns_record_type: Annotated[str, Form()] = "A",
    dns_expected_address: Annotated[str, Form()] = "",
    dns_max_response_ms: Annotated[str, Form()] = "",
    directory_path: Annotated[str, Form()] = "",
    directory_pattern: Annotated[str, Form()] = "*",
    directory_period_hours: Annotated[str, Form()] = "24",
    directory_show_last: Annotated[str, Form()] = "0",
    directory_username: Annotated[str, Form()] = "",
    directory_password: Annotated[str, Form()] = "",
    return_to: Annotated[str, Form()] = "",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    check = session.get(TargetCheck, check_id)
    if check is None or check.target_id != target_id:
        raise HTTPException(status_code=404, detail="Проверка не найдена")
    destination = _destination(target_id, return_to)
    if check.is_primary:
        return redirect_with(
            destination,
            "error",
            "Основная проверка изменяется в настройках объекта",
        )
    try:
        fields = normalize_check_fields(
            checker_registry,
            name=name,
            checker_type=checker_type,
            address_override=address_override,
            port=_parse_optional_int(port),
            path=path,
            timeout_seconds=_parse_optional_float(timeout_seconds),
            retries=retries,
        )
        clean_name, clean_type, clean_address, clean_port, clean_path, clean_timeout, clean_retries = fields
        http_fields = normalize_http_deep_fields(
            checker_type=clean_type,
            expected_status=_parse_optional_int(expected_status),
            content_contains=content_contains,
            content_not_contains=content_not_contains,
            max_response_ms=_parse_optional_float(max_response_ms),
        )
        (
            http_expected_status,
            http_content_contains,
            http_content_not_contains,
            http_max_response_ms,
        ) = http_fields
        tls_fields = normalize_tls_monitoring(
            checker_type=clean_type,
            enabled=tls_monitor_enabled == "true",
            warning_days=_parse_optional_int(tls_warning_days),
            critical_days=_parse_optional_int(tls_critical_days),
        )
        tls_enabled, tls_warning, tls_critical = tls_fields
        dns_clean_name, dns_record, dns_expected, dns_max = normalize_dns_fields(
            checker_type=clean_type,
            name=dns_name,
            record_type=dns_record_type,
            expected_address=dns_expected_address,
            max_response_ms=_parse_optional_float(dns_max_response_ms),
        )
        directory = normalize_directory_fields(
            checker_type=clean_type,
            path=directory_path,
            pattern=directory_pattern,
            period_hours=_parse_optional_float(directory_period_hours),
            show_last=_parse_optional_int(directory_show_last),
            username=directory_username,
        )
        if directory is not None and directory_password and directory.username is None:
            raise ValueError("Пароль SMB можно указать только вместе с пользователем")
        if duplicate_check_name_exists(
            session,
            target_id=target_id,
            name=clean_name,
            exclude_check_id=check.id,
        ):
            raise ValueError("Проверка с таким названием уже существует")
    except (TypeError, ValueError) as exc:
        return redirect_with(destination, "error", str(exc))
    before = {
        "name": check.name,
        "checker_type": check.checker_type,
        "address_override": check.address_override,
        "port": check.port,
        "path": check.path,
        "timeout_seconds": check.timeout_seconds,
        "retries": check.retries,
        "http_expected_status": check.http_expected_status,
        "http_content_contains": check.http_content_contains,
        "http_content_not_contains": check.http_content_not_contains,
        "http_max_response_ms": check.http_max_response_ms,
        "tls_monitor_enabled": check.tls_monitor_enabled,
        "tls_warning_days": check.tls_warning_days,
        "tls_critical_days": check.tls_critical_days,
        "dns_name": check.dns_name,
        "dns_record_type": check.dns_record_type,
        "dns_expected_address": check.dns_expected_address,
        "dns_max_response_ms": check.dns_max_response_ms,
        "directory_path": check.directory_path,
        "directory_pattern": check.directory_pattern,
        "directory_period_hours": check.directory_period_hours,
        "directory_show_last": check.directory_show_last,
        "directory_username": check.directory_username,
        "directory_password_configured": bool(check.directory_password_encrypted),
        "config_version": check.config_version,
    }
    execution_before = check_execution_signature(check)
    tls_was_enabled = check.tls_monitor_enabled
    previous_checker_type = check.checker_type
    check.name = clean_name
    check.checker_type = clean_type
    check.address_override = clean_address
    check.port = clean_port
    check.path = clean_path
    check.timeout_seconds = clean_timeout
    check.retries = clean_retries
    check.http_expected_status = http_expected_status
    check.http_content_contains = http_content_contains
    check.http_content_not_contains = http_content_not_contains
    check.http_max_response_ms = http_max_response_ms
    check.tls_monitor_enabled = tls_enabled
    check.tls_warning_days = tls_warning
    check.tls_critical_days = tls_critical
    check.dns_name = dns_clean_name
    check.dns_record_type = dns_record
    check.dns_expected_address = dns_expected
    check.dns_max_response_ms = dns_max
    if directory is None:
        clear_directory_fields(check)
    else:
        check.directory_path = directory.path
        check.directory_pattern = directory.pattern
        check.directory_period_hours = directory.period_hours
        check.directory_show_last = directory.show_last
        check.directory_username = directory.username
        if directory.username is None:
            check.directory_password_encrypted = ""
        elif directory_password:
            check.directory_password_encrypted = encrypt_secret(
                get_settings(), directory_password
            )
    if check_execution_signature(check) != execution_before:
        check.config_version += 1
        reset_unstable_link(check)
        if check.checker_type == DIRECTORY_CHECKER_TYPE:
            clear_directory_runtime(check)
    if (
        (tls_was_enabled and not check.tls_monitor_enabled)
        or (previous_checker_type == "https" and check.checker_type != "https")
    ):
        target = session.get(MonitorTarget, target_id)
        if target is not None:
            incident_service.resolve_check_tls_silently(
                session,
                target,
                check,
                message=f"Контроль TLS для «{check.name}» отключён администратором",
            )
    write_audit(
        session,
        "target_check.updated",
        user_id=auth.user.id,
        entity_type="target_check",
        entity_id=check.id,
        entity_name=check.name,
        details={
            "before": before,
            "target_id": target_id,
            "after_http_deep_check": {
                "expected_status": check.http_expected_status,
                "content_contains": check.http_content_contains,
                "content_not_contains": check.http_content_not_contains,
                "max_response_ms": check.http_max_response_ms,
            },
            "after_tls_monitoring": {
                "enabled": check.tls_monitor_enabled,
                "warning_days": check.tls_warning_days,
                "critical_days": check.tls_critical_days,
            },
            "after_dns_monitoring": {
                "name": check.dns_name,
                "record_type": check.dns_record_type,
                "expected_address": check.dns_expected_address,
                "max_response_ms": check.dns_max_response_ms,
            },
            "after_directory": {
                "path": check.directory_path,
                "pattern": check.directory_pattern,
                "period_hours": check.directory_period_hours,
                "show_last": check.directory_show_last,
                "username": check.directory_username,
                "password_configured": bool(check.directory_password_encrypted),
            },
        },
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(destination, "notice", "Сервис сохранён")


@router.post("/targets/{target_id}/checks/{check_id}/toggle")
def target_check_toggle(
    target_id: int,
    check_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    check = session.get(TargetCheck, check_id)
    if check is None or check.target_id != target_id:
        raise HTTPException(status_code=404, detail="Проверка не найдена")
    destination = _destination(target_id, return_to)
    if check.is_primary:
        return redirect_with(destination, "error", "Основную проверку нельзя отключить отдельно")
    target = session.get(MonitorTarget, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Объект не найден")
    check.enabled = not check.enabled
    check.config_version += 1
    reset_unstable_link(check)
    if not check.enabled:
        incident_service.resolve_target_check_silently(
            session,
            target,
            check,
            message=f"Проверка «{check.name}» отключена администратором",
        )
    write_audit(
        session,
        "target_check.enabled_changed",
        user_id=auth.user.id,
        entity_type="target_check",
        entity_id=check.id,
        entity_name=check.name,
        details={"enabled": check.enabled, "target_id": target_id},
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(destination, "notice", "Состояние сервиса изменено")


@router.post("/targets/{target_id}/checks/{check_id}/delete")
def target_check_delete(
    target_id: int,
    check_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    check = session.get(TargetCheck, check_id)
    if check is None or check.target_id != target_id:
        raise HTTPException(status_code=404, detail="Проверка не найдена")
    destination = _destination(target_id, return_to)
    if check.is_primary:
        return redirect_with(destination, "error", "Основную проверку удалить нельзя")
    name = check.name
    target = session.get(MonitorTarget, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Объект не найден")
    incident_service.resolve_target_check_silently(
        session,
        target,
        check,
        message=f"Проверка «{name}» удалена администратором",
        detach=True,
    )
    write_audit(
        session,
        "target_check.deleted",
        user_id=auth.user.id,
        entity_type="target_check",
        entity_id=check.id,
        entity_name=name,
        details={"target_id": target_id},
        ip_address=client_ip(request),
    )
    session.delete(check)
    session.commit()
    return redirect_with(destination, "notice", "Сервис удалён")
