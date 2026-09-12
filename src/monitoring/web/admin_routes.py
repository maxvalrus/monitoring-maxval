import json
from typing import Annotated
from urllib.parse import parse_qsl, urlencode, urlsplit

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import delete, exists, func, or_, select
from sqlalchemy.orm import aliased

from monitoring.checks import checker_registry
from monitoring.config import get_settings
from monitoring.models import (
    AuditLog,
    CheckResult,
    FailedLoginAttempt,
    Incident,
    LoginBlock,
    MonitorTarget,
    Site,
    SnmpConfig,
    SnmpMetric,
    SnmpSample,
    TargetCheck,
    TargetKind,
    User,
    UserRole,
    WorkSchedule,
)
from monitoring.services.audit import (
    audit_changes,
    audit_details_for_table,
    audit_entity_name,
    format_audit_entry_text,
    write_audit,
)
from monitoring.services.auth import (
    create_user,
    get_min_password_length,
    hash_password,
    revoke_user_sessions,
    utc_now,
    validate_password,
)
from monitoring.services.backups import (
    BackupError,
    check_database_integrity,
    create_backup,
    delete_backup_file,
    inspect_backup,
    restore_backup,
    safe_stored_backup_path,
    save_uploaded_backup,
    staged_backup_path,
)
from monitoring.services.communication import cleanup_deleted_user_communication
from monitoring.services.exports import xlsx_bytes
from monitoring.services.pagination import Pagination, SortState, positive_int
from monitoring.services.scheduler import CheckScheduler
from monitoring.services.site_entry import (
    ENTRY_TARGET_KINDS,
    normalize_site_entry_for_kind,
    set_site_entry,
)
from monitoring.services.site_order import move_site, next_site_display_order
from monitoring.services.target_checks import (
    primary_checker_names,
    secondary_checker_names,
    sync_target_primary_check,
)
from monitoring.services.target_clone import clone_target_configuration
from monitoring.services.target_order import move_target, move_to_group_end, next_display_order
from monitoring.services.time_display import session_datetime_formatter
from monitoring.services.unstable_link import reset_unstable_link
from monitoring.services.work_schedules import (
    DAY_ABBREVIATIONS,
    DAY_FIELDS,
    schedule_is_working,
    schedule_summary,
    schedule_timezone,
    validate_schedule_values,
)
from monitoring.web.dependencies import AdminAuth, CurrentAuth, DbSession, template_context
from monitoring.web.routes import templates
from monitoring.web.security import (
    client_ip,
    delete_session_cookie,
    session_cookie_name,
    verify_session_csrf,
)

router = APIRouter()


def require_csrf(auth: CurrentAuth, submitted: str) -> None:
    if not verify_session_csrf(auth.user_session.csrf_token, submitted):
        raise HTTPException(status_code=400, detail="Недействительный CSRF-токен")


@router.post("/checks/run-now")
async def checks_run_now(
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "/",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    requested_path = urlsplit(return_to).path
    # The TV wallboard invokes the same audited batch operation as the ordinary
    # dashboard, but must remain on its dedicated display after the POST.
    destination = safe_return_path(
        return_to,
        "/wallboard" if requested_path == "/wallboard" else "/",
    )
    scheduler: CheckScheduler | None = getattr(request.app.state, "scheduler", None)
    if scheduler is None:
        return redirect_with(
            destination,
            "error",
            "Сервис проверок ещё не готов",
        )
    started = scheduler.trigger_all()
    write_audit(
        session,
        "check.manual_started" if started else "check.manual_already_running",
        user_id=auth.user.id,
        entity_type="monitoring",
        ip_address=client_ip(request),
    )
    session.commit()
    message = (
        "Внеочередная проверка запущена. Обновите страницу через несколько секунд"
        if started
        else "Внеочередная проверка уже выполняется"
    )
    return redirect_with(destination, "notice", message)



@router.post("/checks/targets/{target_id}/run-now")
async def target_check_run_now(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "/",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    scheduler: CheckScheduler | None = getattr(request.app.state, "scheduler", None)
    parsed_return = urlsplit(return_to)
    history_path = f"/targets/{target_id}/history"
    snmp_path = f"/targets/{target_id}/snmp"
    fallback = (
        parsed_return.path
        if parsed_return.path in {"/", "/targets", history_path, snmp_path}
        else "/targets"
    )
    destination = safe_return_path(return_to, fallback)
    if scheduler is None:
        return redirect_with(destination, "error", "Сервис проверок ещё не готов")
    try:
        result = await scheduler.run_target_now(target_id)
    except LookupError as exc:
        return redirect_with(destination, "error", str(exc))
    target = session.get(MonitorTarget, target_id)
    write_audit(
        session,
        "check.target_manual",
        user_id=auth.user.id,
        entity_type="monitor_target",
        entity_id=target_id,
        entity_name=target.name if target is not None else None,
        details={
            "status": result.status,
            "latency_ms": result.latency_ms,
            "message": result.message,
            "off_hours": result.off_hours,
            "saved_to_history": result.saved,
        },
        ip_address=client_ip(request),
    )
    session.commit()
    status_label = {"up": "доступен", "down": "недоступен", "unknown": "нет данных"}.get(
        result.status, result.status
    )
    suffix = " Результат диагностический и не записан в статистику." if result.off_hours else ""
    latency = f" · {result.latency_ms:.1f} мс" if result.latency_ms is not None else ""
    return redirect_with(
        destination,
        "notice",
        f"Проверка объекта завершена: {status_label}{latency}.{suffix}".strip(),
    )


def redirect_with(path: str, parameter: str, message: str) -> RedirectResponse:
    parsed = urlsplit(path)
    parameters = dict(parse_qsl(parsed.query, keep_blank_values=True))
    parameters.pop("notice", None)
    parameters.pop("error", None)
    parameters[parameter] = message
    return RedirectResponse(
        f"{parsed.path}?{urlencode(parameters)}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


def safe_return_path(value: str, fallback: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or parsed.path != fallback:
        return fallback
    return f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path



@router.post("/settings/backups/create")
def settings_backup_create(
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    backup_type: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    try:
        info = create_backup(
            session,
            get_settings(),
            backup_type=backup_type,
            creation_mode="manual",
        )
    except (BackupError, OSError, ValueError) as exc:
        session.rollback()
        return redirect_with("/settings", "error", f"Не удалось создать резервную копию: {exc}")
    write_audit(
        session,
        "backup.created",
        user_id=auth.user.id,
        entity_type="backup",
        entity_id=info.filename,
        entity_name=info.filename,
        details={"backup_type": info.backup_type, "creation_mode": info.creation_mode},
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(
        "/settings",
        "notice",
        f"Создана резервная копия «{info.backup_type_label}»: {info.filename}",
    )


@router.get("/settings/backups/{filename}/download")
def settings_backup_download(
    filename: str,
    auth: AdminAuth,
) -> FileResponse:
    del auth
    try:
        path = safe_stored_backup_path(get_settings(), filename)
    except BackupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=path.name,
    )


@router.post("/settings/backups/{filename}/delete")
def settings_backup_delete(
    filename: str,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    try:
        path = safe_stored_backup_path(get_settings(), filename)
        info = inspect_backup(path, verify_integrity=False)
        delete_backup_file(get_settings(), filename)
    except BackupError as exc:
        return redirect_with("/settings", "error", str(exc))
    write_audit(
        session,
        "backup.deleted",
        user_id=auth.user.id,
        entity_type="backup",
        entity_id=filename,
        entity_name=filename,
        details={"backup_type": info.backup_type, "creation_mode": info.creation_mode},
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with("/settings", "notice", "Резервная копия удалена")


@router.post("/settings/backups/upload")
async def settings_backup_upload(
    upload: Annotated[UploadFile, File()],
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    del session
    require_csrf(auth, csrf_token)
    try:
        token, info = save_uploaded_backup(upload.file, get_settings())
    except (BackupError, OSError, ValueError) as exc:
        return redirect_with("/settings", "error", f"Файл резервной копии не принят: {exc}")
    finally:
        await upload.close()
    return redirect_with(
        f"/settings?backup_candidate={token}",
        "notice",
        f"Файл проверен: {info.backup_type_label}, версия {info.app_version}",
    )


def _restore_backup_and_logout(
    *,
    path,
    source: str,
    request: Request,
    session: DbSession,
) -> RedirectResponse:
    try:
        info = restore_backup(session, get_settings(), path)
        write_audit(
            session,
            "backup.restored",
            user_id=None,
            entity_type="backup",
            entity_id=info.filename,
            entity_name=info.filename,
            details={
                "backup_type": info.backup_type,
                "creation_mode": info.creation_mode,
                "source": source,
                "app_version": info.app_version,
            },
            ip_address=client_ip(request),
        )
        session.commit()
    except (BackupError, OSError, ValueError) as exc:
        session.rollback()
        return redirect_with("/settings", "error", f"Восстановление не выполнено: {exc}")
    response = redirect_with(
        "/login",
        "notice",
        "Восстановление завершено. Войдите снова.",
    )
    delete_session_cookie(response, get_settings(), name=session_cookie_name(get_settings(), request))
    return response


@router.post("/settings/backups/staged/{token}/restore")
def settings_backup_restore_staged(
    token: str,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    try:
        path = staged_backup_path(get_settings(), token)
    except BackupError as exc:
        return redirect_with("/settings", "error", str(exc))
    response = _restore_backup_and_logout(
        path=path,
        source="uploaded",
        request=request,
        session=session,
    )
    if response.status_code == status.HTTP_303_SEE_OTHER and response.headers.get("location", "").startswith("/login"):
        path.unlink(missing_ok=True)
    return response


@router.post("/settings/backups/{filename}/restore")
def settings_backup_restore_stored(
    filename: str,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    try:
        path = safe_stored_backup_path(get_settings(), filename)
    except BackupError as exc:
        return redirect_with("/settings", "error", str(exc))
    return _restore_backup_and_logout(
        path=path,
        source="stored",
        request=request,
        session=session,
    )


@router.post("/settings/database-integrity")
def settings_database_integrity(
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    result = check_database_integrity(session)
    write_audit(
        session,
        "database.integrity_checked",
        user_id=auth.user.id,
        entity_type="database",
        entity_name="База данных Мониторинг Maxval",
        details={"checks": result.checks_count, "issues": list(result.issues)},
        ip_address=client_ip(request),
    )
    session.commit()
    if result.ok:
        return redirect_with(
            "/settings",
            "notice",
            f"Целостность базы проверена: ошибок не обнаружено ({result.checks_count} проверок)",
        )
    return redirect_with(
        "/settings",
        "error",
        f"Проверка целостности обнаружила проблем: {len(result.issues)}. " + " · ".join(result.issues),
    )


def validate_site_fields(name: str, description: str) -> tuple[str, str | None]:
    clean_name = name.strip()
    clean_description = description.strip() or None
    if not 2 <= len(clean_name) <= 120:
        raise ValueError("Название площадки должно содержать от 2 до 120 символов")
    if clean_description and len(clean_description) > 500:
        raise ValueError("Описание площадки не должно превышать 500 символов")
    return clean_name, clean_description


def validate_target_fields(
    name: str,
    address: str,
    port: int | None,
    interval_seconds: int,
    kind: str,
    checker_type: str,
) -> tuple[str, str, int]:
    clean_name = name.strip()
    clean_address = address.strip()
    if not 2 <= len(clean_name) <= 160:
        raise ValueError("Название объекта должно содержать от 2 до 160 символов")
    invalid_address = (
        not clean_address
        or len(clean_address) > 255
        or any(char.isspace() for char in clean_address)
    )
    if invalid_address:
        raise ValueError("Укажите корректный IP-адрес или DNS-имя без пробелов")
    if checker_type == "rtsp":
        parsed_rtsp = urlsplit(
            clean_address if "://" in clean_address else f"rtsp://{clean_address}"
        )
        if (
            parsed_rtsp.scheme.casefold() != "rtsp"
            or not parsed_rtsp.hostname
            or parsed_rtsp.username is not None
            or parsed_rtsp.password is not None
        ):
            raise ValueError("Укажите RTSP-адрес без логина и пароля")
    if checker_type == "icmp":
        clean_port = 1
    elif port is None and checker_type == "http":
        clean_port = 80
    elif port is None and checker_type == "https":
        clean_port = 443
    elif port is None and checker_type == "rtsp":
        clean_port = 554
    elif port is None:
        raise ValueError("Укажите порт для выбранной проверки")
    else:
        clean_port = port
    if not 1 <= clean_port <= 65535:
        raise ValueError("Порт должен быть в диапазоне 1–65535")
    if not 60 <= interval_seconds <= 86400:
        raise ValueError("Интервал должен быть в диапазоне 60–86400 секунд")
    if kind not in {item.value for item in TargetKind}:
        raise ValueError("Неизвестный тип объекта")
    if checker_type not in primary_checker_names(checker_registry):
        raise ValueError("Неизвестный тип проверки")
    return clean_name, clean_address, clean_port


def target_duplicate_exists(
    session: DbSession,
    *,
    site_id: int,
    name: str,
    kind: str,
    checker_type: str,
    address: str,
    port: int,
    interval_seconds: int,
    notifications_suppressed: bool,
) -> bool:
    candidates = session.execute(
        select(MonitorTarget.name, MonitorTarget.address)
        .where(
            MonitorTarget.site_id == site_id,
            MonitorTarget.kind == kind,
            MonitorTarget.checker_type == checker_type,
            MonitorTarget.port == port,
            MonitorTarget.interval_seconds == interval_seconds,
            MonitorTarget.notifications_suppressed.is_(notifications_suppressed),
        )
    ).all()
    normalized_name = name.casefold()
    normalized_address = address.casefold()
    return any(
        existing_name.casefold() == normalized_name
        and existing_address.casefold() == normalized_address
        for existing_name, existing_address in candidates
    )


def _schedule_form_values(form) -> dict[str, tuple[bool, str, str]]:
    return {
        field: (
            form.get(f"{field}_enabled") == "true",
            str(form.get(f"{field}_start") or ""),
            str(form.get(f"{field}_end") or ""),
        )
        for field, _ in DAY_FIELDS
    }


def _schedule_audit_state(
    *,
    name: str,
    is_24x7: bool,
    values: dict[str, str | None],
) -> dict[str, object]:
    state: dict[str, object] = {"name": name, "is_24x7": is_24x7}
    for field, _ in DAY_FIELDS:
        start = values.get(f"{field}_start")
        end = values.get(f"{field}_end")
        if is_24x7:
            display = "круглосуточно"
        elif start and end:
            display = f"{start}–{end}"
        else:
            display = "выходной"
        state[DAY_ABBREVIATIONS[field]] = display
    return state


def _schedule_model_audit_state(schedule: WorkSchedule) -> dict[str, object]:
    values = {
        f"{field}_{suffix}": getattr(schedule, f"{field}_{suffix}")
        for field, _ in DAY_FIELDS
        for suffix in ("start", "end")
    }
    return _schedule_audit_state(
        name=schedule.name,
        is_24x7=schedule.is_24x7,
        values=values,
    )


def _schedule_ref(schedule: WorkSchedule | None) -> dict[str, object] | None:
    if schedule is None:
        return None
    return {"id": schedule.id, "name": schedule.name}


def _site_audit_state(site: Site, schedule: WorkSchedule | None = None) -> dict[str, object]:
    effective_schedule = schedule if schedule is not None else site.schedule
    return {
        "name": site.name,
        "description": site.description or "",
        "schedule": _schedule_ref(effective_schedule),
        "enabled": site.enabled,
    }


def _target_audit_state(target: MonitorTarget, site: Site | None = None) -> dict[str, object]:
    effective_site = site if site is not None else target.site
    return {
        "name": target.name,
        "site": {"id": effective_site.id, "name": effective_site.name} if effective_site else None,
        "kind": target.kind,
        "checker_type": target.checker_type,
        "address": target.address,
        "port": target.port,
        "interval_seconds": target.interval_seconds,
        "comment": target.comment or "",
        "notifications_suppressed": target.notifications_suppressed,
        "favorite": target.favorite,
        "is_site_entry": target.is_site_entry,
        "enabled": target.enabled,
    }


@router.get("/schedules", response_class=HTMLResponse)
def schedules_page(request: Request, session: DbSession, auth: CurrentAuth) -> HTMLResponse:
    site_count = func.count(Site.id)
    rows = session.execute(
        select(WorkSchedule, site_count)
        .outerjoin(Site, Site.schedule_id == WorkSchedule.id)
        .group_by(WorkSchedule.id)
        .order_by(WorkSchedule.built_in.desc(), WorkSchedule.name, WorkSchedule.id)
    ).all()
    timezone_name = schedule_timezone(session)
    schedule_rows = [
        {
            "schedule": schedule,
            "site_count": count,
            "summary": schedule_summary(schedule),
            "working_now": schedule_is_working(schedule, timezone_name=timezone_name),
        }
        for schedule, count in rows
    ]
    return templates.TemplateResponse(
        request=request,
        name="schedules.html",
        context=template_context(
            request, auth, schedule_rows=schedule_rows, day_fields=DAY_FIELDS
        ),
    )


@router.post("/schedules")
async def schedule_create(
    request: Request, session: DbSession, auth: AdminAuth
) -> RedirectResponse:
    form = await request.form()
    require_csrf(auth, str(form.get("csrf_token") or ""))
    try:
        is_24x7 = form.get("is_24x7") == "true"
        clean_name, values = validate_schedule_values(
            str(form.get("name") or ""), is_24x7, _schedule_form_values(form)
        )
        duplicate = session.scalar(
            select(WorkSchedule.id).where(func.lower(WorkSchedule.name) == clean_name.casefold())
        )
        if duplicate is not None:
            raise ValueError("График с таким названием уже существует")
    except ValueError as exc:
        return redirect_with("/schedules", "error", str(exc))
    schedule = WorkSchedule(name=clean_name, is_24x7=is_24x7, **values)
    session.add(schedule)
    session.flush()
    write_audit(
        session,
        "schedule.created",
        user_id=auth.user.id,
        entity_type="work_schedule",
        entity_id=schedule.id,
        entity_name=schedule.name,
        details=_schedule_model_audit_state(schedule),
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with("/schedules", "notice", "График работы добавлен")


@router.post("/schedules/{schedule_id}/update")
async def schedule_update(
    schedule_id: int, request: Request, session: DbSession, auth: AdminAuth
) -> RedirectResponse:
    form = await request.form()
    require_csrf(auth, str(form.get("csrf_token") or ""))
    schedule = session.get(WorkSchedule, schedule_id)
    if schedule is None:
        raise HTTPException(status_code=404, detail="График не найден")
    if schedule.built_in:
        return redirect_with("/schedules", "error", "Встроенный график изменять нельзя")
    try:
        is_24x7 = form.get("is_24x7") == "true"
        clean_name, values = validate_schedule_values(
            str(form.get("name") or ""), is_24x7, _schedule_form_values(form)
        )
        duplicate = session.scalar(
            select(WorkSchedule.id).where(
                func.lower(WorkSchedule.name) == clean_name.casefold(),
                WorkSchedule.id != schedule_id,
            )
        )
        if duplicate is not None:
            raise ValueError("График с таким названием уже существует")
    except ValueError as exc:
        return redirect_with("/schedules", "error", str(exc))
    before = _schedule_model_audit_state(schedule)
    after = _schedule_audit_state(name=clean_name, is_24x7=is_24x7, values=values)
    schedule.name = clean_name
    schedule.is_24x7 = is_24x7
    for key, value in values.items():
        setattr(schedule, key, value)
    write_audit(
        session,
        "schedule.updated",
        user_id=auth.user.id,
        entity_type="work_schedule",
        entity_id=schedule.id,
        entity_name=schedule.name,
        details=audit_changes(before, after) or {"unchanged": True},
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with("/schedules", "notice", "График работы сохранён")


@router.post("/schedules/{schedule_id}/delete")
def schedule_delete(
    schedule_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    schedule = session.get(WorkSchedule, schedule_id)
    if schedule is None:
        raise HTTPException(status_code=404, detail="График не найден")
    if schedule.built_in:
        return redirect_with("/schedules", "error", "Встроенный график удалить нельзя")
    used = session.scalar(select(func.count(Site.id)).where(Site.schedule_id == schedule.id)) or 0
    if used:
        return redirect_with(
            "/schedules", "error", "Сначала назначьте площадкам другой график"
        )
    deleted_state = _schedule_model_audit_state(schedule)
    session.delete(schedule)
    write_audit(
        session,
        "schedule.deleted",
        user_id=auth.user.id,
        entity_type="work_schedule",
        entity_id=schedule_id,
        entity_name=schedule.name,
        details=deleted_state,
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with("/schedules", "notice", "График работы удалён")


@router.get("/sites", response_class=HTMLResponse)
def sites_page(request: Request, session: DbSession, auth: CurrentAuth) -> HTMLResponse:
    sort_state = SortState.from_request(
        request,
        {"display_order", "name", "description", "target_count", "schedule", "enabled"},
        "display_order",
    )
    target_count = func.count(MonitorTarget.id)
    site_entry_target = aliased(MonitorTarget)
    site_entry_target_id = (
        select(site_entry_target.id)
        .where(
            site_entry_target.site_id == Site.id,
            site_entry_target.is_site_entry.is_(True),
        )
        .limit(1)
        .scalar_subquery()
        .label("site_entry_target_id")
    )
    sort_columns = {
        "display_order": Site.display_order,
        "name": func.lower(Site.name),
        "description": func.lower(func.coalesce(Site.description, "")),
        "target_count": target_count,
        "schedule": func.lower(func.coalesce(WorkSchedule.name, "Круглосуточно")),
        "enabled": Site.enabled,
    }
    total = session.scalar(select(func.count(Site.id))) or 0
    pager = Pagination.from_request(request, total)
    site_rows = session.execute(
        select(Site, target_count, site_entry_target_id)
        .outerjoin(MonitorTarget, MonitorTarget.site_id == Site.id)
        .outerjoin(WorkSchedule, WorkSchedule.id == Site.schedule_id)
        .group_by(Site.id, WorkSchedule.id, WorkSchedule.name)
        .order_by(sort_state.order(sort_columns[sort_state.column]), Site.id)
        .offset(pager.offset)
        .limit(pager.per_page)
    ).all()
    schedules = session.scalars(
        select(WorkSchedule).order_by(WorkSchedule.built_in.desc(), WorkSchedule.name)
    ).all()
    return templates.TemplateResponse(
        request=request,
        name="sites.html",
        context=template_context(
            request,
            auth,
            site_rows=site_rows,
            schedules=schedules,
            pager=pager,
            sort_state=sort_state,
        ),
    )


@router.get("/sites/{site_id}/layout", response_class=HTMLResponse)
def site_layout_page(site_id: int, request: Request, session: DbSession, auth: AdminAuth) -> HTMLResponse:
    site = session.get(Site, site_id)
    if site is None:
        raise HTTPException(status_code=404, detail="Площадка не найдена")
    targets = session.scalars(
        select(MonitorTarget).where(MonitorTarget.site_id == site.id).order_by(
            MonitorTarget.favorite.desc(), MonitorTarget.display_order, MonitorTarget.id
        )
    ).all()
    target_services_by_target: dict[int, list[TargetCheck]] = {}
    target_ids = [target.id for target in targets]
    if target_ids:
        for check in session.scalars(
            select(TargetCheck)
            .where(TargetCheck.target_id.in_(target_ids), TargetCheck.is_primary.is_(False))
            .order_by(TargetCheck.target_id, TargetCheck.display_order, TargetCheck.id)
        ):
            target_services_by_target.setdefault(check.target_id, []).append(check)
    site_options = session.scalars(select(Site).order_by(Site.display_order, Site.id)).all()
    return templates.TemplateResponse(
        request=request,
        name="site_layout.html",
        context=template_context(
            request, auth, site=site, targets=targets, site_options=site_options,
            target_services_by_target=target_services_by_target,
        ),
    )


@router.post("/sites/{site_id}/layout")
def site_layout_save(
    site_id: int, request: Request, session: DbSession, auth: AdminAuth,
    csrf_token: Annotated[str, Form()], positions: Annotated[str, Form()],
    layout_scale: Annotated[int, Form()],
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    site = session.get(Site, site_id)
    if site is None:
        raise HTTPException(status_code=404, detail="Площадка не найдена")
    try:
        if not 50 <= layout_scale <= 200 or layout_scale % 10:
            raise ValueError
        payload = json.loads(positions)
        if not isinstance(payload, list) or len(payload) > 255:
            raise ValueError
        targets = {item.id: item for item in session.scalars(select(MonitorTarget).where(MonitorTarget.site_id == site.id))}
        changed, seen = 0, set()
        for item in payload:
            if not isinstance(item, dict):
                raise ValueError
            target_id, x, y = item.get("id"), item.get("x"), item.get("y")
            if not isinstance(target_id, int) or target_id in seen or target_id not in targets:
                raise ValueError
            if not isinstance(x, int) or not isinstance(y, int) or not 0 <= x <= 10000 or not 0 <= y <= 10000:
                raise ValueError
            seen.add(target_id)
            target = targets[target_id]
            if (target.layout_x, target.layout_y) != (x, y):
                target.layout_x, target.layout_y = x, y
                changed += 1
        for target_id, target in targets.items():
            if target_id not in seen and (target.layout_x is not None or target.layout_y is not None):
                target.layout_x = None
                target.layout_y = None
                changed += 1
        if site.layout_scale != layout_scale:
            site.layout_scale = layout_scale
            changed += 1
    except (ValueError, TypeError, json.JSONDecodeError):
        return redirect_with(f"/sites/{site_id}/layout", "error", "Некорректные координаты схемы")
    write_audit(session, "site.layout_changed", user_id=auth.user.id, entity_type="site", entity_id=site.id, entity_name=site.name, details={"changed_targets": changed}, ip_address=client_ip(request))
    session.commit()
    return redirect_with(f"/sites/{site_id}/layout", "notice", "Расположение объектов сохранено")


@router.post("/sites/{site_id}/layout-scale")
def site_layout_scale_save(
    site_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    layout_scale: Annotated[int, Form()],
) -> JSONResponse:
    """Persist the shared editor/TV scale without changing target coordinates."""
    require_csrf(auth, csrf_token)
    site = session.get(Site, site_id)
    if site is None:
        raise HTTPException(status_code=404, detail="Площадка не найдена")
    if not 50 <= layout_scale <= 200 or layout_scale % 10:
        raise HTTPException(status_code=422, detail="Некорректный масштаб схемы")
    if site.layout_scale != layout_scale:
        previous = site.layout_scale
        site.layout_scale = layout_scale
        write_audit(
            session,
            "site.layout_scale_changed",
            user_id=auth.user.id,
            entity_type="site",
            entity_id=site.id,
            entity_name=site.name,
            details={"previous": previous, "current": layout_scale},
            ip_address=client_ip(request),
        )
        session.commit()
    return JSONResponse({"layout_scale": site.layout_scale})


@router.post("/sites")
def site_create(
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    name: Annotated[str, Form()],
    description: Annotated[str, Form()] = "",
    schedule_id: Annotated[int, Form()] = 0,
    csrf_token: Annotated[str, Form()] = "",
    return_to: Annotated[str, Form()] = "/sites",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    try:
        clean_name, clean_description = validate_site_fields(name, description)
        if session.scalar(select(Site.id).where(func.lower(Site.name) == clean_name.lower())):
            raise ValueError("Площадка с таким названием уже существует")
    except ValueError as exc:
        return redirect_with(safe_return_path(return_to, "/sites"), "error", str(exc))
    schedule = session.get(WorkSchedule, schedule_id) or session.get(WorkSchedule, 0)
    if schedule is None:
        return redirect_with(safe_return_path(return_to, "/sites"), "error", "График работы не найден")
    site = Site(
        name=clean_name,
        description=clean_description,
        schedule_id=schedule.id,
        display_order=next_site_display_order(session),
    )
    session.add(site)
    session.flush()
    write_audit(
        session,
        "site.created",
        user_id=auth.user.id,
        entity_type="site",
        entity_id=site.id,
        entity_name=site.name,
        details=_site_audit_state(site, schedule),
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(
        safe_return_path(return_to, "/sites"), "notice", "Площадка добавлена"
    )


@router.post("/sites/{site_id}/move")
def site_move(
    site_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    direction: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "/sites",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    site = session.get(Site, site_id)
    if site is None:
        raise HTTPException(status_code=404, detail="Площадка не найдена")
    try:
        changed = move_site(session, site, direction)
    except ValueError as exc:
        return redirect_with(safe_return_path(return_to, "/sites"), "error", str(exc))
    if changed:
        write_audit(
            session,
            "site.display_order_changed",
            user_id=auth.user.id,
            entity_type="site",
            entity_id=site.id,
            entity_name=site.name,
            details={"direction": direction},
            ip_address=client_ip(request),
        )
        session.commit()
        message = "Порядок площадок изменён"
    else:
        session.rollback()
        message = "Площадка уже находится на границе списка"
    return redirect_with(safe_return_path(return_to, "/sites"), "notice", message)


@router.post("/sites/{site_id}/update")
def site_update(
    site_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    name: Annotated[str, Form()],
    description: Annotated[str, Form()] = "",
    schedule_id: Annotated[int, Form()] = 0,
    csrf_token: Annotated[str, Form()] = "",
    return_to: Annotated[str, Form()] = "/sites",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    site = session.get(Site, site_id)
    if site is None:
        raise HTTPException(status_code=404, detail="Площадка не найдена")
    try:
        clean_name, clean_description = validate_site_fields(name, description)
        duplicate = session.scalar(
            select(Site.id).where(
                func.lower(Site.name) == clean_name.lower(), Site.id != site_id
            )
        )
        if duplicate:
            raise ValueError("Площадка с таким названием уже существует")
    except ValueError as exc:
        return redirect_with(safe_return_path(return_to, "/sites"), "error", str(exc))
    schedule = session.get(WorkSchedule, schedule_id)
    if schedule is None:
        return redirect_with(safe_return_path(return_to, "/sites"), "error", "График работы не найден")
    before = _site_audit_state(site)
    after = {
        "name": clean_name,
        "description": clean_description or "",
        "schedule": _schedule_ref(schedule),
        "enabled": site.enabled,
    }
    site.name = clean_name
    site.description = clean_description
    site.schedule_id = schedule.id
    site.schedule = schedule
    write_audit(
        session,
        "site.updated",
        user_id=auth.user.id,
        entity_type="site",
        entity_id=site.id,
        entity_name=site.name,
        details=audit_changes(before, after) or {"unchanged": True},
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(
        safe_return_path(return_to, "/sites"), "notice", "Площадка сохранена"
    )


@router.post("/sites/{site_id}/toggle")
def site_toggle(
    site_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "/sites",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    site = session.get(Site, site_id)
    if site is None:
        raise HTTPException(status_code=404, detail="Площадка не найдена")
    old_enabled = site.enabled
    site.enabled = not site.enabled
    write_audit(
        session,
        "site.enabled_changed",
        user_id=auth.user.id,
        entity_type="site",
        entity_id=site.id,
        entity_name=site.name,
        details={"enabled": {"old": old_enabled, "new": site.enabled}},
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(
        safe_return_path(return_to, "/sites"),
        "notice",
        "Состояние площадки изменено",
    )


@router.post("/sites/{site_id}/delete")
def site_delete(
    site_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "/sites",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    site = session.get(Site, site_id)
    if site is None:
        raise HTTPException(status_code=404, detail="Площадка не найдена")
    target_count = session.scalar(
        select(func.count(MonitorTarget.id)).where(MonitorTarget.site_id == site.id)
    ) or 0
    if target_count:
        return redirect_with(
            safe_return_path(return_to, "/sites"),
            "error",
            "Сначала удалите все объекты этой площадки",
        )
    site_name = site.name
    session.delete(site)
    write_audit(
        session,
        "site.deleted",
        user_id=auth.user.id,
        entity_type="site",
        entity_id=site_id,
        entity_name=site_name,
        details={"name": site_name},
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(
        safe_return_path(return_to, "/sites"), "notice", "Площадка удалена"
    )


@router.post("/sites/{site_id}/targets/delete-all")
def site_targets_delete_all(
    site_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "/sites",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    site = session.get(Site, site_id)
    if site is None:
        raise HTTPException(status_code=404, detail="Площадка не найдена")
    target_ids = select(MonitorTarget.id).where(MonitorTarget.site_id == site.id)
    metric_ids = select(SnmpMetric.id).where(SnmpMetric.target_id.in_(target_ids))
    target_count = session.scalar(
        select(func.count(MonitorTarget.id)).where(MonitorTarget.site_id == site.id)
    ) or 0
    session.execute(delete(CheckResult).where(CheckResult.target_id.in_(target_ids)))
    session.execute(delete(Incident).where(Incident.target_id.in_(target_ids)))
    session.execute(delete(SnmpSample).where(SnmpSample.metric_id.in_(metric_ids)))
    session.execute(delete(SnmpMetric).where(SnmpMetric.target_id.in_(target_ids)))
    session.execute(delete(SnmpConfig).where(SnmpConfig.target_id.in_(target_ids)))
    session.execute(delete(MonitorTarget).where(MonitorTarget.site_id == site.id))
    write_audit(
        session,
        "site.targets_deleted",
        user_id=auth.user.id,
        entity_type="site",
        entity_id=site.id,
        entity_name=site.name,
        details={"count": target_count},
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(
        safe_return_path(return_to, "/sites"),
        "notice",
        f"Удалено объектов: {target_count}",
    )


@router.get("/targets", response_class=HTMLResponse)
def targets_page(request: Request, session: DbSession, auth: CurrentAuth) -> HTMLResponse:
    sort_state = SortState.from_request(
        request,
        {
            "site",
            "name",
            "kind",
            "checker_type",
            "address",
            "port",
            "interval_seconds",
            "enabled",
        },
        "site",
    )
    sort_columns = {
        "site": func.lower(Site.name),
        "name": func.lower(MonitorTarget.name),
        "kind": MonitorTarget.kind,
        "checker_type": MonitorTarget.checker_type,
        "address": func.lower(MonitorTarget.address),
        "port": MonitorTarget.port,
        "interval_seconds": MonitorTarget.interval_seconds,
        "enabled": MonitorTarget.enabled,
    }
    selected_site = positive_int(request.query_params.get("site_id"), 0)
    selected_kind = request.query_params.get("kind", "all")
    if selected_kind not in {"all", *(item.value for item in TargetKind)}:
        selected_kind = "all"
    selected_checker = request.query_params.get("checker_type", "all")
    if selected_checker not in {"all", *primary_checker_names(checker_registry)}:
        selected_checker = "all"
    selected_enabled = request.query_params.get("enabled", "all")
    if selected_enabled not in {"all", "true", "false"}:
        selected_enabled = "all"
    selected_notifications_suppressed = request.query_params.get(
        "notifications_suppressed", "all"
    )
    if selected_notifications_suppressed not in {"all", "true", "false"}:
        selected_notifications_suppressed = "all"
    selected_favorite = request.query_params.get("favorite", "all")
    if selected_favorite not in {"all", "true", "false"}:
        selected_favorite = "all"
    selected_snmp_enabled = request.query_params.get("snmp_enabled", "all")
    if selected_snmp_enabled not in {"all", "true"}:
        selected_snmp_enabled = "all"
    search = request.query_params.get("q", "").strip()[:100]
    focus_target_id = positive_int(request.query_params.get("focus_target_id"), 0)
    copy_target_id = positive_int(request.query_params.get("copy_target_id"), 0)
    add_service_target_id = positive_int(request.query_params.get("add_service"), 0)
    if add_service_target_id != focus_target_id:
        add_service_target_id = 0
    editor_return_to = safe_return_path(request.query_params.get("return_to", ""), "/targets")
    editor_save_return_to = "/targets"
    if focus_target_id:
        editor_save_return_to = f"/targets?{urlencode({'focus_target_id': focus_target_id, 'return_to': editor_return_to})}"
    conditions = []
    if focus_target_id:
        conditions.append(MonitorTarget.id == focus_target_id)
    if selected_site:
        conditions.append(Site.id == selected_site)
    if selected_kind != "all":
        conditions.append(MonitorTarget.kind == selected_kind)
    if selected_checker != "all":
        conditions.append(MonitorTarget.checker_type == selected_checker)
    if selected_enabled != "all":
        conditions.append(MonitorTarget.enabled.is_(selected_enabled == "true"))
    if selected_notifications_suppressed != "all":
        conditions.append(
            MonitorTarget.notifications_suppressed.is_(
                selected_notifications_suppressed == "true"
            )
        )
    if selected_favorite != "all":
        conditions.append(MonitorTarget.favorite.is_(selected_favorite == "true"))
    if selected_snmp_enabled == "true":
        conditions.append(
            exists(
                select(1).where(
                    SnmpConfig.target_id == MonitorTarget.id,
                    SnmpConfig.enabled.is_(True),
                )
            )
        )
    if search:
        pattern = f"%{search.casefold()}%"
        conditions.append(
            or_(
                func.lower(MonitorTarget.name).like(pattern),
                func.lower(MonitorTarget.address).like(pattern),
            )
        )
    total = session.scalar(
        select(func.count(MonitorTarget.id))
        .select_from(MonitorTarget)
        .join(Site, Site.id == MonitorTarget.site_id)
        .where(*conditions)
    ) or 0
    pager = Pagination.from_request(request, total)
    targets = session.execute(
        select(MonitorTarget, Site)
        .join(Site, Site.id == MonitorTarget.site_id)
        .where(*conditions)
        .order_by(
            sort_state.order(sort_columns[sort_state.column]),
            func.lower(MonitorTarget.name),
            MonitorTarget.id,
        )
        .offset(pager.offset)
        .limit(pager.per_page)
    ).all()
    target_checks_by_target: dict[int, list[TargetCheck]] = {}
    target_ids = [target.id for target, _site in targets]
    if target_ids:
        for check in session.scalars(
            select(TargetCheck)
            .where(TargetCheck.target_id.in_(target_ids))
            .order_by(TargetCheck.target_id, TargetCheck.display_order, TargetCheck.id)
        ):
            target_checks_by_target.setdefault(check.target_id, []).append(check)
    sites = session.scalars(select(Site).order_by(Site.display_order, Site.id)).all()
    copy_source: MonitorTarget | None = None
    if copy_target_id and auth.user.role == UserRole.ADMIN:
        copy_source = session.get(MonitorTarget, copy_target_id)
        if copy_source is None:
            raise HTTPException(status_code=404, detail="Исходный объект не найден")
    return templates.TemplateResponse(
        request=request,
        name="targets.html",
        context=template_context(
            request,
            auth,
            targets=targets,
            target_checks_by_target=target_checks_by_target,
            sites=sites,
            kinds=list(TargetKind),
            checker_names=primary_checker_names(checker_registry),
            secondary_checker_names=secondary_checker_names(checker_registry),
            default_check_timeout=get_settings().check_timeout_seconds,
            pager=pager,
            sort_state=sort_state,
            focus_target_id=focus_target_id,
            copy_source=copy_source,
            add_service_target_id=add_service_target_id,
            editor_return_to=editor_return_to,
            editor_save_return_to=editor_save_return_to,
            filters={
                "site_id": selected_site,
                "kind": selected_kind,
                "checker_type": selected_checker,
                "enabled": selected_enabled,
                "notifications_suppressed": selected_notifications_suppressed,
                "favorite": selected_favorite,
                "snmp_enabled": selected_snmp_enabled,
                "q": search,
            },
        ),
    )


@router.post("/targets")
def target_create(
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    site_id: Annotated[int, Form()],
    name: Annotated[str, Form()],
    kind: Annotated[str, Form()],
    checker_type: Annotated[str, Form()],
    address: Annotated[str, Form()],
    interval_seconds: Annotated[int, Form()],
    csrf_token: Annotated[str, Form()],
    port: Annotated[int | None, Form()] = None,
    notifications_suppressed: Annotated[str | None, Form()] = None,
    favorite: Annotated[str | None, Form()] = None,
    is_site_entry: Annotated[str | None, Form()] = None,
    comment: Annotated[str, Form()] = "",
    copy_target_id: Annotated[int | None, Form()] = None,
    return_to: Annotated[str, Form()] = "/targets",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    site = session.get(Site, site_id)
    if site is None:
        return redirect_with(
            safe_return_path(return_to, "/targets"), "error", "Площадка не найдена"
        )
    try:
        clean_name, clean_address, clean_port = validate_target_fields(
            name, address, port, interval_seconds, kind, checker_type
        )
        suppress_notifications = notifications_suppressed == "true"
        if target_duplicate_exists(
            session,
            site_id=site.id,
            name=clean_name,
            kind=kind,
            checker_type=checker_type,
            address=clean_address,
            port=clean_port,
            interval_seconds=interval_seconds,
            notifications_suppressed=suppress_notifications,
        ):
            raise ValueError("Объект с такими параметрами уже существует")
        if is_site_entry == "true" and kind not in ENTRY_TARGET_KINDS:
            raise ValueError(
                "Точкой входа площадки может быть только объект типа «Сеть» или «Сервер»"
            )
    except ValueError as exc:
        return redirect_with(safe_return_path(return_to, "/targets"), "error", str(exc))
    clean_comment = comment.strip() or None
    if clean_comment and len(clean_comment) > 1000:
        return redirect_with(safe_return_path(return_to, "/targets"), "error", "Комментарий не должен превышать 1000 символов")
    target = MonitorTarget(
        site_id=site.id,
        name=clean_name,
        kind=kind,
        checker_type=checker_type,
        address=clean_address,
        comment=clean_comment,
        port=clean_port,
        interval_seconds=interval_seconds,
        notifications_suppressed=suppress_notifications,
        favorite=favorite == "true",
        display_order=next_display_order(session, favorite == "true"),
    )
    session.add(target)
    session.flush()
    sync_target_primary_check(session, target)
    clone_result = None
    if copy_target_id is not None:
        source = session.get(MonitorTarget, copy_target_id)
        if source is None:
            session.rollback()
            return redirect_with(
                safe_return_path(return_to, "/targets"),
                "error",
                "Исходный объект для копирования не найден",
            )
        # Administrative enablement is configuration. Site-entry designation is
        # intentionally not copied because a site can have only one entry point.
        target.enabled = source.enabled
        clone_result = clone_target_configuration(session, source, target)
    replaced_entry_id = set_site_entry(session, target, True) if is_site_entry == "true" else None
    audit_details = _target_audit_state(target, site)
    if replaced_entry_id is not None:
        audit_details["replaced_site_entry_id"] = replaced_entry_id
    write_audit(
        session,
        "target.created",
        user_id=auth.user.id,
        entity_type="target",
        entity_id=target.id,
        entity_name=target.name,
        details=audit_details,
        ip_address=client_ip(request),
    )
    if clone_result is not None:
        write_audit(
            session,
            "target.cloned",
            user_id=auth.user.id,
            entity_type="target",
            entity_id=target.id,
            entity_name=target.name,
            details={
                "source_target_id": source.id,
                "copied": clone_result.audit_details(),
            },
            ip_address=client_ip(request),
        )
    session.commit()
    return redirect_with(
        safe_return_path(return_to, "/targets"),
        "notice",
        "Объект скопирован" if clone_result is not None else "Объект добавлен",
    )


@router.post("/targets/{target_id}/update")
def target_update(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    site_id: Annotated[int, Form()],
    name: Annotated[str, Form()],
    kind: Annotated[str, Form()],
    checker_type: Annotated[str, Form()],
    address: Annotated[str, Form()],
    interval_seconds: Annotated[int, Form()],
    csrf_token: Annotated[str, Form()],
    port: Annotated[int | None, Form()] = None,
    notifications_suppressed: Annotated[str | None, Form()] = None,
    favorite: Annotated[str | None, Form()] = None,
    is_site_entry: Annotated[str | None, Form()] = None,
    comment: Annotated[str, Form()] = "",
    return_to: Annotated[str, Form()] = "/targets",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    target = session.get(MonitorTarget, target_id)
    site = session.get(Site, site_id)
    if target is None or site is None:
        raise HTTPException(status_code=404, detail="Объект или площадка не найдены")
    try:
        clean_name, clean_address, clean_port = validate_target_fields(
            name, address, port, interval_seconds, kind, checker_type
        )
        if is_site_entry == "true" and kind not in ENTRY_TARGET_KINDS:
            raise ValueError(
                "Точкой входа площадки может быть только объект типа «Сеть» или «Сервер»"
            )
    except ValueError as exc:
        return redirect_with(safe_return_path(return_to, "/targets"), "error", str(exc))
    before = _target_audit_state(target)
    execution_before = (target.checker_type, target.address, target.port)
    clean_comment = comment.strip() or None
    if clean_comment and len(clean_comment) > 1000:
        return redirect_with(safe_return_path(return_to, "/targets"), "error", "Комментарий не должен превышать 1000 символов")
    new_favorite = favorite == "true"
    if target.site_id != site.id:
        target.layout_x = None
        target.layout_y = None
    target.site_id = site.id
    target.site = site
    target.name = clean_name
    target.kind = kind
    target.checker_type = checker_type
    target.address = clean_address
    target.comment = clean_comment
    target.port = clean_port
    target.interval_seconds = interval_seconds
    target.notifications_suppressed = notifications_suppressed == "true"
    if (target.checker_type, target.address, target.port) != execution_before:
        reset_unstable_link(target)
    if new_favorite != target.favorite:
        move_to_group_end(session, target, new_favorite)
    sync_target_primary_check(session, target)
    replaced_entry_id = (
        set_site_entry(session, target, True)
        if is_site_entry == "true"
        else None
    )
    if is_site_entry != "true":
        target.is_site_entry = False
    normalize_site_entry_for_kind(target)
    after = _target_audit_state(target, site)
    audit_details = audit_changes(before, after) or {"unchanged": True}
    if replaced_entry_id is not None:
        audit_details["replaced_site_entry_id"] = replaced_entry_id
    write_audit(
        session,
        "target.updated",
        user_id=auth.user.id,
        entity_type="target",
        entity_id=target.id,
        entity_name=target.name,
        details=audit_details,
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(
        safe_return_path(return_to, "/targets"), "notice", "Объект сохранён"
    )


@router.post("/targets/{target_id}/favorite")
def target_favorite_toggle(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "/targets",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    target = session.get(MonitorTarget, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Объект не найден")
    old_favorite = target.favorite
    move_to_group_end(session, target, not target.favorite)
    write_audit(
        session,
        "target.favorite_changed",
        user_id=auth.user.id,
        entity_type="target",
        entity_id=target.id,
        entity_name=target.name,
        details={"favorite": {"old": old_favorite, "new": target.favorite}},
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(
        safe_return_path(return_to, "/targets"),
        "notice",
        "Объект добавлен в избранное" if target.favorite else "Объект убран из избранного",
    )


@router.post("/targets/{target_id}/move")
def target_move(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    direction: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "/",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    target = session.get(MonitorTarget, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Объект не найден")
    try:
        changed = move_target(session, target, direction)
    except ValueError as exc:
        return redirect_with(safe_return_path(return_to, "/"), "error", str(exc))
    if changed:
        write_audit(
            session,
            "target.display_order_changed",
            user_id=auth.user.id,
            entity_type="target",
            entity_id=target.id,
            entity_name=target.name,
            details={"direction": direction, "favorite": target.favorite},
            ip_address=client_ip(request),
        )
        session.commit()
        message = "Порядок объектов изменён"
    else:
        session.rollback()
        message = "Объект уже находится на границе своей группы"
    return redirect_with(safe_return_path(return_to, "/"), "notice", message)


@router.post("/targets/{target_id}/toggle")
def target_toggle(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "/targets",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    target = session.get(MonitorTarget, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Объект не найден")
    old_enabled = target.enabled
    target.enabled = not target.enabled
    reset_unstable_link(target)
    for check in target.checks:
        reset_unstable_link(check)
    write_audit(
        session,
        "target.enabled_changed",
        user_id=auth.user.id,
        entity_type="target",
        entity_id=target.id,
        entity_name=target.name,
        details={"enabled": {"old": old_enabled, "new": target.enabled}},
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(
        safe_return_path(return_to, "/targets"),
        "notice",
        "Состояние объекта изменено",
    )


@router.post("/targets/{target_id}/delete")
def target_delete(
    target_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "/targets",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    target = session.get(MonitorTarget, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Объект не найден")
    target_name = target.name
    metric_ids = select(SnmpMetric.id).where(SnmpMetric.target_id == target.id)
    session.execute(delete(CheckResult).where(CheckResult.target_id == target.id))
    session.execute(delete(Incident).where(Incident.target_id == target.id))
    session.execute(delete(SnmpSample).where(SnmpSample.metric_id.in_(metric_ids)))
    session.execute(delete(SnmpMetric).where(SnmpMetric.target_id == target.id))
    session.execute(delete(SnmpConfig).where(SnmpConfig.target_id == target.id))
    session.delete(target)
    write_audit(
        session,
        "target.deleted",
        user_id=auth.user.id,
        entity_type="target",
        entity_id=target_id,
        entity_name=target_name,
        details={"name": target_name},
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(
        safe_return_path(return_to, "/targets"), "notice", "Объект удалён"
    )


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request, session: DbSession, auth: AdminAuth) -> HTMLResponse:
    user_sort_state = SortState.from_request(
        request,
        {"username", "role", "active", "last_login_at", "last_login_ip"},
        "username",
    )
    user_sort_columns = {
        "username": func.lower(User.username),
        "role": User.role,
        "active": User.active,
        "last_login_at": User.last_login_at,
        "last_login_ip": func.coalesce(User.last_login_ip, ""),
    }
    block_sort_state = SortState.from_request(
        request,
        {"username", "ip_address", "blocked_until"},
        "blocked_until",
        "desc",
        column_parameter="block_sort",
        direction_parameter="block_direction",
    )
    block_sort_columns = {
        "username": func.lower(LoginBlock.username),
        "ip_address": LoginBlock.ip_address,
        "blocked_until": LoginBlock.blocked_until,
    }
    total = session.scalar(select(func.count(User.id)).where(User.deleted_at.is_(None))) or 0
    pager = Pagination.from_request(request, total)
    users = session.scalars(
        select(User)
        .where(User.deleted_at.is_(None))
        .order_by(
            user_sort_state.order(user_sort_columns[user_sort_state.column]),
            User.id,
        )
        .offset(pager.offset)
        .limit(pager.per_page)
    ).all()
    blocks = session.scalars(
        select(LoginBlock)
        .where(LoginBlock.blocked_until > utc_now())
        .order_by(
            block_sort_state.order(block_sort_columns[block_sort_state.column]),
            LoginBlock.id,
        )
    ).all()
    return templates.TemplateResponse(
        request=request,
        name="users.html",
        context=template_context(
            request,
            auth,
            users=users,
            blocks=blocks,
            pager=pager,
            user_sort_state=user_sort_state,
            block_sort_state=block_sort_state,
            min_password_length=get_min_password_length(session),
            display_datetime=session_datetime_formatter(session),
        ),
    )


@router.post("/users")
def user_create(
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    role: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "/users",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    try:
        user = create_user(session, username, password, role)
    except ValueError as exc:
        return redirect_with(safe_return_path(return_to, "/users"), "error", str(exc))
    write_audit(
        session,
        "user.created",
        user_id=auth.user.id,
        entity_type="user",
        entity_id=user.id,
        entity_name=user.username,
        details={"username": user.username, "role": user.role},
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(
        safe_return_path(return_to, "/users"), "notice", "Пользователь создан"
    )


@router.post("/users/{user_id}/update")
def user_update(
    user_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    role: Annotated[str, Form()],
    active: Annotated[str | None, Form()] = None,
    csrf_token: Annotated[str, Form()] = "",
    return_to: Annotated[str, Form()] = "/users",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    user = session.get(User, user_id)
    if user is None or user.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if role not in {UserRole.ADMIN, UserRole.VIEWER}:
        return redirect_with(
            safe_return_path(return_to, "/users"), "error", "Неизвестная роль"
        )
    new_active = active == "true"
    if user.id == auth.user.id and (not new_active or role != UserRole.ADMIN):
        return redirect_with(
            safe_return_path(return_to, "/users"),
            "error",
            "Нельзя отключить себя или снять у себя права администратора",
        )
    removes_admin = user.active and user.role == UserRole.ADMIN and (
        not new_active or role != UserRole.ADMIN
    )
    if removes_admin:
        active_admin_ids = session.scalars(
            select(User.id)
            .where(User.active.is_(True), User.role == UserRole.ADMIN)
            .order_by(User.id)
            .with_for_update()
        ).all()
        if not any(admin_id != user.id for admin_id in active_admin_ids):
            return redirect_with(
                safe_return_path(return_to, "/users"),
                "error",
                "Нельзя отключить последнего администратора",
            )
    user.role = role
    user.active = new_active
    if not new_active:
        revoke_user_sessions(session, user.id)
    write_audit(
        session,
        "user.updated",
        user_id=auth.user.id,
        entity_type="user",
        entity_id=user.id,
        entity_name=user.username,
        details={"role": user.role, "active": user.active},
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(
        safe_return_path(return_to, "/users"), "notice", "Пользователь сохранён"
    )


@router.post("/users/{user_id}/password")
def user_password(
    user_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    password: Annotated[str, Form()],
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "/users",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    user = session.get(User, user_id)
    if user is None or user.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    try:
        validate_password(session, password)
    except ValueError as exc:
        return redirect_with(safe_return_path(return_to, "/users"), "error", str(exc))
    user.password_hash = hash_password(password)
    user.must_change_default_password = False
    revoke_user_sessions(session, user.id)
    write_audit(
        session,
        "user.password_changed",
        user_id=auth.user.id,
        entity_type="user",
        entity_id=user.id,
        entity_name=user.username,
        ip_address=client_ip(request),
    )
    session.commit()
    response = redirect_with(
        safe_return_path(return_to, "/users"),
        "notice",
        "Пароль изменён; сессии завершены",
    )
    return response


@router.post("/users/{user_id}/delete")
def user_delete(
    user_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "/users",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    user = session.get(User, user_id)
    if user is None or user.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if user.id == auth.user.id:
        return redirect_with(
            safe_return_path(return_to, "/users"),
            "error",
            "Нельзя удалить самого себя",
        )
    if user.active and user.role == UserRole.ADMIN:
        other_admin = session.scalar(
            select(User.id).where(
                User.id != user.id,
                User.active.is_(True),
                User.role == UserRole.ADMIN,
            ).limit(1)
        )
        if other_admin is None:
            return redirect_with(
                safe_return_path(return_to, "/users"),
                "error",
                "Нельзя удалить последнего активного администратора",
            )
    username = user.username
    revoke_user_sessions(session, user.id)
    session.execute(delete(LoginBlock).where(LoginBlock.username == username))
    session.execute(delete(FailedLoginAttempt).where(FailedLoginAttempt.username == username))
    user.active = False
    user.deleted_at = utc_now()
    purged_messages = cleanup_deleted_user_communication(session, user=user)
    write_audit(
        session,
        "user.deleted",
        user_id=auth.user.id,
        entity_type="user",
        entity_id=user_id,
        entity_name=username,
        details={
            "username": username,
            "chat_history_preserved": True,
            "purged_messages_with_deleted_users": purged_messages,
        },
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(
        safe_return_path(return_to, "/users"), "notice", "Пользователь удалён"
    )


@router.post("/users/{user_id}/unblock")
def user_unblock(
    user_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "/users",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    user = session.get(User, user_id)
    if user is None or user.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    session.execute(delete(LoginBlock).where(LoginBlock.username == user.username))
    write_audit(
        session,
        "user.unblocked",
        user_id=auth.user.id,
        entity_type="user",
        entity_id=user.id,
        entity_name=user.username,
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(
        safe_return_path(return_to, "/users"), "notice", "Блокировка снята"
    )


@router.post("/users/blocks/{block_id}/delete")
def login_block_delete(
    block_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "/users",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    block = session.get(LoginBlock, block_id)
    if block is None:
        raise HTTPException(status_code=404, detail="Блокировка не найдена")
    session.delete(block)
    write_audit(
        session,
        "auth.block_removed",
        user_id=auth.user.id,
        entity_type="login_block",
        entity_id=block_id,
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(
        safe_return_path(return_to, "/users"), "notice", "Блокировка снята"
    )


@router.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, session: DbSession, auth: AdminAuth) -> HTMLResponse:
    search = request.query_params.get("q", "").strip()[:100]
    selected_action = request.query_params.get("action", "").strip()[:80]
    selected_entity = request.query_params.get("entity_type", "").strip()[:50]
    selected_user = request.query_params.get("user_id", "all")
    sort_state = SortState.from_request(
        request,
        {"created_at", "username", "action", "entity", "ip_address", "details"},
        "created_at",
        "desc",
    )

    conditions = []
    if search:
        pattern = f"%{search.casefold()}%"
        conditions.append(
            or_(
                func.lower(AuditLog.action).like(pattern),
                func.lower(AuditLog.entity_type).like(pattern),
                func.lower(AuditLog.entity_id).like(pattern),
                func.lower(AuditLog.ip_address).like(pattern),
                func.lower(AuditLog.details).like(pattern),
                func.lower(User.username).like(pattern),
            )
        )
    if selected_action:
        conditions.append(AuditLog.action == selected_action)
    if selected_entity:
        conditions.append(AuditLog.entity_type == selected_entity)
    if selected_user == "system":
        conditions.append(AuditLog.user_id.is_(None))
    elif positive_int(selected_user, 0):
        conditions.append(AuditLog.user_id == int(selected_user))
    else:
        selected_user = "all"

    sort_columns = {
        "created_at": AuditLog.created_at,
        "username": func.coalesce(func.lower(User.username), ""),
        "action": func.lower(AuditLog.action),
        "entity": func.coalesce(func.lower(AuditLog.entity_type), ""),
        "ip_address": func.coalesce(AuditLog.ip_address, ""),
        "details": func.coalesce(func.lower(AuditLog.details), ""),
    }
    total = session.scalar(
        select(func.count(AuditLog.id))
        .select_from(AuditLog)
        .outerjoin(User, User.id == AuditLog.user_id)
        .where(*conditions)
    ) or 0
    pager = Pagination.from_request(request, total)
    rows = session.execute(
        select(AuditLog, User.username)
        .outerjoin(User, User.id == AuditLog.user_id)
        .where(*conditions)
        .order_by(
            sort_state.order(sort_columns[sort_state.column]),
            sort_state.order(AuditLog.id),
        )
        .offset(pager.offset)
        .limit(pager.per_page)
    ).all()
    display_datetime = session_datetime_formatter(session)
    audit_rows = [
        (
            entry,
            username,
            format_audit_entry_text(entry, username, display_datetime),
            audit_details_for_table(entry.details),
        )
        for entry, username in rows
    ]
    users = session.scalars(select(User).order_by(func.lower(User.username), User.id)).all()
    actions = session.scalars(
        select(AuditLog.action).distinct().order_by(AuditLog.action)
    ).all()
    entity_types = session.scalars(
        select(AuditLog.entity_type)
        .where(AuditLog.entity_type.is_not(None))
        .distinct()
        .order_by(AuditLog.entity_type)
    ).all()
    return templates.TemplateResponse(
        request=request,
        name="audit.html",
        context=template_context(
            request,
            auth,
            audit_rows=audit_rows,
            pager=pager,
            users=users,
            actions=actions,
            entity_types=entity_types,
            sort_state=sort_state,
            filters={
                "q": search,
                "action": selected_action,
                "entity_type": selected_entity,
                "user_id": selected_user,
            },
            display_datetime=display_datetime,
            audit_export_query=urlencode(
                {
                    "q": search,
                    "action": selected_action,
                    "entity_type": selected_entity,
                    "user_id": selected_user,
                    "sort": sort_state.column,
                    "direction": sort_state.direction,
                }
            ),
        ),
    )



@router.get("/audit/export/{export_format}")
def audit_export(
    export_format: str,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
) -> Response:
    if export_format not in {"xlsx", "json"}:
        raise HTTPException(status_code=404, detail="Неизвестный формат экспорта")
    scope = request.query_params.get("scope", "current")
    if scope not in {"current", "all"}:
        scope = "current"

    search = request.query_params.get("q", "").strip()[:100]
    selected_action = request.query_params.get("action", "").strip()[:80]
    selected_entity = request.query_params.get("entity_type", "").strip()[:50]
    selected_user = request.query_params.get("user_id", "all")
    sort_state = SortState.from_request(
        request,
        {"created_at", "username", "action", "entity", "ip_address", "details"},
        "created_at",
        "desc",
    )
    conditions = []
    if scope == "current":
        if search:
            pattern = f"%{search.casefold()}%"
            conditions.append(
                or_(
                    func.lower(AuditLog.action).like(pattern),
                    func.lower(AuditLog.entity_type).like(pattern),
                    func.lower(AuditLog.entity_id).like(pattern),
                    func.lower(AuditLog.ip_address).like(pattern),
                    func.lower(AuditLog.details).like(pattern),
                    func.lower(User.username).like(pattern),
                )
            )
        if selected_action:
            conditions.append(AuditLog.action == selected_action)
        if selected_entity:
            conditions.append(AuditLog.entity_type == selected_entity)
        if selected_user == "system":
            conditions.append(AuditLog.user_id.is_(None))
        elif positive_int(selected_user, 0):
            conditions.append(AuditLog.user_id == int(selected_user))
        else:
            selected_user = "all"
    else:
        search = ""
        selected_action = ""
        selected_entity = ""
        selected_user = "all"
        sort_state = SortState("created_at", "desc")

    sort_columns = {
        "created_at": AuditLog.created_at,
        "username": func.coalesce(func.lower(User.username), ""),
        "action": func.lower(AuditLog.action),
        "entity": func.coalesce(func.lower(AuditLog.entity_type), ""),
        "ip_address": func.coalesce(AuditLog.ip_address, ""),
        "details": func.coalesce(func.lower(AuditLog.details), ""),
    }
    rows = session.execute(
        select(AuditLog, User.username)
        .outerjoin(User, User.id == AuditLog.user_id)
        .where(*conditions)
        .order_by(
            sort_state.order(sort_columns[sort_state.column]),
            sort_state.order(AuditLog.id),
        )
    ).all()
    display_datetime = session_datetime_formatter(session)
    stamp = utc_now().strftime("%Y%m%d-%H%M")
    scope_name = "current" if scope == "current" else "all"

    if export_format == "xlsx":
        data = xlsx_bytes(
            "Аудит",
            ("Время", "Пользователь", "Действие", "Тип объекта", "Название", "ID", "IP", "Подробности"),
            (
                (
                    display_datetime(entry.created_at),
                    username or "система",
                    entry.action,
                    entry.entity_type or "",
                    audit_entity_name(entry.details) or "",
                    entry.entity_id or "",
                    entry.ip_address or "",
                    audit_details_for_table(entry.details),
                )
                for entry, username in rows
            ),
        )
        return Response(
            data,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f'attachment; filename="audit-{scope_name}-{stamp}.xlsx"'},
        )

    records = []
    for entry, username in rows:
        records.append(
            {
                "id": entry.id,
                "created_at": entry.created_at.isoformat(),
                "display_time": display_datetime(entry.created_at),
                "user": username or "система",
                "user_id": entry.user_id,
                "action": entry.action,
                "entity_type": entry.entity_type,
                "entity_name": audit_entity_name(entry.details),
                "entity_id": entry.entity_id,
                "ip_address": entry.ip_address,
                "details": json.loads(audit_details_for_table(entry.details)) if entry.details and audit_details_for_table(entry.details).startswith("{") else audit_details_for_table(entry.details),
            }
        )
    payload = {
        "exported_at": utc_now().isoformat(),
        "scope": scope,
        "count": len(records),
        "filters": {
            "q": search,
            "action": selected_action,
            "entity_type": selected_entity,
            "user_id": selected_user,
        }
        if scope == "current"
        else {},
        "sort": {"column": sort_state.column, "direction": sort_state.direction},
        "records": records,
    }
    return Response(
        json.dumps(payload, ensure_ascii=False, indent=2),
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="audit-{scope_name}-{stamp}.json"'},
    )


@router.post("/incidents/{incident_id}/disable-target")
def incident_target_disable(
    incident_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "/incidents",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Инцидент не найден")
    target = session.get(MonitorTarget, incident.target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Объект не найден")
    if not target.enabled:
        return redirect_with(
            safe_return_path(return_to, "/incidents"),
            "notice",
            "Объект уже отключён",
        )
    target.enabled = False
    reset_unstable_link(target)
    for check in target.checks:
        reset_unstable_link(check)
    write_audit(
        session,
        "target.enabled_changed",
        user_id=auth.user.id,
        entity_type="target",
        entity_id=target.id,
        entity_name=target.name,
        details={"enabled": False, "incident_id": incident.id, "source": "incident"},
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(
        safe_return_path(return_to, "/incidents"),
        "notice",
        "Объект отключён",
    )


@router.post("/incidents/{incident_id}/delete")
def incident_delete(
    incident_id: int,
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "/incidents",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Инцидент не найден")
    target_id = incident.target_id
    target = session.get(MonitorTarget, target_id)
    target_name = target.name if target is not None else f"Объект ID {target_id}"
    session.delete(incident)
    write_audit(
        session,
        "incident.deleted",
        user_id=auth.user.id,
        entity_type="incident",
        entity_id=incident_id,
        entity_name=target_name,
        details={"target_id": target_id},
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(
        safe_return_path(return_to, "/incidents"), "notice", "Инцидент удалён"
    )


@router.post("/incidents/delete-all")
def incidents_delete_all(
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "/incidents",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    incident_count = session.scalar(select(func.count(Incident.id))) or 0
    session.execute(delete(Incident))
    write_audit(
        session,
        "incident.all_deleted",
        user_id=auth.user.id,
        entity_type="incident",
        details={"count": incident_count},
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(
        safe_return_path(return_to, "/incidents"),
        "notice",
        f"Удалено инцидентов: {incident_count}",
    )


@router.post("/incidents/delete-resolved")
def incidents_delete_resolved(
    request: Request,
    session: DbSession,
    auth: AdminAuth,
    csrf_token: Annotated[str, Form()],
    return_to: Annotated[str, Form()] = "/incidents",
) -> RedirectResponse:
    require_csrf(auth, csrf_token)
    incident_count = session.scalar(
        select(func.count(Incident.id)).where(Incident.status == "resolved")
    ) or 0
    session.execute(delete(Incident).where(Incident.status == "resolved"))
    write_audit(
        session,
        "incident.resolved_deleted",
        user_id=auth.user.id,
        entity_type="incident",
        details={"count": incident_count},
        ip_address=client_ip(request),
    )
    session.commit()
    return redirect_with(
        safe_return_path(return_to, "/incidents"),
        "notice",
        f"Удалено закрытых инцидентов: {incident_count}",
    )
