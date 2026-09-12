import csv
import io
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from monitoring.checks import checker_registry
from monitoring.models import MonitorTarget, Site, TargetKind
from monitoring.services.target_checks import primary_checker_names, sync_target_primary_check

CSV_FIELDS = (
    "site",
    "name",
    "kind",
    "checker_type",
    "address",
    "comment",
    "port",
    "interval_seconds",
    "enabled",
    "notifications_suppressed",
    "favorite",
)


@dataclass(frozen=True, slots=True)
class ImportResult:
    created: int
    updated: int
    sites_created: int


def export_targets_csv(session: Session) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_FIELDS)
    writer.writeheader()
    rows = session.execute(
        select(MonitorTarget, Site)
        .join(Site, Site.id == MonitorTarget.site_id)
        .order_by(Site.name, MonitorTarget.name, MonitorTarget.id)
    ).all()
    for target, site in rows:
        writer.writerow(
            {
                "site": site.name,
                "name": target.name,
                "kind": target.kind,
                "checker_type": target.checker_type,
                "address": target.address,
                "comment": target.comment or "",
                "port": target.port,
                "interval_seconds": target.interval_seconds,
                "enabled": "true" if target.enabled else "false",
                "notifications_suppressed": (
                    "true" if target.notifications_suppressed else "false"
                ),
                "favorite": "true" if target.favorite else "false",
            }
        )
    return output.getvalue()


def _integer(value: str, label: str, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{label}: ожидается целое число") from exc
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{label}: допустимо {minimum}–{maximum}")
    return parsed


def _clean_row(row: dict[str, str | None], number: int) -> dict[str, object]:
    missing = [field for field in CSV_FIELDS if field not in row]
    if missing:
        raise ValueError(f"Отсутствуют колонки: {', '.join(missing)}")
    values = {key: (row.get(key) or "").strip() for key in CSV_FIELDS}
    if not 2 <= len(values["site"]) <= 120:
        raise ValueError(f"Строка {number}: некорректная площадка")
    if not 2 <= len(values["name"]) <= 160:
        raise ValueError(f"Строка {number}: некорректное название")
    address = values["address"]
    if len(values["comment"]) > 1000:
        raise ValueError(f"Строка {number}: комментарий не должен превышать 1000 символов")
    if not address or len(address) > 255 or any(char.isspace() for char in address):
        raise ValueError(f"Строка {number}: некорректный IP или DNS")
    if values["kind"] not in {item.value for item in TargetKind}:
        raise ValueError(f"Строка {number}: неизвестный тип объекта")
    if values["checker_type"] not in primary_checker_names(checker_registry):
        raise ValueError(f"Строка {number}: неизвестная проверка")
    if values["enabled"].casefold() not in {"true", "false", "1", "0"}:
        raise ValueError(f"Строка {number}: enabled должен быть true или false")
    if values["notifications_suppressed"].casefold() not in {
        "true",
        "false",
        "1",
        "0",
    }:
        raise ValueError(
            f"Строка {number}: notifications_suppressed должен быть true или false"
        )
    if values["favorite"].casefold() not in {"true", "false", "1", "0"}:
        raise ValueError(f"Строка {number}: favorite должен быть true или false")
    return {
        **values,
        "port": _integer(values["port"], f"Строка {number}, порт", 1, 65535),
        "interval_seconds": _integer(
            values["interval_seconds"],
            f"Строка {number}, интервал",
            60,
            86400,
        ),
        "enabled": values["enabled"].casefold() in {"true", "1"},
        "notifications_suppressed": values[
            "notifications_suppressed"
        ].casefold()
        in {"true", "1"},
        "favorite": values["favorite"].casefold() in {"true", "1"},
    }


def import_targets_csv(session: Session, content: bytes) -> ImportResult:
    if len(content) > 1_000_000:
        raise ValueError("CSV-файл не должен превышать 1 МБ")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("CSV-файл должен быть в кодировке UTF-8") from exc
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        raise ValueError("CSV-файл пуст")
    if tuple(reader.fieldnames) != CSV_FIELDS:
        raise ValueError("Неверный набор или порядок колонок CSV")
    raw_rows = list(reader)
    if len(raw_rows) > 1000:
        raise ValueError("За один раз можно импортировать не более 1000 объектов")
    clean_rows = [_clean_row(row, number) for number, row in enumerate(raw_rows, start=2)]

    sites = {
        site.name.casefold(): site
        for site in session.scalars(select(Site).order_by(Site.id)).all()
    }
    existing = {
        (target.site_id, target.name.casefold()): target
        for target in session.scalars(select(MonitorTarget).order_by(MonitorTarget.id)).all()
    }
    next_orders = {
        favorite: int(
            session.scalar(
                select(func.max(MonitorTarget.display_order)).where(
                    MonitorTarget.favorite.is_(favorite)
                )
            )
            or 0
        )
        for favorite in (False, True)
    }
    created = updated = sites_created = 0
    touched_targets: list[MonitorTarget] = []
    for row in clean_rows:
        site_name = str(row["site"])
        site = sites.get(site_name.casefold())
        if site is None:
            duplicate = session.scalar(
                select(Site).where(func.lower(Site.name) == site_name.casefold())
            )
            site = duplicate or Site(name=site_name)
            if duplicate is None:
                session.add(site)
                session.flush()
                sites_created += 1
            sites[site_name.casefold()] = site
        key = (site.id, str(row["name"]).casefold())
        target = existing.get(key)
        favorite = bool(row["favorite"])
        if target is None:
            next_orders[favorite] += 1
            target = MonitorTarget(
                site_id=site.id,
                name=str(row["name"]),
                favorite=favorite,
                display_order=next_orders[favorite],
            )
            session.add(target)
            existing[key] = target
            created += 1
        else:
            updated += 1
            if target.favorite != favorite:
                next_orders[favorite] += 1
                target.favorite = favorite
                target.display_order = next_orders[favorite]
        target.kind = str(row["kind"])
        target.checker_type = str(row["checker_type"])
        target.address = str(row["address"])
        target.comment = str(row["comment"]) or None
        target.port = int(row["port"])
        target.interval_seconds = int(row["interval_seconds"])
        target.enabled = bool(row["enabled"])
        target.notifications_suppressed = bool(row["notifications_suppressed"])
        touched_targets.append(target)
    session.flush()
    for target in touched_targets:
        sync_target_primary_check(session, target)
    return ImportResult(created=created, updated=updated, sites_created=sites_created)
