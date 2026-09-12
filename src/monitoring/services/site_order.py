from sqlalchemy import func, select
from sqlalchemy.orm import Session

from monitoring.models import Site


def next_site_display_order(session: Session) -> int:
    current = session.scalar(select(func.max(Site.display_order)))
    return int(current or 0) + 1


def move_site(session: Session, site: Site, direction: str) -> bool:
    if direction not in {"up", "down"}:
        raise ValueError("Неизвестное направление перемещения")

    sites = list(
        session.scalars(select(Site).order_by(Site.display_order, Site.id)).all()
    )
    for index, item in enumerate(sites, start=1):
        item.display_order = index

    position = next((index for index, item in enumerate(sites) if item.id == site.id), None)
    if position is None:
        return False
    neighbour_position = position - 1 if direction == "up" else position + 1
    if neighbour_position < 0 or neighbour_position >= len(sites):
        return False

    neighbour = sites[neighbour_position]
    site.display_order, neighbour.display_order = (
        neighbour.display_order,
        site.display_order,
    )
    return True
