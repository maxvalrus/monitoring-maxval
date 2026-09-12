from sqlalchemy import func, select
from sqlalchemy.orm import Session

from monitoring.models import MonitorTarget


def next_display_order(session: Session, favorite: bool) -> int:
    current = session.scalar(
        select(func.max(MonitorTarget.display_order)).where(
            MonitorTarget.favorite.is_(favorite)
        )
    )
    return int(current or 0) + 1


def move_to_group_end(session: Session, target: MonitorTarget, favorite: bool) -> None:
    target.favorite = favorite
    target.display_order = next_display_order(session, favorite)


def move_target(session: Session, target: MonitorTarget, direction: str) -> bool:
    if direction not in {"up", "down"}:
        raise ValueError("Неизвестное направление перемещения")
    group = list(
        session.scalars(
            select(MonitorTarget)
            .where(MonitorTarget.favorite.is_(target.favorite))
            .order_by(MonitorTarget.display_order, MonitorTarget.id)
        ).all()
    )
    if not group:
        return False

    for index, item in enumerate(group, start=1):
        item.display_order = index

    position = next((index for index, item in enumerate(group) if item.id == target.id), None)
    if position is None:
        return False
    neighbour_position = position - 1 if direction == "up" else position + 1
    if neighbour_position < 0 or neighbour_position >= len(group):
        return False

    neighbour = group[neighbour_position]
    target.display_order, neighbour.display_order = (
        neighbour.display_order,
        target.display_order,
    )
    return True
