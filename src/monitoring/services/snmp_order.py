from sqlalchemy import select
from sqlalchemy.orm import Session

from monitoring.models import SnmpMetric


def move_metric(session: Session, metric: SnmpMetric, direction: str) -> bool:
    if direction not in {"up", "down"}:
        raise ValueError("Неизвестное направление перемещения")

    metrics = list(
        session.scalars(
            select(SnmpMetric)
            .where(SnmpMetric.target_id == metric.target_id)
            .order_by(SnmpMetric.display_order, SnmpMetric.id)
        ).all()
    )
    for index, item in enumerate(metrics, start=1):
        item.display_order = index

    position = next((index for index, item in enumerate(metrics) if item.id == metric.id), None)
    if position is None:
        return False
    neighbour_position = position - 1 if direction == "up" else position + 1
    if neighbour_position < 0 or neighbour_position >= len(metrics):
        return False

    neighbour = metrics[neighbour_position]
    metric.display_order, neighbour.display_order = (
        neighbour.display_order,
        metric.display_order,
    )
    return True
