from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from monitoring.db import Base
from monitoring.models.mixins import TimestampMixin


class WorkSchedule(TimestampMixin, Base):
    __tablename__ = "work_schedules"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    is_24x7: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    built_in: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")

    monday_start: Mapped[str | None] = mapped_column(String(5))
    monday_end: Mapped[str | None] = mapped_column(String(5))
    tuesday_start: Mapped[str | None] = mapped_column(String(5))
    tuesday_end: Mapped[str | None] = mapped_column(String(5))
    wednesday_start: Mapped[str | None] = mapped_column(String(5))
    wednesday_end: Mapped[str | None] = mapped_column(String(5))
    thursday_start: Mapped[str | None] = mapped_column(String(5))
    thursday_end: Mapped[str | None] = mapped_column(String(5))
    friday_start: Mapped[str | None] = mapped_column(String(5))
    friday_end: Mapped[str | None] = mapped_column(String(5))
    saturday_start: Mapped[str | None] = mapped_column(String(5))
    saturday_end: Mapped[str | None] = mapped_column(String(5))
    sunday_start: Mapped[str | None] = mapped_column(String(5))
    sunday_end: Mapped[str | None] = mapped_column(String(5))

    sites = relationship("Site", back_populates="schedule")
