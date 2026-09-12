from sqlalchemy import Boolean, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from monitoring.db import Base
from monitoring.models.mixins import TimestampMixin


class Site(TimestampMixin, Base):
    __tablename__ = "sites"

    id: Mapped[int] = mapped_column(primary_key=True)
    schedule_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("work_schedules.id", ondelete="RESTRICT"),
        default=0,
        server_default="0",
        index=True,
    )
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(String(500))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    display_order: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    # Shared by the editor and the read-only TV wallboard for this site.
    layout_scale: Mapped[int] = mapped_column(
        Integer, default=100, server_default="100", nullable=False
    )

    schedule = relationship("WorkSchedule", back_populates="sites")
    targets = relationship("MonitorTarget", back_populates="site")
