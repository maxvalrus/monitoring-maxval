from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Float
from sqlalchemy.orm import Mapped, mapped_column

from monitoring.db import Base
from monitoring.models.mixins import utc_now


class PortalMetric(Base):
    __tablename__ = "portal_metrics"
    id: Mapped[int] = mapped_column(primary_key=True)
    cpu_percent: Mapped[float] = mapped_column(Float)
    memory_percent: Mapped[float] = mapped_column(Float)
    disk_percent: Mapped[float] = mapped_column(Float)
    uptime_seconds: Mapped[int] = mapped_column(BigInteger)
    bytes_sent: Mapped[int] = mapped_column(BigInteger)
    bytes_received: Mapped[int] = mapped_column(BigInteger)
    packets_sent: Mapped[int] = mapped_column(BigInteger)
    packets_received: Mapped[int] = mapped_column(BigInteger)
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )
