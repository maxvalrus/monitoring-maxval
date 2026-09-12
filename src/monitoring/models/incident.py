from datetime import datetime
from enum import StrEnum

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from monitoring.db import Base
from monitoring.models.mixins import utc_now


class IncidentStatus(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"


class IncidentSourceKind(StrEnum):
    AVAILABILITY = "availability"
    SNMP = "snmp"
    CHECK = "check"
    CHECK_TLS = "check_tls"


class IncidentSeverity(StrEnum):
    WARNING = "warning"
    CRITICAL = "critical"


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint("status IN ('open', 'resolved')", name="ck_incident_status"),
        CheckConstraint(
            "source_kind IN ('availability', 'snmp', 'check', 'check_tls')",
            name="ck_incident_source_kind",
        ),
        CheckConstraint(
            "severity IS NULL OR severity IN ('warning', 'critical')",
            name="ck_incident_severity",
        ),
        Index("ix_incidents_target_status", "target_id", "status"),
        Index("ix_incidents_check_status", "check_id", "status"),
        Index(
            "ix_incidents_target_source_status",
            "target_id",
            "source_kind",
            "source_key",
            "status",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("monitor_targets.id", ondelete="CASCADE"), index=True
    )
    check_id: Mapped[int | None] = mapped_column(
        ForeignKey("target_checks.id", ondelete="SET NULL"), index=True
    )
    status: Mapped[str] = mapped_column(String(20), default=IncidentStatus.OPEN, index=True)
    source_kind: Mapped[str] = mapped_column(
        String(20),
        default=IncidentSourceKind.AVAILABILITY,
        server_default=IncidentSourceKind.AVAILABILITY,
    )
    source_key: Mapped[str | None] = mapped_column(String(120))
    severity: Mapped[str | None] = mapped_column(String(16))
    failure_count: Mapped[int] = mapped_column(Integer, default=1)
    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_failure_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_message: Mapped[str | None] = mapped_column(String(500))
    open_notification_attempted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    recovery_notification_attempted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )

    target = relationship("MonitorTarget", back_populates="incidents")
    check = relationship("TargetCheck")
