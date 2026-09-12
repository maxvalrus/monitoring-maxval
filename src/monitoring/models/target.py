from datetime import datetime
from enum import StrEnum

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from monitoring.db import Base
from monitoring.models.mixins import TimestampMixin


class TargetKind(StrEnum):
    SERVER = "server"
    COMPUTER = "computer"
    NETWORK = "network"
    PRINTER = "printer"
    UPS = "ups"
    CAMERA = "camera"
    WEBSITE = "website"
    SERVICE = "service"


class MonitorTarget(TimestampMixin, Base):
    __tablename__ = "monitor_targets"
    __table_args__ = (
        CheckConstraint("interval_seconds >= 60", name="ck_target_interval_minimum"),
        CheckConstraint("port > 0 AND port <= 65535", name="ck_target_port_range"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"), index=True)
    name: Mapped[str] = mapped_column(String(160), index=True)
    kind: Mapped[str] = mapped_column(String(30), default=TargetKind.SERVICE)
    checker_type: Mapped[str] = mapped_column(String(50), default="tcp")
    address: Mapped[str] = mapped_column(String(255))
    comment: Mapped[str | None] = mapped_column(String(1000))
    port: Mapped[int] = mapped_column(Integer)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=300, server_default="300")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    favorite: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    # A site has at most one entry point.  It is an availability gate, not a
    # generic dependency graph: its primary DOWN suppresses only sibling polling.
    is_site_entry: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )
    display_order: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    # Relative position on the optional visual layout of the target's site.
    # NULL deliberately means that an administrator has not placed it yet.
    layout_x: Mapped[int | None] = mapped_column(Integer)
    layout_y: Mapped[int | None] = mapped_column(Integer)
    notifications_suppressed: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false"
    )
    unstable_pending_down: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )
    unstable_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    site = relationship("Site", back_populates="targets")
    results = relationship("CheckResult", back_populates="target", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="target", cascade="all, delete-orphan")
    checks = relationship(
        "TargetCheck",
        back_populates="target",
        cascade="all, delete-orphan",
        order_by="TargetCheck.display_order, TargetCheck.id",
    )
    snmp_config = relationship(
        "SnmpConfig", back_populates="target", cascade="all, delete-orphan", uselist=False
    )
    snmp_metrics = relationship("SnmpMetric", back_populates="target", cascade="all, delete-orphan")
    snmp_interfaces = relationship(
        "SnmpInterface", back_populates="target", cascade="all, delete-orphan"
    )
    snmp_supplies = relationship(
        "SnmpSupply", back_populates="target", cascade="all, delete-orphan"
    )
    snmp_ups_state = relationship(
        "SnmpUpsState", back_populates="target", cascade="all, delete-orphan", uselist=False
    )
