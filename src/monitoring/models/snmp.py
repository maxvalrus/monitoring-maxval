from datetime import datetime
from decimal import Decimal
from enum import StrEnum

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from monitoring.db import Base
from monitoring.models.mixins import utc_now


class SnmpStatus(StrEnum):
    NEVER = "never"
    OK = "ok"
    ERROR = "error"


class SnmpConfig(Base):
    __tablename__ = "snmp_configs"
    __table_args__ = (
        CheckConstraint("port > 0 AND port <= 65535", name="ck_snmp_config_port_range"),
        CheckConstraint("timeout_seconds >= 1 AND timeout_seconds <= 60", name="ck_snmp_config_timeout_range"),
        CheckConstraint("retries >= 0 AND retries <= 10", name="ck_snmp_config_retries_range"),
    )

    target_id: Mapped[int] = mapped_column(
        ForeignKey("monitor_targets.id", ondelete="CASCADE"), primary_key=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    version: Mapped[str] = mapped_column(String(10), default="v2c", server_default="v2c")
    port: Mapped[int] = mapped_column(Integer, default=161, server_default="161")
    community_encrypted: Mapped[str] = mapped_column(Text, default="", server_default="")
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=3, server_default="3")
    retries: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    ups_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    last_status: Mapped[str] = mapped_column(String(10), default=SnmpStatus.NEVER, server_default="never")
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(500))
    sys_name: Mapped[str | None] = mapped_column(Text)
    sys_descr: Mapped[str | None] = mapped_column(Text)
    sys_object_id: Mapped[str | None] = mapped_column(String(255))
    sys_uptime_ticks: Mapped[int | None] = mapped_column(BigInteger)
    system_data_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    target = relationship("MonitorTarget", back_populates="snmp_config")


class SnmpUpsState(Base):
    """Normalized current UPS-MIB state.  One optional state per SNMP target."""

    __tablename__ = "snmp_ups_states"

    target_id: Mapped[int] = mapped_column(
        ForeignKey("monitor_targets.id", ondelete="CASCADE"), primary_key=True
    )
    manufacturer: Mapped[str | None] = mapped_column(String(255))
    model: Mapped[str | None] = mapped_column(String(255))
    profile: Mapped[str | None] = mapped_column(String(32))
    battery_status: Mapped[int | None] = mapped_column(Integer)
    output_source: Mapped[int | None] = mapped_column(Integer)
    seconds_on_battery: Mapped[int | None] = mapped_column(BigInteger)
    estimated_runtime_minutes: Mapped[Decimal | None] = mapped_column(Numeric(12, 1))
    battery_charge_percent: Mapped[Decimal | None] = mapped_column(Numeric(7, 2))
    battery_voltage: Mapped[Decimal | None] = mapped_column(Numeric(12, 2))
    battery_temperature: Mapped[Decimal | None] = mapped_column(Numeric(12, 2))
    battery_replace_needed: Mapped[bool | None] = mapped_column(Boolean)
    last_transfer_reason: Mapped[str | None] = mapped_column(String(255))
    last_self_test_result: Mapped[str | None] = mapped_column(String(100))
    # APC PowerNet exposes this as a display string (typically dd/mm/yy), without
    # a timezone. Keep it verbatim instead of inventing a potentially wrong time.
    last_self_test_at: Mapped[str | None] = mapped_column(String(100))
    input_lines: Mapped[int | None] = mapped_column(Integer)
    output_lines: Mapped[int | None] = mapped_column(Integer)
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(500))

    target = relationship("MonitorTarget", back_populates="snmp_ups_state")
    lines = relationship("SnmpUpsLine", back_populates="state", cascade="all, delete-orphan")
    samples = relationship("SnmpUpsSample", back_populates="state", cascade="all, delete-orphan")
    events = relationship("SnmpUpsEvent", back_populates="state", cascade="all, delete-orphan")


class SnmpUpsLine(Base):
    __tablename__ = "snmp_ups_lines"
    __table_args__ = (UniqueConstraint("target_id", "direction", "line_index", name="uq_snmp_ups_line"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("snmp_ups_states.target_id", ondelete="CASCADE"), index=True)
    direction: Mapped[str] = mapped_column(String(10))
    line_index: Mapped[int] = mapped_column(Integer)
    voltage: Mapped[Decimal | None] = mapped_column(Numeric(12, 2))
    frequency: Mapped[Decimal | None] = mapped_column(Numeric(12, 2))
    current: Mapped[Decimal | None] = mapped_column(Numeric(12, 2))
    power: Mapped[Decimal | None] = mapped_column(Numeric(16, 2))
    load_percent: Mapped[Decimal | None] = mapped_column(Numeric(7, 2))
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    state = relationship("SnmpUpsState", back_populates="lines")


class SnmpUpsSample(Base):
    __tablename__ = "snmp_ups_samples"
    __table_args__ = (Index("ix_snmp_ups_samples_target_metric_collected", "target_id", "metric_key", "collected_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("snmp_ups_states.target_id", ondelete="CASCADE"), index=True)
    metric_key: Mapped[str] = mapped_column(String(80))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    value: Mapped[Decimal] = mapped_column(Numeric(20, 4))

    state = relationship("SnmpUpsState", back_populates="samples")


class SnmpUpsEvent(Base):
    __tablename__ = "snmp_ups_events"
    __table_args__ = (Index("ix_snmp_ups_events_target_collected", "target_id", "collected_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("snmp_ups_states.target_id", ondelete="CASCADE"), index=True)
    event_key: Mapped[str] = mapped_column(String(40))
    value: Mapped[int] = mapped_column(Integer)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    state = relationship("SnmpUpsState", back_populates="events")


class SnmpMetric(Base):
    __tablename__ = "snmp_metrics"
    __table_args__ = (
        UniqueConstraint("target_id", "oid", name="uq_snmp_metric_target_oid"),
        CheckConstraint(
            "(source_kind = 'oid' AND oid IS NOT NULL AND formula IS NULL) OR "
            "(source_kind = 'formula' AND oid IS NULL AND formula IS NOT NULL)",
            name="ck_snmp_metric_source",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("monitor_targets.id", ondelete="CASCADE"), index=True
    )
    oid: Mapped[str | None] = mapped_column(String(255))
    source_kind: Mapped[str] = mapped_column(String(16), default="oid", server_default="oid")
    formula: Mapped[str | None] = mapped_column(Text)
    name: Mapped[str] = mapped_column(String(160))
    unit: Mapped[str | None] = mapped_column(String(80))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    display_order: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    detected_type: Mapped[str | None] = mapped_column(String(40))
    last_value: Mapped[str | None] = mapped_column(Text)
    last_numeric_value: Mapped[Decimal | None] = mapped_column(Numeric(30, 10))
    last_collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(500))

    target = relationship("MonitorTarget", back_populates="snmp_metrics")
    samples = relationship("SnmpSample", back_populates="metric", cascade="all, delete-orphan")


class SnmpInterface(Base):
    __tablename__ = "snmp_interfaces"
    __table_args__ = (
        CheckConstraint("if_index > 0", name="ck_snmp_interface_index_positive"),
        UniqueConstraint("target_id", "if_index", name="uq_snmp_interface_target_index"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("monitor_targets.id", ondelete="CASCADE"), index=True
    )
    if_index: Mapped[int] = mapped_column(Integer)
    if_name: Mapped[str | None] = mapped_column(String(255))
    if_descr: Mapped[str | None] = mapped_column(Text)
    if_alias: Mapped[str | None] = mapped_column(Text)
    if_type: Mapped[int | None] = mapped_column(Integer)
    if_mtu: Mapped[int | None] = mapped_column(Integer)
    speed_bps: Mapped[int | None] = mapped_column(BigInteger)
    phys_address: Mapped[str | None] = mapped_column(String(255))
    admin_status: Mapped[int | None] = mapped_column(Integer)
    oper_status: Mapped[int | None] = mapped_column(Integer)
    traffic_counter_mode: Mapped[str | None] = mapped_column(String(16))
    # Counters are strings: Counter64 can exceed portable SQL integer ranges.
    in_octets: Mapped[str | None] = mapped_column(String(32))
    out_octets: Mapped[str | None] = mapped_column(String(32))
    traffic_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    traffic_uptime_ticks: Mapped[int | None] = mapped_column(BigInteger)
    rx_bps: Mapped[int | None] = mapped_column(BigInteger)
    tx_bps: Mapped[int | None] = mapped_column(BigInteger)
    in_errors: Mapped[int | None] = mapped_column(BigInteger)
    out_errors: Mapped[int | None] = mapped_column(BigInteger)
    in_discards: Mapped[int | None] = mapped_column(BigInteger)
    out_discards: Mapped[int | None] = mapped_column(BigInteger)
    traffic_error: Mapped[str | None] = mapped_column(String(500))
    monitor_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    present: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(500))

    target = relationship("MonitorTarget", back_populates="snmp_interfaces")
    samples = relationship(
        "SnmpInterfaceSample",
        back_populates="interface",
        cascade="all, delete-orphan",
    )
    thresholds = relationship(
        "SnmpThreshold",
        back_populates="interface",
        cascade="all, delete-orphan",
    )


class SnmpInterfaceSample(Base):
    __tablename__ = "snmp_interface_samples"
    __table_args__ = (
        Index(
            "ix_snmp_interface_samples_interface_collected",
            "interface_id",
            "collected_at",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    interface_id: Mapped[int] = mapped_column(
        ForeignKey("snmp_interfaces.id", ondelete="CASCADE"), index=True
    )
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now
    )
    rx_bps: Mapped[int | None] = mapped_column(BigInteger)
    tx_bps: Mapped[int | None] = mapped_column(BigInteger)
    in_errors: Mapped[int | None] = mapped_column(BigInteger)
    out_errors: Mapped[int | None] = mapped_column(BigInteger)
    in_discards: Mapped[int | None] = mapped_column(BigInteger)
    out_discards: Mapped[int | None] = mapped_column(BigInteger)

    interface = relationship("SnmpInterface", back_populates="samples")


class SnmpSupply(Base):
    __tablename__ = "snmp_supplies"
    __table_args__ = (
        CheckConstraint("hr_device_index > 0", name="ck_snmp_supply_hr_device_positive"),
        CheckConstraint("supply_index > 0", name="ck_snmp_supply_index_positive"),
        UniqueConstraint(
            "target_id",
            "hr_device_index",
            "supply_index",
            name="uq_snmp_supply_target_index",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("monitor_targets.id", ondelete="CASCADE"), index=True
    )
    hr_device_index: Mapped[int] = mapped_column(Integer)
    supply_index: Mapped[int] = mapped_column(Integer)
    marker_index: Mapped[int | None] = mapped_column(Integer)
    colorant_index: Mapped[int | None] = mapped_column(Integer)
    supply_class: Mapped[int | None] = mapped_column(Integer)
    supply_type: Mapped[int | None] = mapped_column(Integer)
    description: Mapped[str | None] = mapped_column(Text)
    custom_name: Mapped[str | None] = mapped_column(String(160))
    unit_code: Mapped[int | None] = mapped_column(Integer)
    max_capacity: Mapped[int | None] = mapped_column(BigInteger)
    level: Mapped[int | None] = mapped_column(BigInteger)
    percent_remaining: Mapped[float | None] = mapped_column(Float)
    level_state: Mapped[str] = mapped_column(
        String(20), default="never", server_default="never"
    )
    present: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    first_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=utc_now
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=utc_now
    )
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(500))

    target = relationship("MonitorTarget", back_populates="snmp_supplies")
    thresholds = relationship(
        "SnmpThreshold",
        back_populates="supply",
        cascade="all, delete-orphan",
    )

    @property
    def display_name(self) -> str:
        return self.custom_name or self.description or f"Расходник {self.supply_index}"


class SnmpThreshold(Base):
    __tablename__ = "snmp_thresholds"
    __table_args__ = (
        CheckConstraint(
            "source_kind IN ('metric', 'interface', 'supply', 'ups')",
            name="ck_snmp_threshold_source_kind",
        ),
        CheckConstraint(
            "operator IN ('gt', 'lt')",
            name="ck_snmp_threshold_operator",
        ),
        CheckConstraint(
            "current_level IN ('normal', 'warning', 'critical')",
            name="ck_snmp_threshold_level",
        ),
        CheckConstraint(
            "warning_value IS NOT NULL OR critical_value IS NOT NULL",
            name="ck_snmp_threshold_has_value",
        ),
        CheckConstraint(
            "("
            "source_kind = 'metric' AND metric_id IS NOT NULL "
            "AND interface_id IS NULL AND supply_id IS NULL AND field = 'value'"
            ") OR ("
            "source_kind = 'interface' AND interface_id IS NOT NULL "
            "AND metric_id IS NULL AND supply_id IS NULL "
            "AND field IN ('rx_bps', 'tx_bps', 'errors_delta', 'discards_delta')"
            ") OR ("
            "source_kind = 'supply' AND supply_id IS NOT NULL "
            "AND metric_id IS NULL AND interface_id IS NULL AND field = 'percent'"
            ") OR ("
            "source_kind = 'ups' AND metric_id IS NULL AND interface_id IS NULL "
            "AND supply_id IS NULL AND field IN ("
            "'battery_charge_percent', 'estimated_runtime_minutes', 'battery_voltage', "
            "'battery_temperature', 'input_voltage:1', 'input_voltage:2', 'input_voltage:3', "
            "'output_voltage:1', 'output_voltage:2', 'output_voltage:3', "
            "'input_current:1', 'input_current:2', 'input_current:3', "
            "'output_current:1', 'output_current:2', 'output_current:3', "
            "'output_load_percent:1', 'output_load_percent:2', 'output_load_percent:3'"
            ")"
            ")",
            name="ck_snmp_threshold_source",
        ),
        Index("ix_snmp_thresholds_target_enabled", "target_id", "enabled"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("monitor_targets.id", ondelete="CASCADE"), index=True
    )
    source_kind: Mapped[str] = mapped_column(String(16))
    metric_id: Mapped[int | None] = mapped_column(
        ForeignKey("snmp_metrics.id", ondelete="CASCADE"), index=True
    )
    interface_id: Mapped[int | None] = mapped_column(
        ForeignKey("snmp_interfaces.id", ondelete="CASCADE"), index=True
    )
    supply_id: Mapped[int | None] = mapped_column(
        ForeignKey("snmp_supplies.id", ondelete="CASCADE"), index=True
    )
    field: Mapped[str] = mapped_column(String(32))
    operator: Mapped[str] = mapped_column(String(4))
    warning_value: Mapped[float | None] = mapped_column(Float)
    critical_value: Mapped[float | None] = mapped_column(Float)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    current_level: Mapped[str] = mapped_column(
        String(16), default="normal", server_default="normal"
    )
    last_value: Mapped[float | None] = mapped_column(Float)
    last_evaluated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    target = relationship("MonitorTarget")
    metric = relationship("SnmpMetric")
    interface = relationship("SnmpInterface", back_populates="thresholds")
    supply = relationship("SnmpSupply", back_populates="thresholds")


class SnmpSample(Base):
    __tablename__ = "snmp_samples"
    __table_args__ = (Index("ix_snmp_samples_metric_collected", "metric_id", "collected_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    metric_id: Mapped[int] = mapped_column(
        ForeignKey("snmp_metrics.id", ondelete="CASCADE"), index=True
    )
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )
    value: Mapped[Decimal] = mapped_column(Numeric(30, 10))

    metric = relationship("SnmpMetric", back_populates="samples")
