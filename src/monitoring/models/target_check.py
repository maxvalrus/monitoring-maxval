from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from monitoring.db import Base
from monitoring.models.mixins import TimestampMixin, utc_now


class TargetCheck(TimestampMixin, Base):
    __tablename__ = "target_checks"
    __table_args__ = (
        CheckConstraint("port > 0 AND port <= 65535", name="ck_target_check_port_range"),
        CheckConstraint(
            "timeout_seconds IS NULL OR (timeout_seconds >= 0.5 AND timeout_seconds <= 60)",
            name="ck_target_check_timeout_range",
        ),
        CheckConstraint("retries >= 0 AND retries <= 10", name="ck_target_check_retries_range"),
        CheckConstraint(
            "http_expected_status IS NULL OR (http_expected_status >= 100 AND http_expected_status <= 599)",
            name="ck_target_check_http_expected_status",
        ),
        CheckConstraint(
            "http_max_response_ms IS NULL OR http_max_response_ms > 0",
            name="ck_target_check_http_max_response_ms",
        ),
        CheckConstraint(
            "tls_warning_days IS NULL OR tls_warning_days > 0",
            name="ck_target_check_tls_warning_days",
        ),
        CheckConstraint(
            "tls_critical_days IS NULL OR tls_critical_days >= 0",
            name="ck_target_check_tls_critical_days",
        ),
        CheckConstraint(
            "tls_warning_days IS NULL OR tls_critical_days IS NULL "
            "OR tls_warning_days > tls_critical_days",
            name="ck_target_check_tls_threshold_order",
        ),
        CheckConstraint(
            "dns_record_type IS NULL OR dns_record_type IN ('A', 'AAAA')",
            name="ck_target_check_dns_record_type",
        ),
        CheckConstraint(
            "dns_max_response_ms IS NULL OR dns_max_response_ms > 0",
            name="ck_target_check_dns_max_response_ms",
        ),
        CheckConstraint(
            "directory_period_hours IS NULL OR directory_period_hours > 0",
            name="ck_target_check_directory_period_hours",
        ),
        CheckConstraint(
            "directory_show_last IS NULL OR directory_show_last >= 0",
            name="ck_target_check_directory_show_last",
        ),
        CheckConstraint(
            "directory_recent_count IS NULL OR directory_recent_count >= 0",
            name="ck_target_check_directory_recent_count",
        ),
        Index("ix_target_checks_target_order", "target_id", "display_order", "id"),
        Index(
            "uq_target_checks_primary_per_target",
            "target_id",
            unique=True,
            postgresql_where=text("is_primary"),
            sqlite_where=text("is_primary = 1"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("monitor_targets.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(160))
    checker_type: Mapped[str] = mapped_column(String(50))
    address_override: Mapped[str | None] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer)
    path: Mapped[str] = mapped_column(String(500), default="/", server_default="/")
    timeout_seconds: Mapped[float | None] = mapped_column(Float)
    retries: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    display_order: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    config_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    http_expected_status: Mapped[int | None] = mapped_column(Integer)
    http_content_contains: Mapped[str | None] = mapped_column(String(500))
    http_content_not_contains: Mapped[str | None] = mapped_column(String(500))
    http_max_response_ms: Mapped[float | None] = mapped_column(Float)
    tls_monitor_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false"
    )
    tls_warning_days: Mapped[int | None] = mapped_column(Integer)
    tls_critical_days: Mapped[int | None] = mapped_column(Integer)
    dns_name: Mapped[str | None] = mapped_column(String(253))
    dns_record_type: Mapped[str | None] = mapped_column(String(8))
    dns_expected_address: Mapped[str | None] = mapped_column(String(45))
    dns_max_response_ms: Mapped[float | None] = mapped_column(Float)
    # Directory secondary-check configuration and its read-only last successful scan.
    directory_path: Mapped[str | None] = mapped_column(String(1024))
    directory_pattern: Mapped[str | None] = mapped_column(String(255))
    directory_period_hours: Mapped[float | None] = mapped_column(Float)
    directory_show_last: Mapped[int | None] = mapped_column(Integer)
    directory_username: Mapped[str | None] = mapped_column(String(255))
    directory_password_encrypted: Mapped[str] = mapped_column(
        String, default="", server_default=""
    )
    directory_last_files: Mapped[list[dict[str, object]] | None] = mapped_column(JSON)
    directory_recent_count: Mapped[int | None] = mapped_column(Integer)
    directory_latest_file_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    directory_scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    unstable_pending_down: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )
    unstable_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    target = relationship("MonitorTarget", back_populates="checks")
    results = relationship(
        "TargetCheckResult", back_populates="check", cascade="all, delete-orphan"
    )

    @property
    def effective_address(self) -> str:
        if self.checker_type == "dns" and self.dns_name:
            return self.dns_name
        return self.address_override or self.target.address


class TargetCheckResult(Base):
    __tablename__ = "target_check_results"
    __table_args__ = (
        CheckConstraint(
            "tls_health IS NULL OR tls_health IN ('ok', 'warning', 'critical')",
            name="ck_target_check_result_tls_health",
        ),
        Index("ix_target_check_results_check_checked", "check_id", "checked_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    check_id: Mapped[int] = mapped_column(
        ForeignKey("target_checks.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(20))
    latency_ms: Mapped[float | None] = mapped_column(Float)
    message: Mapped[str | None] = mapped_column(String(500))
    config_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )
    tls_not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tls_days_remaining: Mapped[float | None] = mapped_column(Float)
    tls_health: Mapped[str | None] = mapped_column(String(16))

    check = relationship("TargetCheck", back_populates="results")
