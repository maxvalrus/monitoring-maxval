import math
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from monitoring.db import Base
from monitoring.models import (
    Incident,
    MonitorTarget,
    Site,
    SnmpConfig,
    SnmpInterface,
    SnmpInterfaceSample,
    SnmpThreshold,
    SnmpUpsLine,
    SnmpUpsState,
)
from monitoring.services.snmp_thresholds import (
    SnmpThresholdService,
    ThresholdLevel,
    evaluate_level,
    format_threshold_value,
    safe_counter_delta,
    validate_threshold_values,
)


def test_gt_warning_and_critical() -> None:
    assert evaluate_level(50, operator="gt", warning=60, critical=80) == ThresholdLevel.NORMAL
    assert evaluate_level(70, operator="gt", warning=60, critical=80) == ThresholdLevel.WARNING
    assert evaluate_level(90, operator="gt", warning=60, critical=80) == ThresholdLevel.CRITICAL


def test_lt_warning_and_critical() -> None:
    assert evaluate_level(50, operator="lt", warning=40, critical=20) == ThresholdLevel.NORMAL
    assert evaluate_level(30, operator="lt", warning=40, critical=20) == ThresholdLevel.WARNING
    assert evaluate_level(10, operator="lt", warning=40, critical=20) == ThresholdLevel.CRITICAL


def test_counter_reset_is_not_threshold_value() -> None:
    assert safe_counter_delta(110, 100) == 10.0
    assert safe_counter_delta(5, 100) is None
    assert safe_counter_delta(None, 100) is None


def test_interface_traffic_threshold_value_uses_two_decimal_places() -> None:
    threshold = SnmpThreshold(source_kind="interface", field="rx_bps")
    assert format_threshold_value(threshold, 12.3456) == "12.35"
    threshold.field = "errors_delta"
    assert format_threshold_value(threshold, 12.3456) == "12.3456"


def test_threshold_order_validation() -> None:
    validate_threshold_values(operator="gt", warning=60, critical=80)
    validate_threshold_values(operator="lt", warning=40, critical=20)
    try:
        validate_threshold_values(operator="gt", warning=80, critical=60)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid GT threshold order must fail")


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_threshold_rejects_non_finite_values(value: float) -> None:
    with pytest.raises(ValueError, match="конечными"):
        validate_threshold_values(operator="gt", warning=value, critical=None)


def test_interface_baseline_does_not_evaluate_counter_delta() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    observed_at = datetime.now(UTC)
    with Session(engine) as session:
        target = MonitorTarget(
            site=Site(name="SNMP"),
            name="switch",
            address="192.0.2.10",
            port=443,
        )
        session.add(target)
        session.flush()
        interface = SnmpInterface(
            target_id=target.id,
            if_index=1,
            monitor_enabled=True,
            present=True,
        )
        session.add(interface)
        session.flush()
        threshold = SnmpThreshold(
            target_id=target.id,
            source_kind="interface",
            interface_id=interface.id,
            field="errors_delta",
            operator="gt",
            warning_value=10,
            enabled=True,
        )
        session.add(threshold)
        session.add_all(
            (
                SnmpInterfaceSample(
                    interface_id=interface.id,
                    collected_at=observed_at - timedelta(minutes=5),
                    rx_bps=1,
                    tx_bps=1,
                    in_errors=1,
                    out_errors=1,
                ),
                SnmpInterfaceSample(
                    interface_id=interface.id,
                    collected_at=observed_at,
                    rx_bps=None,
                    tx_bps=None,
                    in_errors=100,
                    out_errors=100,
                ),
            )
        )
        session.commit()

        assert (
            SnmpThresholdService().evaluate_target(
                session, target.id, observed_at=observed_at
            )
            == []
        )
        assert threshold.last_evaluated_at is None
        assert session.scalar(select(Incident)) is None


def test_ups_current_values_are_available_to_existing_threshold_lifecycle() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    observed_at = datetime.now(UTC)
    with Session(engine) as session:
        target = MonitorTarget(
            site=Site(name="UPS"),
            name="ИБП",
            address="192.0.2.20",
            port=161,
        )
        session.add(target)
        session.flush()
        session.add(SnmpConfig(target_id=target.id, enabled=True, ups_enabled=True))
        session.add(
            SnmpUpsState(
                target_id=target.id,
                battery_charge_percent=20,
                battery_temperature=31,
                last_polled_at=observed_at,
            )
        )
        session.add(
            SnmpUpsLine(
                target_id=target.id,
                direction="output",
                line_index=1,
                voltage=230,
                current=2,
                load_percent=85,
                last_polled_at=observed_at,
            )
        )
        session.flush()

        service = SnmpThresholdService()
        options = service.source_options(session, target.id)
        assert any(option.value == f"ups:{target.id}:battery_charge_percent" for option in options)
        assert any(option.value == f"ups:{target.id}:output_load_percent.1" for option in options)
        assert service.parse_source(
            session, target.id, f"ups:{target.id}:output_load_percent.1"
        ) == ("ups", None, None, None, "output_load_percent:1")

        threshold = SnmpThreshold(
            target_id=target.id,
            source_kind="ups",
            field="battery_charge_percent",
            operator="lt",
            warning_value=30,
            enabled=True,
        )
        session.add(threshold)
        session.commit()

        events = service.evaluate_target(session, target.id, observed_at=observed_at)
        assert threshold.last_value == 20
        assert threshold.current_level == ThresholdLevel.WARNING
        assert len(events) == 1
