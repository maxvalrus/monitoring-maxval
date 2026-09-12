from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from monitoring.db import Base
from monitoring.models import (
    MonitorTarget,
    Site,
    SnmpInterface,
    SnmpInterfaceSample,
    SnmpMetric,
    SnmpSample,
)
from monitoring.services.snmp_graphs import MAX_GRAPH_POINTS, build_snmp_history_graph


def _target(session: Session) -> MonitorTarget:
    target = MonitorTarget(
        site=Site(name="SNMP"), name="switch", address="192.0.2.10", port=161
    )
    session.add(target)
    session.flush()
    return target


def test_interface_graph_uses_mbit_and_safe_counter_deltas() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    with Session(engine) as session:
        target = _target(session)
        interface = SnmpInterface(
            target_id=target.id,
            if_index=1,
            if_name="ether1",
            if_alias="Uplink",
            monitor_enabled=True,
        )
        session.add(interface)
        session.flush()
        session.add_all(
            [
                SnmpInterfaceSample(
                    interface_id=interface.id,
                    collected_at=now - timedelta(minutes=2),
                    rx_bps=1_000_000,
                    tx_bps=2_000_000,
                    in_errors=10,
                    out_errors=5,
                    in_discards=4,
                    out_discards=2,
                ),
                SnmpInterfaceSample(
                    interface_id=interface.id,
                    collected_at=now - timedelta(minutes=1),
                    rx_bps=2_000_000,
                    tx_bps=1_000_000,
                    in_errors=12,
                    out_errors=8,
                    in_discards=5,
                    out_discards=5,
                ),
                SnmpInterfaceSample(
                    interface_id=interface.id,
                    collected_at=now,
                    rx_bps=3_000_000,
                    tx_bps=4_000_000,
                    in_errors=1,
                    out_errors=1,
                    in_discards=1,
                    out_discards=1,
                ),
            ]
        )
        session.commit()
        choices, graph, selected = build_snmp_history_graph(
            session, target.id, hours=24, selection=f"interface:{interface.id}"
        )
        assert choices[0].value == selected == f"interface:{interface.id}"
        assert choices[0].label == "Интерфейс · ether1 · Uplink"
        assert graph is not None
        assert graph.title == "SNMP · ether1 · Uplink"
        traffic, events = graph.panels
        assert traffic.unit == "Mbit/s"
        assert traffic.series[0].last_value == "3.0"
        assert traffic.series[1].last_value == "4.0"
        assert traffic.tooltip_series[0]["points"] == traffic.series[0].points
        assert traffic.tooltip_series[0]["css_class"] == "snmp-series-rx"
        assert events.series[0].last_value == "0"
        assert events.series[1].last_value == "0"


def test_disabled_interface_history_is_not_offered_as_a_current_snmp_graph() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        target = _target(session)
        interface = SnmpInterface(
            target_id=target.id,
            if_index=1,
            if_name="ether1",
            monitor_enabled=False,
        )
        session.add(interface)
        session.flush()
        session.add(SnmpInterfaceSample(interface_id=interface.id, rx_bps=1_000_000))
        session.commit()
        choices, graph, selected = build_snmp_history_graph(
            session, target.id, hours=24, selection=f"interface:{interface.id}"
        )
        assert choices == ()
        assert graph is None and selected == ""


def test_numeric_metric_is_shown_but_sources_without_samples_are_hidden() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        target = _target(session)
        numeric = SnmpMetric(target_id=target.id, oid="1.3.6.1.4.1.1.0", name="CPU", enabled=True)
        text_only = SnmpMetric(target_id=target.id, oid="1.3.6.1.4.1.2.0", name="Text", enabled=True)
        session.add_all((numeric, text_only))
        session.flush()
        session.add(SnmpSample(metric_id=numeric.id, value=Decimal("42")))
        session.commit()
        choices, graph, selected = build_snmp_history_graph(
            session, target.id, hours=24, selection=f"metric:{numeric.id}"
        )
        assert [item.value for item in choices] == [f"metric:{numeric.id}"]
        assert selected == f"metric:{numeric.id}"
        assert graph is not None and graph.panels[0].series[0].last_value == "42.0"


def test_graph_selection_falls_back_and_downsamples_to_limit() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    with Session(engine) as session:
        target = _target(session)
        metric = SnmpMetric(target_id=target.id, oid="1.3.6.1.4.1.1.0", name="Load", enabled=True)
        session.add(metric)
        session.flush()
        session.add_all(
            SnmpSample(
                metric_id=metric.id,
                value=Decimal(index),
                collected_at=now - timedelta(minutes=MAX_GRAPH_POINTS + 5 - index),
            )
            for index in range(MAX_GRAPH_POINTS + 5)
        )
        session.commit()
        _choices, graph, selected = build_snmp_history_graph(
            session, target.id, hours=24, selection="metric:999999"
        )
        assert selected == f"metric:{metric.id}"
        assert graph is not None
        assert len(graph.panels[0].series[0].points.split()) == MAX_GRAPH_POINTS


def test_history_selector_uses_csp_safe_auto_submit() -> None:
    template = Path("src/monitoring/templates/target_history.html").read_text(encoding="utf-8")
    assert 'name="snmp_graph" data-auto-submit' in template
    assert "data-snmp-history-selector" in template
    assert 'href="/targets/{{ history.target.id }}/snmp/interfaces">Интерфейсы</a>' not in template
    assert "onchange=" not in template
    javascript = Path("src/monitoring/static/app.js").read_text(encoding="utf-8")
    assert 'form.matches("[data-snmp-history-selector]")' in javascript
