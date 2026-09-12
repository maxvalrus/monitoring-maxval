import asyncio
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from monitoring.config import Settings
from monitoring.db import Base
from monitoring.models import (
    AppSetting,
    Incident,
    MonitorTarget,
    Site,
    SnmpConfig,
    SnmpMetric,
    SnmpSample,
    SnmpStatus,
    SnmpThreshold,
    SnmpUpsSample,
    SnmpUpsState,
)
from monitoring.services.maintenance import cleanup_snmp_samples
from monitoring.services.snmp import (
    MAX_SNMP_SAMPLES_PER_TARGET,
    SnmpMetricForm,
    SnmpService,
    SnmpSettingsForm,
    trim_snmp_samples_for_target,
)
from monitoring.services.snmp_client import PySnmpClient, SnmpClientError, SnmpRequest, SnmpVarBind
from monitoring.services.snmp_formula import FormulaError, compile_snmp_formula
from monitoring.services.snmp_interfaces import traffic_poll_oids
from monitoring.services.snmp_ups import APC_HIGH_PRECISION_OIDS, APC_SCALAR_OIDS, UPS_SCALAR_OIDS


class FakeSnmpClient:
    def __init__(self, values: dict[str, SnmpVarBind] | None = None, *, error: bool = False):
        self.values = values or {}
        self.error = error
        self.calls: list[tuple[SnmpRequest, tuple[str, ...]]] = []

    async def get(self, request: SnmpRequest, oids):
        self.calls.append((request, tuple(oids)))
        if self.error:
            raise SnmpClientError("Ошибка транспорта SNMP")
        return [self.values[oid] for oid in oids if oid in self.values]


def _service(fake: FakeSnmpClient):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    settings = Settings(secret_key="snmp-test-secret", _env_file=None)
    service = SnmpService(factory, settings, fake, asyncio.Semaphore(4))
    with factory() as session:
        target = MonitorTarget(
            site=Site(name="SNMP"), name="switch", address="192.0.2.10", port=443
        )
        session.add(target)
        session.commit()
        target_id = target.id
    return factory, service, target_id


def _system_values() -> dict[str, SnmpVarBind]:
    return {
        "1.3.6.1.2.1.1.1.0": SnmpVarBind("1.3.6.1.2.1.1.1.0", "switch", "OctetString"),
        "1.3.6.1.2.1.1.2.0": SnmpVarBind("1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.9", "ObjectIdentifier"),
        "1.3.6.1.2.1.1.3.0": SnmpVarBind("1.3.6.1.2.1.1.3.0", "12345", "TimeTicks"),
        "1.3.6.1.2.1.1.5.0": SnmpVarBind("1.3.6.1.2.1.1.5.0", "core", "OctetString"),
    }


def _enable(session: Session, service: SnmpService, target_id: int) -> None:
    service.save_settings(session, target_id, SnmpSettingsForm(True, 161, "private", 3, 1))
    session.commit()


def test_disabled_snmp_never_calls_client() -> None:
    fake = FakeSnmpClient(_system_values())
    _factory, service, target_id = _service(fake)
    asyncio.run(service.poll_target(target_id))
    assert fake.calls == []


def test_snmp_v1_is_saved_and_used_for_polling() -> None:
    fake = FakeSnmpClient(_system_values())
    factory, service, target_id = _service(fake)
    with factory() as session:
        service.save_settings(
            session,
            target_id,
            SnmpSettingsForm(True, 161, "private", 3, 1, version="v1"),
        )
        session.commit()

    asyncio.run(service.poll_target(target_id))

    assert fake.calls[0][0].version == "v1"
    with factory() as session:
        config = session.get(SnmpConfig, target_id)
        assert config is not None and config.version == "v1"


def test_snmp_settings_reject_unknown_version() -> None:
    factory, service, target_id = _service(FakeSnmpClient())
    with factory() as session, pytest.raises(ValueError, match="SNMP v1 и v2c"):
        service.save_settings(
            session,
            target_id,
            SnmpSettingsForm(True, 161, "private", 3, 1, version="v3"),
        )


def test_snmp_v1_traffic_request_uses_legacy_counters_only() -> None:
    oids = traffic_poll_oids(1, None, supports_counter64=False)
    assert "1.3.6.1.2.1.2.2.1.10.1" in oids
    assert "1.3.6.1.2.1.2.2.1.16.1" in oids
    assert "1.3.6.1.2.1.31.1.1.1.6.1" not in oids
    assert "1.3.6.1.2.1.31.1.1.1.10.1" not in oids


def test_snmp_client_selects_v1_protocol_model() -> None:
    captured: dict[str, object] = {}

    def community_data(community: str, *, mpModel: int) -> tuple[str, int]:
        captured["community"] = community
        captured["mp_model"] = mpModel
        return community, mpModel

    request = SnmpRequest("192.0.2.10", 161, "private", 3, 1, version="v1")
    assert PySnmpClient._community_data(community_data, request) == ("private", 0)
    assert captured == {"community": "private", "mp_model": 0}


def test_optional_ups_mib_saves_normalized_state_history_and_incident() -> None:
    values = _system_values()
    values.update(
        {
            UPS_SCALAR_OIDS["manufacturer"]: SnmpVarBind(
                UPS_SCALAR_OIDS["manufacturer"], "APC", "OctetString"
            ),
            UPS_SCALAR_OIDS["model"]: SnmpVarBind(
                UPS_SCALAR_OIDS["model"], "Smart-UPS", "OctetString"
            ),
            UPS_SCALAR_OIDS["battery_status"]: SnmpVarBind(
                UPS_SCALAR_OIDS["battery_status"], "2", "Integer"
            ),
            UPS_SCALAR_OIDS["output_source"]: SnmpVarBind(
                UPS_SCALAR_OIDS["output_source"], "5", "Integer"
            ),
            UPS_SCALAR_OIDS["battery_charge_percent"]: SnmpVarBind(
                UPS_SCALAR_OIDS["battery_charge_percent"], "96", "Gauge32"
            ),
            UPS_SCALAR_OIDS["estimated_runtime_minutes"]: SnmpVarBind(
                UPS_SCALAR_OIDS["estimated_runtime_minutes"], "42", "Integer"
            ),
            UPS_SCALAR_OIDS["battery_voltage"]: SnmpVarBind(
                UPS_SCALAR_OIDS["battery_voltage"], "273", "Integer"
            ),
            UPS_SCALAR_OIDS["input_lines"]: SnmpVarBind(
                UPS_SCALAR_OIDS["input_lines"], "1", "Integer"
            ),
            UPS_SCALAR_OIDS["output_lines"]: SnmpVarBind(
                UPS_SCALAR_OIDS["output_lines"], "1", "Integer"
            ),
        }
    )
    factory, service, target_id = _service(FakeSnmpClient(values))
    with factory() as session:
        service.save_settings(
            session, target_id, SnmpSettingsForm(True, 161, "private", 3, 1, True)
        )
        session.commit()
    asyncio.run(service.poll_target(target_id))
    with factory() as session:
        state = session.get(SnmpUpsState, target_id)
        assert state is not None
        assert state.manufacturer == "APC" and state.output_source == 5
        assert state.battery_voltage == Decimal("27.30")
        assert (
            session.scalar(select(SnmpUpsSample).where(SnmpUpsSample.target_id == target_id))
            is not None
        )
        assert (
            session.scalar(
                select(Incident).where(
                    Incident.target_id == target_id, Incident.source_key == "ups.output"
                )
            )
            is not None
        )


def test_apc_powernet_uses_nonstandard_port_high_precision_values_and_existing_ups_state() -> None:
    values = _system_values()
    values.update(
        {
            APC_SCALAR_OIDS["model"]: SnmpVarBind(
                APC_SCALAR_OIDS["model"], "Smart-UPS 3000 XLM", "OctetString"
            ),
            APC_SCALAR_OIDS["battery_status"]: SnmpVarBind(
                APC_SCALAR_OIDS["battery_status"], "2", "Integer"
            ),
            APC_SCALAR_OIDS["output_source"]: SnmpVarBind(
                APC_SCALAR_OIDS["output_source"], "3", "Integer"
            ),
            APC_SCALAR_OIDS["estimated_runtime_minutes"]: SnmpVarBind(
                APC_SCALAR_OIDS["estimated_runtime_minutes"], "252000", "TimeTicks"
            ),
            APC_SCALAR_OIDS["battery_voltage"]: SnmpVarBind(
                APC_SCALAR_OIDS["battery_voltage"], "273", "Integer"
            ),
            APC_SCALAR_OIDS["input_voltage"]: SnmpVarBind(
                APC_SCALAR_OIDS["input_voltage"], "228", "Integer"
            ),
            APC_SCALAR_OIDS["input_frequency"]: SnmpVarBind(
                APC_SCALAR_OIDS["input_frequency"], "500", "Integer"
            ),
            APC_SCALAR_OIDS["battery_replace_needed"]: SnmpVarBind(
                APC_SCALAR_OIDS["battery_replace_needed"], "1", "Integer"
            ),
            APC_SCALAR_OIDS["last_transfer_reason"]: SnmpVarBind(
                APC_SCALAR_OIDS["last_transfer_reason"], "4", "Integer"
            ),
            APC_SCALAR_OIDS["last_self_test_result"]: SnmpVarBind(
                APC_SCALAR_OIDS["last_self_test_result"], "1", "Integer"
            ),
            APC_SCALAR_OIDS["last_self_test_at"]: SnmpVarBind(
                APC_SCALAR_OIDS["last_self_test_at"], "01/09/26", "OctetString"
            ),
            APC_HIGH_PRECISION_OIDS["battery_charge_percent"]: SnmpVarBind(
                APC_HIGH_PRECISION_OIDS["battery_charge_percent"], "780", "Integer"
            ),
            APC_HIGH_PRECISION_OIDS["battery_temperature"]: SnmpVarBind(
                APC_HIGH_PRECISION_OIDS["battery_temperature"], "252", "Integer"
            ),
            APC_HIGH_PRECISION_OIDS["output_voltage"]: SnmpVarBind(
                APC_HIGH_PRECISION_OIDS["output_voltage"], "2304", "Integer"
            ),
            APC_HIGH_PRECISION_OIDS["output_frequency"]: SnmpVarBind(
                APC_HIGH_PRECISION_OIDS["output_frequency"], "500", "Integer"
            ),
            APC_HIGH_PRECISION_OIDS["output_load_percent"]: SnmpVarBind(
                APC_HIGH_PRECISION_OIDS["output_load_percent"], "260", "Integer"
            ),
            APC_HIGH_PRECISION_OIDS["output_current"]: SnmpVarBind(
                APC_HIGH_PRECISION_OIDS["output_current"], "34", "Integer"
            ),
        }
    )
    factory, service, target_id = _service(FakeSnmpClient(values))
    with factory() as session:
        service.save_settings(
            session, target_id, SnmpSettingsForm(True, 1161, "private", 3, 1, True)
        )
        session.commit()
    asyncio.run(service.poll_target(target_id))
    with factory() as session:
        state = session.get(SnmpUpsState, target_id)
        assert state is not None
        assert state.profile == "apc_powernet"
        assert state.manufacturer == "APC" and state.model == "Smart-UPS 3000 XLM"
        assert state.battery_charge_percent == Decimal("78.00")
        assert state.battery_temperature == Decimal("25.20")
        assert state.estimated_runtime_minutes == Decimal("42.0")
        assert state.last_transfer_reason == "Пропадание входного питания"
        assert state.last_self_test_result == "Успешно" and state.last_self_test_at == "01/09/26"
        assert state.battery_replace_needed is False
        assert any(call[0].port == 1161 for call in service._client.calls)


def test_apc_powernet_falls_back_to_basic_values_when_precision_oids_are_missing() -> None:
    values = _system_values()
    values.update(
        {
            APC_SCALAR_OIDS["battery_status"]: SnmpVarBind(
                APC_SCALAR_OIDS["battery_status"], "2", "Integer"
            ),
            APC_SCALAR_OIDS["output_source"]: SnmpVarBind(
                APC_SCALAR_OIDS["output_source"], "2", "Integer"
            ),
            APC_SCALAR_OIDS["battery_charge_percent"]: SnmpVarBind(
                APC_SCALAR_OIDS["battery_charge_percent"], "77", "Integer"
            ),
            APC_SCALAR_OIDS["battery_temperature"]: SnmpVarBind(
                APC_SCALAR_OIDS["battery_temperature"], "24", "Integer"
            ),
            APC_SCALAR_OIDS["output_voltage"]: SnmpVarBind(
                APC_SCALAR_OIDS["output_voltage"], "230", "Integer"
            ),
        }
    )
    factory, service, target_id = _service(FakeSnmpClient(values))
    with factory() as session:
        service.save_settings(
            session, target_id, SnmpSettingsForm(True, 1161, "private", 3, 1, True)
        )
        session.commit()
    asyncio.run(service.poll_target(target_id))
    with factory() as session:
        state = session.get(SnmpUpsState, target_id)
        assert state is not None
        assert state.battery_charge_percent == Decimal("77.00")
        assert state.battery_temperature == Decimal("24.00")


def test_successful_poll_saves_system_data_and_numeric_sample() -> None:
    values = _system_values()
    values["1.3.6.1.4.1.1.0"] = SnmpVarBind("1.3.6.1.4.1.1.0", "18446744073709551615", "Counter64")
    fake = FakeSnmpClient(values)
    factory, service, target_id = _service(fake)
    with factory() as session:
        _enable(session, service, target_id)
        metric = service.add_metric(
            session, target_id, SnmpMetricForm("Bytes", ".1.3.6.1.4.1.1.0", "Б", True)
        )
        session.commit()
        metric_id = metric.id
    asyncio.run(service.poll_target(target_id))
    assert len(fake.calls) == 1
    assert fake.calls[0][0].community == "private"
    with factory() as session:
        config = session.get(SnmpConfig, target_id)
        metric = session.get(SnmpMetric, metric_id)
        sample = session.scalar(select(SnmpSample).where(SnmpSample.metric_id == metric_id))
        assert config is not None and config.last_status == SnmpStatus.OK
        assert config.sys_name == "core" and config.sys_uptime_ticks == 12345
        # SQLite emulates NUMERIC through float; PostgreSQL NUMERIC(20, 0) used in
        # production preserves Counter64 exactly. The canonical display value stays exact here.
        assert metric is not None and metric.last_value == "18446744073709551615"
        assert sample is not None


def test_text_metric_has_last_value_but_no_sample_and_bad_oid_does_not_fail_poll() -> None:
    values = _system_values()
    values["1.3.6.1.4.1.2.0"] = SnmpVarBind("1.3.6.1.4.1.2.0", "hello", "OctetString")
    values["1.3.6.1.4.1.3.0"] = SnmpVarBind(
        "1.3.6.1.4.1.3.0", None, "NoSuchObject", "Объект OID не существует"
    )
    factory, service, target_id = _service(FakeSnmpClient(values))
    with factory() as session:
        _enable(session, service, target_id)
        text_metric = service.add_metric(
            session, target_id, SnmpMetricForm("Text", "1.3.6.1.4.1.2.0", "", True)
        )
        missing_metric = service.add_metric(
            session, target_id, SnmpMetricForm("Missing", "1.3.6.1.4.1.3.0", "", True)
        )
        session.commit()
        text_id, missing_id = text_metric.id, missing_metric.id
    asyncio.run(service.poll_target(target_id))
    with factory() as session:
        config = session.get(SnmpConfig, target_id)
        text_metric = session.get(SnmpMetric, text_id)
        missing_metric = session.get(SnmpMetric, missing_id)
        assert config is not None and config.last_status == SnmpStatus.OK
        assert text_metric is not None and text_metric.last_value == "hello"
        assert session.scalar(select(SnmpSample).where(SnmpSample.metric_id == text_id)) is None
        assert (
            missing_metric is not None and missing_metric.last_error == "Объект OID не существует"
        )


def test_formula_metric_batches_hidden_source_oids_and_saves_decimal_sample() -> None:
    total_oid = "1.3.6.1.2.1.25.2.3.1.5.7"
    used_oid = "1.3.6.1.2.1.25.2.3.1.6.7"
    values = _system_values()
    values.update(
        {
            total_oid: SnmpVarBind(total_oid, "8000", "Integer"),
            used_oid: SnmpVarBind(used_oid, "3000", "Integer"),
        }
    )
    fake = FakeSnmpClient(values)
    factory, service, target_id = _service(fake)
    expression = f'round((oid("{total_oid}") - oid("{used_oid}")) / 1024, 1)'
    with factory() as session:
        _enable(session, service, target_id)
        metric = service.add_metric(
            session,
            target_id,
            SnmpMetricForm("Свободная память", "", "MiB", True, "formula", expression),
        )
        session.commit()
        metric_id = metric.id

    asyncio.run(service.poll_target(target_id))

    requested = {oid for _request, oids in fake.calls for oid in oids}
    assert {total_oid, used_oid}.issubset(requested)
    with factory() as session:
        metric = session.get(SnmpMetric, metric_id)
        sample = session.scalar(select(SnmpSample).where(SnmpSample.metric_id == metric_id))
        assert metric is not None
        assert metric.oid is None and metric.source_kind == "formula"
        assert metric.last_value == "4.9" and metric.last_error is None
        assert sample is not None and sample.value == Decimal("4.9")


def test_hr_storage_formula_normalizes_allocation_units_without_source_metrics() -> None:
    allocation_oid = "1.3.6.1.2.1.25.2.3.1.4.1"
    total_oid = "1.3.6.1.2.1.25.2.3.1.5.1"
    used_oid = "1.3.6.1.2.1.25.2.3.1.6.1"
    values = _system_values()
    values.update(
        {
            allocation_oid: SnmpVarBind(allocation_oid, "4096", "Integer"),
            total_oid: SnmpVarBind(total_oid, "1000", "Integer"),
            used_oid: SnmpVarBind(used_oid, "250", "Integer"),
        }
    )
    fake = FakeSnmpClient(values)
    factory, service, target_id = _service(fake)
    with factory() as session:
        _enable(session, service, target_id)
        metric = service.add_metric(
            session,
            target_id,
            SnmpMetricForm(
                "Свободная память",
                "",
                "MiB",
                True,
                "formula",
                "round(hr_storage_free_bytes(1) / MiB, 1)",
            ),
        )
        session.commit()
        metric_id = metric.id

    asyncio.run(service.poll_target(target_id))

    requested = {oid for _request, oids in fake.calls for oid in oids}
    assert {allocation_oid, total_oid, used_oid}.issubset(requested)
    with factory() as session:
        metric = session.get(SnmpMetric, metric_id)
        assert metric is not None and metric.last_value == "2.9"
        assert session.scalar(select(func.count(SnmpMetric.id))) == 1


def test_formula_source_error_is_local_to_derived_metric() -> None:
    good_oid = "1.3.6.1.4.1.1.0"
    missing_oid = "1.3.6.1.4.1.2.0"
    values = _system_values()
    values[good_oid] = SnmpVarBind(good_oid, "42", "Gauge32")
    values[missing_oid] = SnmpVarBind(missing_oid, None, "NoSuchObject", "Объект OID не существует")
    factory, service, target_id = _service(FakeSnmpClient(values))
    with factory() as session:
        _enable(session, service, target_id)
        raw = service.add_metric(
            session, target_id, SnmpMetricForm("Нагрузка", good_oid, "%", True)
        )
        derived = service.add_metric(
            session,
            target_id,
            SnmpMetricForm("Расчёт", "", "", True, "formula", f'oid("{missing_oid}") / 2'),
        )
        session.commit()
        raw_id, derived_id = raw.id, derived.id

    asyncio.run(service.poll_target(target_id))

    with factory() as session:
        config = session.get(SnmpConfig, target_id)
        raw, derived = session.get(SnmpMetric, raw_id), session.get(SnmpMetric, derived_id)
        assert config is not None and config.last_status == SnmpStatus.OK
        assert raw is not None and raw.last_value == "42"
        assert derived is not None and "не вернул числовое значение" in (derived.last_error or "")


def test_formula_sample_uses_existing_threshold_engine() -> None:
    source_oid = "1.3.6.1.4.1.71.0"
    values = _system_values()
    values[source_oid] = SnmpVarBind(source_oid, "84", "Gauge32")
    factory, service, target_id = _service(FakeSnmpClient(values))
    factory.configure(autoflush=False)
    with factory() as session:
        _enable(session, service, target_id)
        metric = service.add_metric(
            session,
            target_id,
            SnmpMetricForm("Нагрузка", "", "%", True, "formula", f'oid("{source_oid}") / 2'),
        )
        session.flush()
        session.add(
            SnmpThreshold(
                target_id=target_id,
                source_kind="metric",
                metric_id=metric.id,
                field="value",
                operator="gt",
                warning_value=40,
                enabled=True,
            )
        )
        session.commit()

    events = asyncio.run(service.poll_target(target_id))

    assert len(events) == 1
    with factory() as session:
        threshold = session.scalar(select(SnmpThreshold))
        assert threshold is not None and threshold.last_value == 42
        assert threshold.current_level == "warning"


@pytest.mark.parametrize(
    "expression",
    ["__import__('os')", "oid('bad')", 'round(oid("1.3.6.1.4.1.1.0"), 12)'],
)
def test_formula_language_rejects_unsafe_or_invalid_expression(expression: str) -> None:
    with pytest.raises(FormulaError):
        compile_snmp_formula(expression)


def test_transport_error_does_not_remove_previous_data() -> None:
    factory, service, target_id = _service(FakeSnmpClient(_system_values(), error=True))
    with factory() as session:
        _enable(session, service, target_id)
        config = session.get(SnmpConfig, target_id)
        assert config is not None
        config.sys_name = "previous"
        config.last_status = SnmpStatus.OK
        session.commit()
    asyncio.run(service.poll_target(target_id))
    with factory() as session:
        config = session.get(SnmpConfig, target_id)
        assert config is not None
        assert config.last_status == SnmpStatus.ERROR and config.sys_name == "previous"


def test_numeric_sample_history_is_limited_per_target() -> None:
    values = _system_values()
    values["1.3.6.1.4.1.7.0"] = SnmpVarBind("1.3.6.1.4.1.7.0", "42", "Gauge32")
    factory, service, target_id = _service(FakeSnmpClient(values))
    with factory() as session:
        _enable(session, service, target_id)
        metric = service.add_metric(
            session, target_id, SnmpMetricForm("Load", "1.3.6.1.4.1.7.0", "", True)
        )
        session.flush()
        session.add_all(
            SnmpSample(
                metric_id=metric.id,
                value=Decimal(index),
                collected_at=datetime.now(UTC)
                - timedelta(minutes=MAX_SNMP_SAMPLES_PER_TARGET - index),
            )
            for index in range(MAX_SNMP_SAMPLES_PER_TARGET)
        )
        session.commit()
    asyncio.run(service.poll_target(target_id))
    with factory() as session:
        samples = session.scalars(
            select(SnmpSample)
            .join(SnmpMetric, SnmpMetric.id == SnmpSample.metric_id)
            .where(SnmpMetric.target_id == target_id)
        ).all()
        assert len(samples) == MAX_SNMP_SAMPLES_PER_TARGET
        assert any(sample.value == Decimal("42") for sample in samples)


def test_poll_limit_includes_all_pending_samples_with_production_autoflush() -> None:
    values = _system_values()
    for index in range(5):
        oid = f"1.3.6.1.4.1.70.{index}"
        values[oid] = SnmpVarBind(oid, str(900 + index), "Gauge32")
    factory, service, target_id = _service(FakeSnmpClient(values))
    factory.configure(autoflush=False)
    with factory() as session:
        _enable(session, service, target_id)
        metrics = []
        for index in range(5):
            metric = service.add_metric(
                session,
                target_id,
                SnmpMetricForm(f"Metric {index}", f"1.3.6.1.4.1.70.{index}", "", True),
            )
            session.flush()
            metrics.append(metric)
        session.add(AppSetting(key="snmp_sample_max_per_target", value="100"))
        session.add_all(
            SnmpSample(
                metric_id=metrics[0].id,
                value=Decimal(index),
                collected_at=datetime.now(UTC) - timedelta(minutes=100 - index),
            )
            for index in range(100)
        )
        session.commit()

    asyncio.run(service.poll_target(target_id))

    with factory() as session:
        samples = session.scalars(
            select(SnmpSample)
            .join(SnmpMetric, SnmpMetric.id == SnmpSample.metric_id)
            .where(SnmpMetric.target_id == target_id)
        ).all()
        assert len(samples) == 100
        assert {sample.value for sample in samples}.issuperset(
            {Decimal(str(900 + index)) for index in range(5)}
        )


def test_current_poll_sample_is_used_for_threshold_with_autoflush_disabled() -> None:
    values = _system_values()
    oid = "1.3.6.1.4.1.71.0"
    values[oid] = SnmpVarBind(oid, "42", "Gauge32")
    factory, service, target_id = _service(FakeSnmpClient(values))
    factory.configure(autoflush=False)
    with factory() as session:
        _enable(session, service, target_id)
        metric = service.add_metric(session, target_id, SnmpMetricForm("Load", oid, "%", True))
        session.flush()
        session.add(
            SnmpThreshold(
                target_id=target_id,
                source_kind="metric",
                metric_id=metric.id,
                field="value",
                operator="gt",
                warning_value=10,
                enabled=True,
            )
        )
        session.commit()

    events = asyncio.run(service.poll_target(target_id))

    assert len(events) == 1
    with factory() as session:
        threshold = session.scalar(select(SnmpThreshold))
        incident = session.scalar(select(Incident))
        assert threshold is not None and threshold.last_value == 42
        assert threshold.current_level == "warning"
        assert incident is not None and incident.status == "open"


def test_failed_metric_oid_does_not_evaluate_stale_threshold_sample() -> None:
    values = _system_values()
    oid = "1.3.6.1.4.1.72.0"
    values[oid] = SnmpVarBind(oid, None, "NoSuchObject", "Объект OID не существует")
    factory, service, target_id = _service(FakeSnmpClient(values))
    factory.configure(autoflush=False)
    with factory() as session:
        _enable(session, service, target_id)
        metric = service.add_metric(session, target_id, SnmpMetricForm("Load", oid, "%", True))
        session.flush()
        session.add(
            SnmpSample(
                metric_id=metric.id,
                value=Decimal("99"),
                collected_at=datetime.now(UTC) - timedelta(minutes=5),
            )
        )
        session.add(
            SnmpThreshold(
                target_id=target_id,
                source_kind="metric",
                metric_id=metric.id,
                field="value",
                operator="gt",
                warning_value=10,
                enabled=True,
            )
        )
        session.commit()

    assert asyncio.run(service.poll_target(target_id)) == []
    with factory() as session:
        threshold = session.scalar(select(SnmpThreshold))
        assert threshold is not None and threshold.current_level == "normal"
        assert threshold.last_evaluated_at is None
        assert session.scalar(select(Incident)) is None


def test_disabling_snmp_during_inflight_poll_returns_no_events() -> None:
    class DisableDuringGetClient(FakeSnmpClient):
        async def get(self, request: SnmpRequest, oids):
            with factory() as session:
                config = session.get(SnmpConfig, target_id)
                assert config is not None
                config.enabled = False
                session.commit()
            return await super().get(request, oids)

    client = DisableDuringGetClient(_system_values())
    factory, service, target_id = _service(client)
    with factory() as session:
        _enable(session, service, target_id)

    assert asyncio.run(service.poll_target(target_id)) == []


def test_configured_snmp_sample_limit_removes_oldest_samples() -> None:
    factory, service, target_id = _service(FakeSnmpClient(_system_values()))
    with factory() as session:
        metric = service.add_metric(
            session,
            target_id,
            SnmpMetricForm("Load", "1.3.6.1.4.1.7.0", "", True),
        )
        session.flush()
        session.add(AppSetting(key="snmp_sample_max_per_target", value="100"))
        session.add_all(
            SnmpSample(
                metric_id=metric.id,
                value=Decimal(index),
                collected_at=datetime.now(UTC) - timedelta(minutes=101 - index),
            )
            for index in range(101)
        )
        trim_snmp_samples_for_target(session, target_id)
        session.commit()

        samples = session.scalars(
            select(SnmpSample)
            .join(SnmpMetric, SnmpMetric.id == SnmpSample.metric_id)
            .where(SnmpMetric.target_id == target_id)
        ).all()
        assert len(samples) == 100
        assert all(sample.value != Decimal("0") for sample in samples)


def test_disable_and_clear_preserve_configuration_and_metric_definitions() -> None:
    factory, service, target_id = _service(FakeSnmpClient(_system_values()))
    with factory() as session:
        _enable(session, service, target_id)
        metric = service.add_metric(
            session, target_id, SnmpMetricForm("Number", "1.3.6.1.4.1.4.0", "", True)
        )
        config = session.get(SnmpConfig, target_id)
        assert config is not None
        config.sys_name = "old"
        config.last_status = SnmpStatus.OK
        metric.last_value = "12"
        metric.last_numeric_value = Decimal("12")
        metric.last_collected_at = datetime.now(UTC)
        session.add(SnmpSample(metric_id=metric.id, value=Decimal("12")))
        session.commit()
        service.save_settings(session, target_id, SnmpSettingsForm(False, 161, "", 3, 1))
        session.commit()
        service.clear_data(session, target_id)
        session.commit()
        session.expire_all()
        config = session.get(SnmpConfig, target_id)
        metric = session.get(SnmpMetric, metric.id)
        assert config is not None and not config.enabled and config.community_encrypted
        assert config.last_status == SnmpStatus.NEVER and config.sys_name is None
        assert metric is not None and metric.name == "Number" and metric.last_value is None
        assert session.scalar(select(SnmpSample).where(SnmpSample.metric_id == metric.id)) is None


def test_oid_limit_and_retention_and_cascade_delete() -> None:
    factory, service, target_id = _service(FakeSnmpClient(_system_values()))
    with factory() as session:
        for index in range(32):
            service.add_metric(
                session, target_id, SnmpMetricForm(str(index), f"1.3.6.1.4.1.99.{index}", "", True)
            )
        with pytest.raises(ValueError, match="не более"):
            service.add_metric(
                session, target_id, SnmpMetricForm("extra", "1.3.6.1.4.1.99.99", "", True)
            )
        metric = session.scalar(select(SnmpMetric).where(SnmpMetric.target_id == target_id))
        assert metric is not None
        session.add(
            SnmpSample(
                metric_id=metric.id,
                value=Decimal("1"),
                collected_at=datetime.now(UTC) - timedelta(days=31),
            )
        )
        session.add(
            SnmpSample(metric_id=metric.id, value=Decimal("2"), collected_at=datetime.now(UTC))
        )
        session.add(SnmpConfig(target_id=target_id))
        session.commit()
        from monitoring.models import AppSetting

        session.add(AppSetting(key="snmp_sample_retention_days", value="30"))
        session.commit()
        assert cleanup_snmp_samples(session) == 1
        target = session.get(MonitorTarget, target_id)
        assert target is not None
        session.delete(target)
        session.commit()
        assert session.scalar(select(SnmpConfig).where(SnmpConfig.target_id == target_id)) is None
        assert session.scalar(select(SnmpMetric).where(SnmpMetric.target_id == target_id)) is None
