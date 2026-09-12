import asyncio
import socket

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from monitoring.checks.base import CheckOutcome
from monitoring.checks.dns import DnsChecker
from monitoring.checks.registry import CheckerRegistry
from monitoring.db import Base
from monitoring.models import CheckStatus, MonitorTarget, Site, TargetCheck
from monitoring.services.dns_monitoring import normalize_dns_fields
from monitoring.services.monitoring import MonitoringService
from monitoring.services.target_checks import normalize_check_fields, primary_checker_names


def test_dns_fields_normalize_idna_and_reject_invalid_name_and_family() -> None:
    assert normalize_dns_fields(
        checker_type="dns",
        name="пример.рф.",
        record_type="A",
        expected_address="192.0.2.1",
        max_response_ms=120,
    ) == ("xn--e1afmkfd.xn--p1ai", "A", "192.0.2.1", 120.0)
    with pytest.raises(ValueError, match="схемы"):
        normalize_dns_fields(
            checker_type="dns", name="https://example.com/x", record_type="A",
            expected_address=None, max_response_ms=None,
        )
    with pytest.raises(ValueError, match="Семейство"):
        normalize_dns_fields(
            checker_type="dns", name="example.com", record_type="A",
            expected_address="2001:db8::1", max_response_ms=None,
        )


def test_dns_checker_uses_one_resolve_and_handles_expected_address(monkeypatch) -> None:
    calls = []

    def fake_getaddrinfo(name, _port, family, _socktype):
        calls.append((name, family))
        return [(family, socket.SOCK_STREAM, 6, "", ("192.0.2.15", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    checker = DnsChecker()
    outcome = asyncio.run(
        checker.check(
            target=type("Target", (), {
                "dns_name": "example.com", "dns_record_type": "A",
                "dns_expected_address": "192.0.2.15", "dns_max_response_ms": None,
            })(),
            timeout_seconds=1,
        )
    )
    assert outcome.status is CheckStatus.UP
    assert calls == [("example.com", socket.AF_INET)]

    mismatch = asyncio.run(
        checker.check(
            target=type("Target", (), {
                "dns_name": "example.com", "dns_record_type": "A",
                "dns_expected_address": "192.0.2.16", "dns_max_response_ms": None,
            })(),
            timeout_seconds=1,
        )
    )
    assert mismatch.status is CheckStatus.DOWN
    assert "Ожидался адрес" in (mismatch.message or "")


def test_dns_is_secondary_only_and_monitoring_uses_dns_name() -> None:
    registry = CheckerRegistry()

    class FakeDns:
        name = "dns"

        async def check(self, target, timeout_seconds):
            self.target = target
            return CheckOutcome(CheckStatus.UP, 1.0, "ok")

    fake = FakeDns()
    registry.register(fake)
    assert "dns" not in primary_checker_names(registry)
    fields = normalize_check_fields(
        registry, name="DNS", checker_type="dns", address_override="ignored",
        port=None, path="/ignored", timeout_seconds=None, retries=0,
    )
    assert fields[2:5] == (None, 53, "/")

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        target = MonitorTarget(site=Site(name="Site"), name="Target", checker_type="tcp", address="192.0.2.2", port=80, interval_seconds=60)
        session.add(target)
        session.flush()
        check = TargetCheck(target_id=target.id, name="DNS", checker_type="dns", port=53, dns_name="example.com", dns_record_type="A")
        session.add(check)
        session.flush()
        outcome = asyncio.run(MonitoringService(registry, 5, 1).check_target_check(target, check))
    assert outcome.status is CheckStatus.UP
    assert fake.target.dns_name == "example.com"
    assert fake.target.address == "192.0.2.2"
