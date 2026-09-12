import asyncio
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock

from monitoring.checks.base import CheckOutcome
from monitoring.models import CheckStatus, SnmpStatus
from monitoring.services.scheduler import CheckScheduler


def test_manual_check_starts_once_and_checks_all_active_targets() -> None:
    monitoring = MagicMock()
    scheduler = CheckScheduler(monitoring, poll_seconds=15)
    targets = [MagicMock(id=1), MagicMock(id=2)]
    scheduler._load_active_targets = MagicMock(return_value=targets)
    scheduler._check_and_save = AsyncMock()

    async def scenario() -> None:
        assert scheduler.trigger_all() is True
        assert scheduler.trigger_all() is False
        assert scheduler._manual_task is not None
        await scheduler._manual_task

    asyncio.run(scenario())

    assert scheduler._load_active_targets.call_count == 1
    assert scheduler._check_and_save.await_count == 2


def test_snmp_polling_runs_only_after_successful_primary_check() -> None:
    monitoring = MagicMock()
    monitoring.check_target = AsyncMock(
        side_effect=[CheckOutcome(CheckStatus.DOWN), CheckOutcome(CheckStatus.UP)]
    )
    snmp = MagicMock()
    snmp.poll_target = AsyncMock()
    scheduler = CheckScheduler(monitoring, poll_seconds=15, snmp_service=snmp)
    scheduler._save_result = MagicMock(return_value=[])
    target = MagicMock(id=44)

    async def scenario() -> None:
        await scheduler._check_and_save(target)
        await scheduler._check_and_save(target)

    asyncio.run(scenario())

    assert scheduler._save_result.call_count == 2
    snmp.poll_target.assert_awaited_once_with(44)


def test_manual_interface_poll_skips_snmp_after_unsuccessful_primary_check(monkeypatch) -> None:
    monitoring = MagicMock()
    monitoring.check_target = AsyncMock(return_value=CheckOutcome(CheckStatus.DOWN))
    snmp = MagicMock()
    snmp.poll_target = AsyncMock()
    scheduler = CheckScheduler(monitoring, poll_seconds=15, snmp_service=snmp)
    session = MagicMock()
    session.scalar.return_value = MagicMock(id=44)

    @contextmanager
    def fake_session():
        yield session

    monkeypatch.setattr("monitoring.services.scheduler.SessionLocal", fake_session)

    result = asyncio.run(scheduler.poll_snmp_interfaces_now(44))

    assert result.status == "skipped"
    assert "основная проверка" in result.message
    snmp.poll_target.assert_not_awaited()


def test_manual_interface_poll_uses_existing_snmp_service(monkeypatch) -> None:
    monitoring = MagicMock()
    monitoring.check_target = AsyncMock(return_value=CheckOutcome(CheckStatus.UP))
    snmp = MagicMock()
    snmp.poll_target = AsyncMock()
    scheduler = CheckScheduler(monitoring, poll_seconds=15, snmp_service=snmp)
    target_session = MagicMock()
    target_session.scalar.return_value = MagicMock(id=44)
    status_session = MagicMock()
    status_session.get.return_value = MagicMock(enabled=True, last_status=SnmpStatus.OK)
    sessions = iter((target_session, status_session))

    @contextmanager
    def fake_session():
        yield next(sessions)

    monkeypatch.setattr("monitoring.services.scheduler.SessionLocal", fake_session)

    result = asyncio.run(scheduler.poll_snmp_interfaces_now(44))

    assert result.status == "ok"
    snmp.poll_target.assert_awaited_once_with(44)


def test_manual_ups_poll_skips_snmp_after_unsuccessful_primary_check(monkeypatch) -> None:
    monitoring = MagicMock()
    monitoring.check_target = AsyncMock(return_value=CheckOutcome(CheckStatus.DOWN))
    snmp = MagicMock()
    snmp.poll_target = AsyncMock()
    scheduler = CheckScheduler(monitoring, poll_seconds=15, snmp_service=snmp)
    session = MagicMock()
    session.scalar.return_value = MagicMock(id=44)
    session.get.return_value = MagicMock(enabled=True, ups_enabled=True)

    @contextmanager
    def fake_session():
        yield session

    monkeypatch.setattr("monitoring.services.scheduler.SessionLocal", fake_session)

    result = asyncio.run(scheduler.poll_snmp_ups_now(44))

    assert result.status == "skipped"
    assert "основная проверка" in result.message
    snmp.poll_target.assert_not_awaited()
