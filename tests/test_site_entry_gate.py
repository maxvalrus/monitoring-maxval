import asyncio
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from monitoring.db import Base
from monitoring.models import CheckResult, MonitorTarget, Site
from monitoring.services.scheduler import CheckScheduler, ScheduledTarget
from monitoring.services.site_entry import (
    blocked_site_ids,
    blocking_gate_for_target,
    set_site_entry,
)
from monitoring.services.target_health import get_targets_health


def _engine():
    return create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


def _target(site: Site, name: str, *, kind: str = "network") -> MonitorTarget:
    return MonitorTarget(
        site=site,
        name=name,
        kind=kind,
        address="192.0.2.1",
        port=443,
        checker_type="tcp",
        enabled=True,
    )


def test_entry_down_blocks_siblings_but_disabled_entry_does_not() -> None:
    engine = _engine()
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        site = Site(name="Филиал")
        router = _target(site, "Router")
        server = _target(site, "Server", kind="server")
        session.add_all((site, router, server))
        session.flush()
        set_site_entry(session, router, True)
        session.add(CheckResult(target_id=router.id, status="down", message="timeout"))
        session.commit()

        assert blocked_site_ids(session) == {site.id}
        assert blocking_gate_for_target(session, router) is None
        gate = blocking_gate_for_target(session, server)
        assert gate is not None and gate.entry_target_id == router.id

        router.enabled = False
        session.flush()
        assert blocked_site_ids(session) == set()


def test_entry_moves_to_another_supported_target_and_rejects_printer() -> None:
    engine = _engine()
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        site = Site(name="Филиал")
        first = _target(site, "Router-1")
        second = _target(site, "Router-2")
        printer = _target(site, "Printer", kind="printer")
        session.add_all((site, first, second, printer))
        session.flush()

        assert set_site_entry(session, first, True) is None
        assert set_site_entry(session, second, True) == first.id
        assert first.is_site_entry is False
        assert second.is_site_entry is True
        try:
            set_site_entry(session, printer, True)
        except ValueError as exc:
            assert "Сеть" in str(exc)
        else:
            raise AssertionError("Expected ValueError")


def test_site_gate_health_hides_stale_child_offline_and_services() -> None:
    engine = _engine()
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        site = Site(name="Филиал")
        entry = _target(site, "Router")
        child = _target(site, "Server", kind="server")
        session.add_all((site, entry, child))
        session.flush()
        set_site_entry(session, entry, True)
        session.add_all(
            (
                CheckResult(target_id=entry.id, status="down"),
                CheckResult(target_id=child.id, status="down"),
            )
        )
        session.flush()

        health = get_targets_health(session, {entry.id: "down", child.id: "down"})

        assert health[entry.id].state == "offline"
        assert health[child.id].state == "site_unreachable"
        assert health[child.id].reason == "Router"
        assert health[child.id].reason_kind == "site_entry"
        assert health[child.id].services_ok is None


def test_scheduler_checks_entry_before_suppressing_blocked_children() -> None:
    scheduler = CheckScheduler(MagicMock(max_parallel_checks=4), poll_seconds=5)
    entry = SimpleNamespace(id=1, site_id=10, is_site_entry=True)
    child = SimpleNamespace(id=2, site_id=10, is_site_entry=False)
    other = SimpleNamespace(id=3, site_id=11, is_site_entry=False)
    calls: list[int] = []

    async def check(item):
        calls.append(item.target.id)

    scheduler._check_and_save = AsyncMock(side_effect=check)  # type: ignore[method-assign]
    scheduler._load_blocked_site_ids = MagicMock(return_value={10})  # type: ignore[method-assign]
    scheduler.metrics.mark_target_complete = MagicMock()

    asyncio.run(
        scheduler._run_site_gated_batch(
            [
                ScheduledTarget(entry, ()),
                ScheduledTarget(child, ()),
                ScheduledTarget(other, ()),
            ]
        )
    )

    assert calls == [1, 3]
    scheduler.metrics.mark_target_complete.assert_called_once_with(2)


def test_manual_child_check_is_neutral_when_its_site_entry_is_down(monkeypatch) -> None:
    engine = _engine()
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        site = Site(name="Филиал")
        entry = _target(site, "Router")
        child = _target(site, "Server", kind="server")
        session.add_all((site, entry, child))
        session.flush()
        set_site_entry(session, entry, True)
        session.add(CheckResult(target_id=entry.id, status="down"))
        session.commit()
        child_id = child.id

    @contextmanager
    def session_factory():
        with Session(engine) as session:
            yield session

    monitoring = MagicMock(max_parallel_checks=1)
    monitoring.check_target = AsyncMock()
    scheduler = CheckScheduler(monitoring, poll_seconds=5)
    monkeypatch.setattr("monitoring.services.scheduler.SessionLocal", session_factory)

    result = asyncio.run(scheduler.run_target_now(child_id))

    assert result.saved is False
    assert result.status == "unknown"
    assert result.message == "Не проверено: нет связи с площадкой (точка входа Router)"
    monitoring.check_target.assert_not_awaited()
