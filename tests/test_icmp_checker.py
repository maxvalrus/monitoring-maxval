import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from monitoring.checks.base import CheckTarget
from monitoring.checks.icmp import IcmpChecker
from monitoring.models import CheckStatus


def test_icmp_checker_reports_alive_and_unreachable_hosts() -> None:
    with patch("monitoring.checks.icmp.async_ping", new=AsyncMock()) as ping:
        ping.return_value = MagicMock(is_alive=True, avg_rtt=8.75)
        success = asyncio.run(IcmpChecker().check(CheckTarget("192.0.2.1", 1), 1))
        ping.return_value = MagicMock(is_alive=False, avg_rtt=0)
        failure = asyncio.run(IcmpChecker().check(CheckTarget("192.0.2.2", 1), 1))

    assert success.status == CheckStatus.UP
    assert success.latency_ms == 8.75
    assert failure.status == CheckStatus.DOWN
