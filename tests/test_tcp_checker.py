import asyncio
import socket

from monitoring.checks.base import CheckTarget
from monitoring.checks.tcp import TcpChecker
from monitoring.models import CheckStatus


def test_tcp_checker_reports_available_port() -> None:
    async def scenario() -> None:
        async def hold_client(_, writer: asyncio.StreamWriter) -> None:
            await asyncio.sleep(TcpChecker.immediate_close_window_seconds * 2)
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(hold_client, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            outcome = await TcpChecker().check(CheckTarget("127.0.0.1", port), 1)
        finally:
            server.close()
            await server.wait_closed()

        assert outcome.status is CheckStatus.UP
        assert outcome.latency_ms is not None

    asyncio.run(scenario())


def test_tcp_checker_rejects_immediately_closed_connection() -> None:
    async def scenario() -> None:
        async def close_client(_, writer: asyncio.StreamWriter) -> None:
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(close_client, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            outcome = await TcpChecker().check(CheckTarget("127.0.0.1", port), 1)
        finally:
            server.close()
            await server.wait_closed()

        assert outcome.status is CheckStatus.DOWN
        assert "сразу закрыто" in (outcome.message or "")

    asyncio.run(scenario())


def test_tcp_checker_reports_closed_port() -> None:
    async def scenario() -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]

        outcome = await TcpChecker().check(CheckTarget("127.0.0.1", port), 1)
        assert outcome.status is CheckStatus.DOWN
        assert outcome.message

    asyncio.run(scenario())
