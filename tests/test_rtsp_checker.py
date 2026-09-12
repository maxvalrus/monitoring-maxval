import asyncio

import pytest

from monitoring.checks.base import CheckTarget
from monitoring.checks.rtsp import RtspChecker
from monitoring.models import CheckStatus


async def run_rtsp_response(status_line: str):
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n\r\n")
        writer.write(f"{status_line}\r\nCSeq: 1\r\n\r\n".encode())
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        return await RtspChecker().check(
            CheckTarget(address="127.0.0.1/stream1", port=port),
            timeout_seconds=1,
        )


@pytest.mark.parametrize(
    ("status_line", "expected"),
    [("RTSP/1.0 200 OK", CheckStatus.UP), ("RTSP/1.0 401 Unauthorized", CheckStatus.UP)],
)
def test_rtsp_checker_accepts_stream_and_auth_challenge(status_line, expected) -> None:
    result = asyncio.run(run_rtsp_response(status_line))
    assert result.status == expected
    assert result.latency_ms is not None


def test_rtsp_checker_rejects_missing_stream() -> None:
    result = asyncio.run(run_rtsp_response("RTSP/1.0 404 Not Found"))
    assert result.status == CheckStatus.DOWN
    assert "404" in (result.message or "")


def test_rtsp_address_does_not_accept_embedded_credentials() -> None:
    with pytest.raises(ValueError):
        RtspChecker._host_and_path("rtsp://user:secret@camera.local/stream")
