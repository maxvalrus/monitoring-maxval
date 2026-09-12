import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest

from monitoring.checks.base import CheckTarget
from monitoring.checks.http import HttpChecker, HttpsChecker
from monitoring.models import CheckStatus


def test_http_checker_reports_success_and_server_error() -> None:
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    client.get = AsyncMock()
    with patch("monitoring.checks.http.httpx.AsyncClient", return_value=client):
        client.get.return_value = MagicMock(status_code=204)
        success = asyncio.run(HttpChecker().check(CheckTarget("example.test", 80), 1))
        client.get.return_value = MagicMock(status_code=503)
        failure = asyncio.run(HttpChecker().check(CheckTarget("example.test", 80), 1))

    assert success.status == CheckStatus.UP
    assert success.message == "HTTP 204"
    assert success.http_status_code == 204
    assert failure.status == CheckStatus.DOWN
    assert failure.message == "HTTP вернул код 503"
    assert failure.http_status_code == 503


def test_https_checker_reuses_current_response_for_certificate_expiry() -> None:
    expires_at = datetime.now(UTC) + timedelta(days=90)
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    client.get = AsyncMock(return_value=MagicMock(status_code=200, extensions={}))
    with (
        patch.object(
            HttpsChecker,
            "_certificate_expiry_from_response",
            return_value=expires_at,
        ),
        patch("monitoring.checks.http.httpx.AsyncClient", return_value=client),
    ):
        outcome = asyncio.run(HttpsChecker().check(CheckTarget("example.test", 443), 1))

    assert outcome.status == CheckStatus.UP
    assert outcome.tls_not_after == expires_at
    assert "TLS до" in (outcome.message or "")
    assert "дн." in (outcome.message or "")
    client.get.assert_awaited_once()


@pytest.mark.parametrize(
    ("target", "status_code", "body", "expected_status", "message"),
    (
        (CheckTarget("example.test", 80, http_expected_status=200), 200, "ok", CheckStatus.UP, "HTTP 200"),
        (CheckTarget("example.test", 80, http_expected_status=200), 204, "ok", CheckStatus.DOWN, "HTTP вернул код 204, ожидался 200"),
        (CheckTarget("example.test", 80), 404, "missing", CheckStatus.DOWN, "HTTP вернул код 404"),
        (CheckTarget("example.test", 80, http_content_contains="healthy"), 200, "healthy", CheckStatus.UP, "HTTP 200"),
        (CheckTarget("example.test", 80, http_content_contains="healthy"), 200, "not ready", CheckStatus.DOWN, "HTTP: ожидаемое содержимое не найдено"),
        (CheckTarget("example.test", 80, http_content_not_contains="error"), 200, "healthy", CheckStatus.UP, "HTTP 200"),
        (CheckTarget("example.test", 80, http_content_not_contains="error"), 200, "error", CheckStatus.DOWN, "HTTP: найдено запрещённое содержимое"),
        (CheckTarget("example.test", 80, http_content_contains="ready", http_content_not_contains="error"), 200, "ready", CheckStatus.UP, "HTTP 200"),
    ),
)
def test_http_checker_deep_criteria(
    target: CheckTarget,
    status_code: int,
    body: str,
    expected_status: CheckStatus,
    message: str,
) -> None:
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    client.get = AsyncMock(return_value=MagicMock(status_code=status_code, text=body))

    with patch("monitoring.checks.http.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(HttpChecker().check(target, 1))

    assert outcome.status == expected_status
    assert outcome.message == message


def test_http_checker_keeps_latency_and_fails_above_deep_threshold() -> None:
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    client.get = AsyncMock(return_value=MagicMock(status_code=200))
    with (
        patch("monitoring.checks.http.httpx.AsyncClient", return_value=client),
        patch("monitoring.checks.http.perf_counter", side_effect=(10.0, 10.125)),
    ):
        outcome = asyncio.run(
            HttpChecker().check(CheckTarget("example.test", 80, http_max_response_ms=100), 1)
        )

    assert outcome.status == CheckStatus.DOWN
    assert outcome.latency_ms == 125.0
    assert outcome.message == "HTTP: время ответа 125 мс выше порога 100 мс"


def test_http_checker_does_not_read_body_without_content_criteria() -> None:
    response = MagicMock(status_code=200)
    body = PropertyMock(side_effect=AssertionError("body must not be read"))
    type(response).text = body
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    client.get = AsyncMock(return_value=response)

    with patch("monitoring.checks.http.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            HttpChecker().check(CheckTarget("example.test", 80, http_expected_status=200), 1)
        )

    assert outcome.status == CheckStatus.UP
    assert body.call_count == 0
