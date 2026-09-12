from datetime import UTC, datetime
from time import perf_counter

import httpx
from cryptography import x509

from monitoring.checks.base import CheckOutcome, CheckTarget
from monitoring.models import CheckStatus


class HttpChecker:
    name = "http"
    scheme = "http"

    async def check(self, target: CheckTarget, timeout_seconds: float) -> CheckOutcome:
        started_at = perf_counter()
        url_host = f"[{target.address}]" if ":" in target.address else target.address
        path = target.path if target.path.startswith("/") else f"/{target.path}"
        url = f"{self.scheme}://{url_host}:{target.port}{path}"
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=timeout_seconds,
            ) as client:
                response = await client.get(url)
        except httpx.TimeoutException:
            return CheckOutcome(
                CheckStatus.DOWN,
                message=f"Истекло время ожидания {self.scheme.upper()}",
            )
        except httpx.HTTPError as exc:
            return CheckOutcome(
                CheckStatus.DOWN,
                message=f"Ошибка {self.scheme.upper()}: {str(exc)[:400]}",
            )
        latency_ms = round((perf_counter() - started_at) * 1000, 2)
        tls_not_after = self._certificate_expiry_from_response(response)
        if (
            target.http_expected_status is not None
            and response.status_code != target.http_expected_status
        ):
            return CheckOutcome(
                CheckStatus.DOWN,
                latency_ms,
                (
                    f"{self.scheme.upper()} вернул код {response.status_code}, "
                    f"ожидался {target.http_expected_status}"
                ),
                tls_not_after=tls_not_after,
                http_status_code=response.status_code,
            )
        if target.http_expected_status is None and response.status_code >= 400:
            return CheckOutcome(
                CheckStatus.DOWN,
                latency_ms,
                f"{self.scheme.upper()} вернул код {response.status_code}",
                tls_not_after=tls_not_after,
                http_status_code=response.status_code,
            )
        if target.http_content_contains or target.http_content_not_contains:
            body = response.text
            if (
                target.http_content_contains is not None
                and target.http_content_contains not in body
            ):
                return CheckOutcome(
                    CheckStatus.DOWN,
                    latency_ms,
                    "HTTP: ожидаемое содержимое не найдено",
                    tls_not_after=tls_not_after,
                    http_status_code=response.status_code,
                )
            if (
                target.http_content_not_contains is not None
                and target.http_content_not_contains in body
            ):
                return CheckOutcome(
                    CheckStatus.DOWN,
                    latency_ms,
                    "HTTP: найдено запрещённое содержимое",
                    tls_not_after=tls_not_after,
                    http_status_code=response.status_code,
                )
        if (
            target.http_max_response_ms is not None
            and latency_ms > target.http_max_response_ms
        ):
            return CheckOutcome(
                CheckStatus.DOWN,
                latency_ms,
                (
                    f"HTTP: время ответа {latency_ms:.0f} мс выше порога "
                    f"{target.http_max_response_ms:.0f} мс"
                ),
                tls_not_after=tls_not_after,
                http_status_code=response.status_code,
            )
        return CheckOutcome(
            CheckStatus.UP,
            latency_ms,
            self._success_message(response.status_code, tls_not_after),
            tls_not_after=tls_not_after,
            http_status_code=response.status_code,
        )

    @staticmethod
    def _certificate_expiry_from_response(response: httpx.Response) -> datetime | None:
        return None

    def _success_message(
        self, status_code: int, tls_not_after: datetime | None
    ) -> str:
        return f"{self.scheme.upper()} {status_code}"


class HttpsChecker(HttpChecker):
    name = "https"
    scheme = "https"

    @staticmethod
    def _certificate_expiry_from_response(response: httpx.Response) -> datetime | None:
        """Read the peer certificate from httpx's current HTTPS connection.

        `network_stream` belongs to the response that was just fetched. This avoids
        the former second socket/TLS handshake solely for expiry inspection.
        """
        try:
            stream = response.extensions.get("network_stream")
            ssl_object = stream.get_extra_info("ssl_object") if stream is not None else None
            if ssl_object is None:
                return None
            certificate = ssl_object.getpeercert(binary_form=True)
            if not certificate:
                return None
            return x509.load_der_x509_certificate(certificate).not_valid_after_utc
        except (AttributeError, TypeError, ValueError):
            return None

    def _success_message(
        self, status_code: int, tls_not_after: datetime | None
    ) -> str:
        message = super()._success_message(status_code, tls_not_after)
        if tls_not_after is None:
            return message
        days_left = max(0, int((tls_not_after - datetime.now(UTC)).total_seconds() // 86400))
        return f"{message}; TLS до {tls_not_after.strftime('%d.%m.%Y')} ({days_left} дн.)"
