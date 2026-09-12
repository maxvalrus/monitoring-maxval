from __future__ import annotations

import asyncio
import socket
import time

from monitoring.checks.base import CheckOutcome, CheckTarget
from monitoring.models import CheckStatus


class DnsChecker:
    """Resolve one A or AAAA record through the host system resolver."""

    name = "dns"

    @staticmethod
    def _resolve(name: str, record_type: str) -> list[str]:
        family = socket.AF_INET if record_type == "A" else socket.AF_INET6
        rows = socket.getaddrinfo(name, None, family, socket.SOCK_STREAM)
        return list(dict.fromkeys(row[4][0] for row in rows))

    async def check(self, target: CheckTarget, timeout_seconds: float) -> CheckOutcome:
        name = target.dns_name or ""
        record_type = target.dns_record_type or "A"
        if not name or record_type not in {"A", "AAAA"}:
            return CheckOutcome(CheckStatus.UNKNOWN, message="Некорректные параметры DNS")
        started = time.perf_counter()
        try:
            addresses = await asyncio.wait_for(
                asyncio.to_thread(self._resolve, name, record_type), timeout=timeout_seconds
            )
        except TimeoutError:
            return CheckOutcome(CheckStatus.DOWN, message="Превышено время ожидания DNS")
        except (socket.gaierror, OSError):
            return CheckOutcome(CheckStatus.DOWN, message="DNS-имя не разрешается")
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        if not addresses:
            return CheckOutcome(CheckStatus.DOWN, latency_ms, "DNS-имя не разрешается")
        if target.dns_expected_address and target.dns_expected_address not in addresses:
            return CheckOutcome(
                CheckStatus.DOWN,
                latency_ms,
                f"Ожидался адрес {target.dns_expected_address}",
            )
        if target.dns_max_response_ms is not None and latency_ms > target.dns_max_response_ms:
            return CheckOutcome(
                CheckStatus.DOWN,
                latency_ms,
                f"DNS-ответ дольше {target.dns_max_response_ms:g} мс",
            )
        shown = ", ".join(addresses[:4])
        if len(addresses) > 4:
            shown += f" и ещё {len(addresses) - 4}"
        return CheckOutcome(CheckStatus.UP, latency_ms, f"DNS {record_type}: {shown}")
