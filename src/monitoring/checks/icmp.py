from icmplib import async_ping

from monitoring.checks.base import CheckOutcome, CheckTarget
from monitoring.models import CheckStatus


class IcmpChecker:
    name = "icmp"

    async def check(self, target: CheckTarget, timeout_seconds: float) -> CheckOutcome:
        try:
            host = await async_ping(
                target.address,
                count=1,
                interval=0,
                timeout=timeout_seconds,
                privileged=False,
            )
        except (OSError, ValueError) as exc:
            return CheckOutcome(CheckStatus.DOWN, message=f"Ошибка ICMP: {str(exc)[:400]}")
        if not host.is_alive:
            return CheckOutcome(CheckStatus.DOWN, message="Узел не ответил на ICMP")
        latency_ms = round(float(host.avg_rtt), 2)
        return CheckOutcome(CheckStatus.UP, latency_ms, "Получен ответ ICMP")
