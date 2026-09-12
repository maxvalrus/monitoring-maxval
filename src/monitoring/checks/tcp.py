import asyncio
from contextlib import suppress
from time import perf_counter

from monitoring.checks.base import CheckOutcome, CheckTarget
from monitoring.models import CheckStatus


class TcpChecker:
    name = "tcp"
    immediate_close_window_seconds = 0.1

    async def check(self, target: CheckTarget, timeout_seconds: float) -> CheckOutcome:
        started_at = perf_counter()
        writer: asyncio.StreamWriter | None = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target.address, target.port),
                timeout=timeout_seconds,
            )
            latency_ms = round((perf_counter() - started_at) * 1000, 2)
            try:
                first_byte = await asyncio.wait_for(
                    reader.read(1),
                    timeout=min(self.immediate_close_window_seconds, timeout_seconds),
                )
            except TimeoutError:
                first_byte = None
            if first_byte == b"":
                return CheckOutcome(
                    CheckStatus.DOWN,
                    latency_ms,
                    "TCP-соединение сразу закрыто удалённой стороной",
                )
            return CheckOutcome(CheckStatus.UP, latency_ms, "TCP-соединение установлено")
        except TimeoutError:
            return CheckOutcome(CheckStatus.DOWN, message="Истекло время ожидания TCP")
        except OSError as exc:
            return CheckOutcome(CheckStatus.DOWN, message=f"Ошибка TCP: {exc}")
        finally:
            if writer is not None:
                writer.close()
                with suppress(OSError):
                    await writer.wait_closed()
