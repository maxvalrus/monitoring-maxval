import asyncio
from contextlib import suppress
from time import perf_counter
from urllib.parse import urlsplit

from monitoring.checks.base import CheckOutcome, CheckTarget
from monitoring.models import CheckStatus


class RtspChecker:
    """Lightweight RTSP endpoint check without downloading or decoding video."""

    name = "rtsp"

    async def check(self, target: CheckTarget, timeout_seconds: float) -> CheckOutcome:
        host, path = self._host_and_path(target.address)
        url_host = f"[{host}]" if ":" in host else host
        started_at = perf_counter()
        writer: asyncio.StreamWriter | None = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, target.port),
                timeout=timeout_seconds,
            )
            request = (
                f"OPTIONS rtsp://{url_host}:{target.port}{path} RTSP/1.0\r\n"
                "CSeq: 1\r\n"
                "User-Agent: Monitoring-Maxval/0.5\r\n\r\n"
            )
            writer.write(request.encode("ascii"))
            await asyncio.wait_for(writer.drain(), timeout=timeout_seconds)
            line = await asyncio.wait_for(reader.readline(), timeout=timeout_seconds)
        except TimeoutError:
            return CheckOutcome(CheckStatus.DOWN, message="Истекло время ожидания RTSP")
        except (OSError, UnicodeError, ValueError) as exc:
            return CheckOutcome(CheckStatus.DOWN, message=f"Ошибка RTSP: {str(exc)[:400]}")
        finally:
            if writer is not None:
                writer.close()
                with suppress(OSError):
                    await writer.wait_closed()

        latency_ms = round((perf_counter() - started_at) * 1000, 2)
        status_line = line.decode("ascii", errors="replace").strip()
        parts = status_line.split(maxsplit=2)
        if len(parts) < 2 or not parts[0].startswith("RTSP/") or not parts[1].isdigit():
            return CheckOutcome(
                CheckStatus.DOWN,
                latency_ms,
                "Сервер не вернул корректный ответ RTSP",
            )
        status_code = int(parts[1])
        if 200 <= status_code < 400:
            return CheckOutcome(CheckStatus.UP, latency_ms, f"RTSP {status_code}")
        if status_code == 401:
            return CheckOutcome(
                CheckStatus.UP,
                latency_ms,
                "RTSP 401 · поток доступен, требуется авторизация",
            )
        return CheckOutcome(
            CheckStatus.DOWN,
            latency_ms,
            f"RTSP вернул код {status_code}",
        )

    @staticmethod
    def _host_and_path(address: str) -> tuple[str, str]:
        value = address.strip()
        parsed = urlsplit(value if "://" in value else f"rtsp://{value}")
        if (
            parsed.scheme.casefold() != "rtsp"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("некорректный адрес потока")
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return parsed.hostname, path
