from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from monitoring.models import CheckStatus


@dataclass(frozen=True, slots=True)
class CheckTarget:
    address: str
    port: int
    path: str = "/"
    http_expected_status: int | None = None
    http_content_contains: str | None = None
    http_content_not_contains: str | None = None
    http_max_response_ms: float | None = None
    dns_name: str | None = None
    dns_record_type: str | None = None
    dns_expected_address: str | None = None
    dns_max_response_ms: float | None = None


@dataclass(frozen=True, slots=True)
class CheckOutcome:
    status: CheckStatus
    latency_ms: float | None = None
    message: str | None = None
    # Metadata from the already established HTTPS connection. It is deliberately
    # separate from availability: certificate expiry does not make HTTPS DOWN.
    tls_not_after: datetime | None = None
    # HTTP status from the response, including a response that does not satisfy
    # the availability criteria. It is used by the configuration form only.
    http_status_code: int | None = None
    # Read-only runtime returned by the Directory secondary check.  Keeping it on
    # the existing result object preserves the normal secondary-check lifecycle.
    directory_accessible: bool | None = None
    directory_files: tuple[dict[str, object], ...] | None = None
    directory_recent_count: int | None = None
    directory_latest_file_at: datetime | None = None


class Checker(Protocol):
    name: str

    async def check(self, target: CheckTarget, timeout_seconds: float) -> CheckOutcome: ...
