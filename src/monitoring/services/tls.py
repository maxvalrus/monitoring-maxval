"""Narrow client for the isolated TLS manager service.

The web process can only ask the manager to validate candidates or apply a known
HTTP/HTTPS state.  It never receives Docker privileges or Caddy admin access.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import BinaryIO

import httpx

from monitoring.config import Settings


class TlsManagerError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class TlsStatus:
    available: bool
    active_valid: bool
    active_expires_at: str | None
    active_redirect_safe: bool
    candidate_valid: bool
    candidate_message: str | None


def _token(settings: Settings) -> str:
    secret = settings.secret_key.get_secret_value().encode("utf-8")
    return hmac.new(secret, b"monitoring-maxval-tls-manager", hashlib.sha256).hexdigest()


class TlsManager:
    def __init__(self, settings: Settings) -> None:
        self.url = settings.tls_manager_url.rstrip("/")
        self.headers = {"X-TLS-Manager-Token": _token(settings)}

    def _request(self, method: str, path: str, **kwargs):
        try:
            response = httpx.request(
                method,
                f"{self.url}{path}",
                headers=self.headers,
                timeout=3,
                trust_env=False,
                **kwargs,
            )
        except httpx.HTTPError as exc:
            raise TlsManagerError("Сервис управления HTTPS недоступен") from exc
        if response.status_code >= 400:
            try:
                message = response.json().get("detail", "")
            except ValueError:
                message = ""
            raise TlsManagerError(message or "Не удалось применить TLS-конфигурацию")
        return response.json()

    def status(self) -> TlsStatus:
        try:
            data = self._request("GET", "/status")
        except TlsManagerError:
            return TlsStatus(False, False, None, False, False, None)
        return TlsStatus(
            True,
            bool(data.get("active_valid")),
            data.get("active_expires_at"),
            bool(data.get("active_redirect_safe")),
            bool(data.get("candidate_valid")),
            data.get("candidate_message"),
        )

    def upload_candidate(self, certificate: BinaryIO, key: BinaryIO) -> dict[str, object]:
        return self._request("POST", "/candidate", files={
            "certificate": ("fullchain.pem", certificate, "application/x-pem-file"),
            "private_key": ("privkey.pem", key, "application/x-pem-file"),
        })

    def apply(self, *, https_enabled: bool, redirect_http: bool) -> dict[str, object]:
        return self._request(
            "POST",
            "/apply",
            json={"https_enabled": https_enabled, "redirect_http": redirect_http},
        )

    def rollback(self) -> dict[str, object]:
        return self._request("POST", "/rollback")

    def disable_redirect(self) -> dict[str, object]:
        return self._request("POST", "/disable-redirect")

    def create_internal_candidate(
        self, *, common_name: str, dns_names: list[str], ip_addresses: list[str]
    ) -> dict[str, object]:
        return self._request(
            "POST",
            "/internal-ca",
            json={
                "common_name": common_name,
                "dns_names": dns_names,
                "ip_addresses": ip_addresses,
            },
        )

    def internal_ca_certificate(self) -> bytes:
        try:
            response = httpx.get(
                f"{self.url}/internal-ca/certificate",
                headers=self.headers,
                timeout=3,
                trust_env=False,
            )
        except httpx.HTTPError as exc:
            raise TlsManagerError("Сервис управления HTTPS недоступен") from exc
        if response.status_code >= 400:
            raise TlsManagerError("Внутренний CA ещё не создан")
        return response.content
