from __future__ import annotations

import ipaddress
import re

DNS_CHECKER_TYPE = "dns"
DNS_RECORD_TYPES = frozenset({"A", "AAAA"})
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_dns_fields(
    *,
    checker_type: str,
    name: str | None,
    record_type: str | None,
    expected_address: str | None,
    max_response_ms: float | None,
) -> tuple[str | None, str | None, str | None, float | None]:
    """Normalize DNS-only fields and clear them for every other check type."""
    if checker_type != DNS_CHECKER_TYPE:
        return None, None, None, None
    raw_name = (name or "").strip().rstrip(".")
    if not raw_name or "://" in raw_name or "/" in raw_name or any(
        character.isspace() for character in raw_name
    ):
        raise ValueError("DNS-имя должно быть доменным именем без схемы, пути и пробелов")
    try:
        clean_name = raw_name.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Некорректное DNS-имя") from exc
    labels = clean_name.split(".")
    if len(clean_name) > 253 or any(not _DNS_LABEL.fullmatch(label) for label in labels):
        raise ValueError("Некорректное DNS-имя")
    clean_type = (record_type or "A").upper()
    if clean_type not in DNS_RECORD_TYPES:
        raise ValueError("Поддерживаются только записи DNS A и AAAA")
    clean_expected = (expected_address or "").strip() or None
    if clean_expected is not None:
        try:
            parsed = ipaddress.ip_address(clean_expected)
        except ValueError as exc:
            raise ValueError("Ожидаемый DNS-адрес должен быть IP-адресом") from exc
        if (clean_type == "A" and parsed.version != 4) or (
            clean_type == "AAAA" and parsed.version != 6
        ):
            raise ValueError("Семейство ожидаемого адреса должно соответствовать типу DNS-записи")
        clean_expected = str(parsed)
    clean_max = None if max_response_ms is None else float(max_response_ms)
    if clean_max is not None and clean_max <= 0:
        raise ValueError("Максимальное время DNS-ответа должно быть больше 0 мс")
    return clean_name, clean_type, clean_expected, clean_max
