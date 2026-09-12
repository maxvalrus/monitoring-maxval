from datetime import UTC, datetime

from monitoring.services.time_display import format_datetime


def test_utc_datetime_is_rendered_in_configured_timezone() -> None:
    value = datetime(2026, 8, 15, 12, 30, 45, tzinfo=UTC)

    rendered = format_datetime(value, "Europe/Moscow")

    assert rendered == "15.08.2026 15:30:45 MSK"


def test_naive_database_datetime_is_treated_as_utc() -> None:
    value = datetime(2026, 8, 15, 12, 30, 45)

    rendered = format_datetime(value, "Europe/Moscow")

    assert rendered == "15.08.2026 15:30:45 MSK"
