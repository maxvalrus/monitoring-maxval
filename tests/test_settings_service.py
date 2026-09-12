import pytest

from monitoring.services.settings import validate_setting


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        ("default_check_interval_seconds", "300", "300"),
        ("failures_before_incident", "2", "2"),
        ("history_retention_days", "90", "90"),
        ("snmp_sample_max_per_target", "1000", "1000"),
        ("availability_warning_threshold_percent", "1", "1"),
        ("availability_good_threshold_percent", "100", "100"),
        ("notifications_enabled", "TRUE", "true"),
        ("min_password_length", "12", "12"),
        ("display_timezone", "Europe/Moscow", "Europe/Moscow"),
    ],
)
def test_editable_settings_are_normalized(key: str, value: str, expected: str) -> None:
    assert validate_setting(key, value) == expected


def test_check_interval_cannot_be_more_frequent_than_one_minute() -> None:
    with pytest.raises(ValueError, match="Минимальное"):
        validate_setting("default_check_interval_seconds", "30")


@pytest.mark.parametrize("value", ["99", "100001"])
def test_snmp_sample_limit_stays_within_safe_range(value: str) -> None:
    with pytest.raises(ValueError):
        validate_setting("snmp_sample_max_per_target", value)


@pytest.mark.parametrize(
    "key",
    [
        "availability_warning_threshold_percent",
        "availability_good_threshold_percent",
    ],
)
def test_availability_color_thresholds_are_percentages(key: str) -> None:
    assert validate_setting(key, "0") == "0"
    assert validate_setting(key, "100") == "100"
    with pytest.raises(ValueError):
        validate_setting(key, "101")


def test_password_minimum_accepts_three_and_rejects_two() -> None:
    assert validate_setting("min_password_length", "3") == "3"
    with pytest.raises(ValueError, match="Минимальное значение: 3"):
        validate_setting("min_password_length", "2")


def test_unknown_setting_cannot_be_changed() -> None:
    with pytest.raises(ValueError, match="нельзя изменять"):
        validate_setting("secret_key", "anything")


def test_unknown_display_timezone_is_rejected() -> None:
    with pytest.raises(ValueError, match="Неизвестный часовой пояс IANA"):
        validate_setting("display_timezone", "Mars/Olympus")
