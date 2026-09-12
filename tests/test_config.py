import os

import pytest

from monitoring.config import Settings


@pytest.fixture(autouse=True)
def isolate_monitoring_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if name.startswith("MONITORING_"):
            monkeypatch.delenv(name)


def test_default_check_interval_is_five_minutes() -> None:
    settings = Settings(_env_file=None)
    assert settings.default_check_interval_seconds == 300


def test_production_rejects_default_secret() -> None:
    settings = Settings(environment="production", _env_file=None)
    with pytest.raises(RuntimeError, match="MONITORING_SECRET_KEY"):
        settings.validate_production()


def test_allowed_hosts_are_trimmed() -> None:
    settings = Settings(allowed_hosts="localhost, 10.0.0.5 ,,monitoring.local", _env_file=None)
    assert settings.allowed_hosts_list == ["localhost", "10.0.0.5", "monitoring.local"]


def test_production_cookie_is_secure_by_default() -> None:
    settings = Settings(environment="production", _env_file=None)
    assert settings.effective_cookie_secure is True


def test_http_cookie_requires_explicit_override() -> None:
    settings = Settings(
        environment="production",
        session_cookie_secure=False,
        _env_file=None,
    )
    assert settings.effective_cookie_secure is False
