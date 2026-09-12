import pytest

from monitoring.checks.base import CheckOutcome, CheckTarget
from monitoring.checks.registry import CheckerRegistry
from monitoring.models import CheckStatus


class FakeChecker:
    name = "fake"

    async def check(self, target: CheckTarget, timeout_seconds: float) -> CheckOutcome:
        return CheckOutcome(CheckStatus.UP)


def test_registry_returns_registered_checker() -> None:
    registry = CheckerRegistry()
    checker = FakeChecker()
    registry.register(checker)
    assert registry.get("fake") is checker
    assert registry.names == ("fake",)


def test_registry_rejects_duplicate_name() -> None:
    registry = CheckerRegistry()
    registry.register(FakeChecker())
    with pytest.raises(ValueError, match="already registered"):
        registry.register(FakeChecker())


def test_registry_rejects_unknown_checker() -> None:
    with pytest.raises(LookupError, match="Unknown checker"):
        CheckerRegistry().get("missing")
