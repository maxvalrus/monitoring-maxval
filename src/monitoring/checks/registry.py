from importlib import metadata

from monitoring.checks.base import Checker


class CheckerRegistry:
    def __init__(self) -> None:
        self._checkers: dict[str, Checker] = {}

    def register(self, checker: Checker) -> None:
        if checker.name in self._checkers:
            raise ValueError(f"Checker '{checker.name}' is already registered")
        self._checkers[checker.name] = checker

    def get(self, name: str) -> Checker:
        try:
            return self._checkers[name]
        except KeyError as exc:
            raise LookupError(f"Unknown checker: {name}") from exc

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._checkers))

    def load_entry_points(self, group: str = "monitoring.checkers") -> None:
        """Load optional checker packages without coupling them to the core source tree."""
        for entry_point in metadata.entry_points(group=group):
            loaded = entry_point.load()
            checker = loaded() if isinstance(loaded, type) else loaded
            self.register(checker)


checker_registry = CheckerRegistry()
