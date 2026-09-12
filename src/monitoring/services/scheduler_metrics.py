from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Lock

from monitoring.models import CheckStatus

ROLLING_WINDOW_SECONDS = 300
DELAY_WARNING_SECONDS = 60


@dataclass(frozen=True, slots=True)
class DueTargetTiming:
    target_id: int
    lag_seconds: float
    interval_seconds: int


@dataclass(frozen=True, slots=True)
class SchedulerErrorEvent:
    occurred_at: datetime
    exception_type: str


@dataclass(frozen=True, slots=True)
class SchedulerHealthSnapshot:
    running: bool
    manual_running: bool
    poll_seconds: int
    parallel_limit: int
    queue_count: int
    delayed_count: int
    missed_interval_count: int
    oldest_lag_seconds: float
    current_batch_size: int
    last_batch_size: int
    last_batch_duration_seconds: float | None
    last_batch_shortest_interval_seconds: int | None
    headroom_percent: float | None
    checks_5m: int
    unknown_5m: int
    average_check_seconds: float | None
    p95_check_seconds: float | None
    scheduler_errors_5m: int
    scheduler_error_events: tuple[SchedulerErrorEvent, ...]
    last_scan_at: datetime | None


@dataclass(frozen=True, slots=True)
class _CheckEvent:
    at_monotonic: float
    duration_seconds: float
    status: str


class SchedulerRuntimeMetrics:
    """Small in-memory snapshot for portal self-monitoring.

    The scheduler is the source of truth for queue timing, so the dashboard can read a
    cheap immutable snapshot instead of re-running the due-target query on every page
    load. Metrics are intentionally process-local because the project runs one embedded
    scheduler in one application process.
    """

    def __init__(self, *, poll_seconds: int, parallel_limit: int) -> None:
        self.poll_seconds = poll_seconds
        self.parallel_limit = max(1, parallel_limit)
        self._lock = Lock()
        self._current_due: dict[int, tuple[float, int]] = {}
        self._scan_monotonic: float | None = None
        self._last_scan_at: datetime | None = None
        self._batch_started_monotonic: float | None = None
        self._current_batch_size = 0
        self._current_batch_shortest_interval_seconds: int | None = None
        self._last_batch_size = 0
        self._last_batch_duration_seconds: float | None = None
        self._last_batch_shortest_interval_seconds: int | None = None
        self._check_events: deque[_CheckEvent] = deque()
        self._scheduler_errors: deque[tuple[float, SchedulerErrorEvent]] = deque()

    def record_scan(self, entries: list[DueTargetTiming]) -> None:
        now_monotonic = time.monotonic()
        now = datetime.now(UTC)
        with self._lock:
            self._current_due = {
                entry.target_id: (max(0.0, entry.lag_seconds), max(1, entry.interval_seconds))
                for entry in entries
            }
            self._scan_monotonic = now_monotonic
            self._last_scan_at = now
            self._current_batch_size = len(entries)
            self._batch_started_monotonic = now_monotonic if entries else None

    def record_check(
        self, target_id: int, duration_seconds: float, status: CheckStatus | str
    ) -> None:
        self._record_network_check(duration_seconds, status, target_id=target_id)

    def record_network_check(
        self, duration_seconds: float, status: CheckStatus | str
    ) -> None:
        self._record_network_check(duration_seconds, status, target_id=None)

    def mark_target_complete(self, target_id: int) -> None:
        with self._lock:
            self._current_due.pop(target_id, None)

    def _record_network_check(
        self,
        duration_seconds: float,
        status: CheckStatus | str,
        *,
        target_id: int | None,
    ) -> None:
        now = time.monotonic()
        normalized_status = status.value if isinstance(status, CheckStatus) else str(status)
        with self._lock:
            self._check_events.append(
                _CheckEvent(
                    at_monotonic=now,
                    duration_seconds=max(0.0, duration_seconds),
                    status=normalized_status,
                )
            )
            if target_id is not None:
                self._current_due.pop(target_id, None)
            self._trim_locked(now)

    def finish_batch(self) -> None:
        now = time.monotonic()
        with self._lock:
            if self._batch_started_monotonic is not None:
                self._last_batch_duration_seconds = max(
                    0.0, now - self._batch_started_monotonic
                )
                self._last_batch_size = self._current_batch_size
                self._last_batch_shortest_interval_seconds = (
                    self._current_batch_shortest_interval_seconds
                )
            self._current_due.clear()
            self._scan_monotonic = None
            self._batch_started_monotonic = None
            self._current_batch_size = 0
            self._current_batch_shortest_interval_seconds = None
            self._trim_locked(now)

    def set_batch_shortest_interval(self, interval_seconds: int | None) -> None:
        with self._lock:
            self._current_batch_shortest_interval_seconds = (
                max(1, interval_seconds) if interval_seconds is not None else None
            )

    def record_scheduler_error(self, error: Exception) -> None:
        now_monotonic = time.monotonic()
        event = SchedulerErrorEvent(
            occurred_at=datetime.now(UTC),
            exception_type=type(error).__name__,
        )
        with self._lock:
            self._scheduler_errors.append((now_monotonic, event))
            self._trim_locked(now_monotonic)

    def snapshot(self, *, running: bool, manual_running: bool) -> SchedulerHealthSnapshot:
        now = time.monotonic()
        with self._lock:
            self._trim_locked(now)
            scan_age = max(0.0, now - self._scan_monotonic) if self._scan_monotonic else 0.0
            remaining = tuple(self._current_due.values())
            effective_lags = tuple(lag + scan_age for lag, _interval in remaining)
            delayed_count = sum(lag >= DELAY_WARNING_SECONDS for lag in effective_lags)
            missed_interval_count = sum(
                lag >= interval
                for lag, (_base_lag, interval) in zip(
                    effective_lags, remaining, strict=False
                )
            )
            oldest_lag = max(effective_lags, default=0.0)
            events = tuple(self._check_events)
            durations = sorted(event.duration_seconds for event in events)
            average = sum(durations) / len(durations) if durations else None
            p95 = None
            if durations:
                index = max(0, math.ceil(len(durations) * 0.95) - 1)
                p95 = durations[index]
            headroom = self._headroom_locked()
            return SchedulerHealthSnapshot(
                running=running,
                manual_running=manual_running,
                poll_seconds=self.poll_seconds,
                parallel_limit=self.parallel_limit,
                queue_count=len(remaining),
                delayed_count=delayed_count,
                missed_interval_count=missed_interval_count,
                oldest_lag_seconds=oldest_lag,
                current_batch_size=self._current_batch_size,
                last_batch_size=self._last_batch_size,
                last_batch_duration_seconds=self._last_batch_duration_seconds,
                last_batch_shortest_interval_seconds=self._last_batch_shortest_interval_seconds,
                headroom_percent=headroom,
                checks_5m=len(events),
                unknown_5m=sum(event.status == CheckStatus.UNKNOWN.value for event in events),
                average_check_seconds=average,
                p95_check_seconds=p95,
                scheduler_errors_5m=len(self._scheduler_errors),
                scheduler_error_events=tuple(
                    event for _at_monotonic, event in reversed(self._scheduler_errors)
                ),
                last_scan_at=self._last_scan_at,
            )

    def _headroom_locked(self) -> float | None:
        duration = self._last_batch_duration_seconds
        interval = self._last_batch_shortest_interval_seconds
        if duration is None or interval is None or interval <= 0:
            return None
        used = duration + self.poll_seconds
        return round(max(0.0, min(100.0, (1.0 - used / interval) * 100.0)), 1)

    def _trim_locked(self, now: float) -> None:
        threshold = now - ROLLING_WINDOW_SECONDS
        while self._check_events and self._check_events[0].at_monotonic < threshold:
            self._check_events.popleft()
        while self._scheduler_errors and self._scheduler_errors[0][0] < threshold:
            self._scheduler_errors.popleft()
