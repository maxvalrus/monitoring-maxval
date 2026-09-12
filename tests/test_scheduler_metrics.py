from monitoring.models import CheckStatus
from monitoring.services.scheduler_metrics import DueTargetTiming, SchedulerRuntimeMetrics


def test_scheduler_runtime_snapshot_tracks_queue_window_and_headroom(monkeypatch) -> None:
    ticks = iter((100.0, 101.0, 102.0, 120.0, 121.0))
    monkeypatch.setattr(
        "monitoring.services.scheduler_metrics.time.monotonic", lambda: next(ticks)
    )
    metrics = SchedulerRuntimeMetrics(poll_seconds=15, parallel_limit=10)
    metrics.record_scan(
        [DueTargetTiming(target_id=7, lag_seconds=75, interval_seconds=300)]
    )
    metrics.set_batch_shortest_interval(300)

    queued = metrics.snapshot(running=True, manual_running=False)
    assert queued.queue_count == 1
    assert queued.delayed_count == 1
    assert queued.missed_interval_count == 0
    assert queued.oldest_lag_seconds == 76

    metrics.record_check(7, 2.0, CheckStatus.UP)
    metrics.finish_batch()
    complete = metrics.snapshot(running=True, manual_running=False)

    assert complete.queue_count == 0
    assert complete.last_batch_size == 1
    assert complete.last_batch_duration_seconds == 20
    assert complete.headroom_percent == 88.3
    assert complete.checks_5m == 1
    assert complete.unknown_5m == 0
    assert complete.average_check_seconds == 2
    assert complete.p95_check_seconds == 2


def test_scheduler_runtime_snapshot_marks_missed_intervals(monkeypatch) -> None:
    ticks = iter((200.0, 321.0))
    monkeypatch.setattr(
        "monitoring.services.scheduler_metrics.time.monotonic", lambda: next(ticks)
    )
    metrics = SchedulerRuntimeMetrics(poll_seconds=15, parallel_limit=4)
    metrics.record_scan(
        [DueTargetTiming(target_id=8, lag_seconds=200, interval_seconds=300)]
    )

    snapshot = metrics.snapshot(running=True, manual_running=False)

    assert snapshot.queue_count == 1
    assert snapshot.delayed_count == 1
    assert snapshot.missed_interval_count == 1
    assert snapshot.oldest_lag_seconds == 321


def test_scheduler_runtime_snapshot_keeps_safe_error_details(monkeypatch) -> None:
    monkeypatch.setattr("monitoring.services.scheduler_metrics.time.monotonic", lambda: 100.0)
    metrics = SchedulerRuntimeMetrics(poll_seconds=15, parallel_limit=4)

    metrics.record_scheduler_error(RuntimeError("secret target address must not be shown"))
    snapshot = metrics.snapshot(running=True, manual_running=False)

    assert snapshot.scheduler_errors_5m == 1
    assert snapshot.scheduler_error_events[0].exception_type == "RuntimeError"
