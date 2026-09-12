"""Runtime marker for a recovered, unconfirmed connectivity failure."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Protocol

UNSTABLE_LINK_TTL_MINUTES = 60


class UnstableLinkSource(Protocol):
    unstable_pending_down: bool
    unstable_until: datetime | None


def reset_unstable_link(source: UnstableLinkSource) -> None:
    """Clear runtime after disabling or materially changing a check."""
    source.unstable_pending_down = False
    source.unstable_until = None


def record_unconfirmed_down(source: UnstableLinkSource) -> None:
    source.unstable_pending_down = True


def record_confirmed_down(source: UnstableLinkSource) -> None:
    """A real outage takes precedence over the informational marker."""
    reset_unstable_link(source)


def record_recovered_up(
    source: UnstableLinkSource,
    *,
    observed_at: datetime,
    recovery_from_confirmed_incident: bool,
) -> None:
    """Set the marker only for UP after an unconfirmed DOWN."""
    if recovery_from_confirmed_incident:
        source.unstable_pending_down = False
        return
    if source.unstable_pending_down:
        source.unstable_until = observed_at + timedelta(minutes=UNSTABLE_LINK_TTL_MINUTES)
        source.unstable_pending_down = False


def unstable_link_active(source: UnstableLinkSource, *, now: datetime | None = None) -> bool:
    until = source.unstable_until
    if until is None:
        return False
    # PostgreSQL returns an aware timestamp. Keeping this defensive normalization
    # also makes local SQLite-based tests and legacy imports harmless.
    if until.tzinfo is None:
        until = until.replace(tzinfo=UTC)
    return until > (now or datetime.now(UTC))
