"""Small, audit-friendly clocks for engagement execution.

Wall-clock time is retained for audit, while active time advances only while
the lease is resumed.  Lease renewal is deliberately narrower than an
engagement amendment: it never changes the snapshot or its policy.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from ariadne.core.enums import AutonomyMode, EnvironmentProfile


def admitted_duration_seconds(
    requested_seconds: int | None,
    remaining_seconds: float,
) -> int | None:
    """Fit a playbook/process duration inside the current active lease.

    Returning a smaller duration is safe: it never raises a policy ceiling and
    lets the caller choose a shorter action when the lease is nearly spent.
    ``None`` means no executable window remains.
    """
    remaining = int(remaining_seconds)
    if remaining < 1:
        return None
    if requested_seconds is None:
        return remaining
    return max(1, min(requested_seconds, remaining))


@dataclass(frozen=True)
class LeaseRenewal:
    """An immutable audit record for one automatic execution-lease renewal."""

    previous_lease_minutes: int
    new_lease_minutes: int
    reason: str
    progress_evidence: str
    renewed_at: float

    def event_payload(self) -> dict[str, object]:
        return {
            "event_type": "execution_lease_renewed",
            "previous_lease_minutes": self.previous_lease_minutes,
            "new_lease_minutes": self.new_lease_minutes,
            "motivation": self.reason,
            "progress_evidence": self.progress_evidence,
            "renewed_at_monotonic": self.renewed_at,
        }


class ActiveTimeLease:
    """Track active execution time independently from wall-clock time.

    The lease is intended for HTB/CTF training runs in full autonomy.  A
    renewal extends only the operational window; historical active and
    wall-clock measurements remain intact.
    """

    RENEWAL_INCREMENT_MINUTES = 30

    def __init__(
        self,
        *,
        profile: EnvironmentProfile,
        autonomy: AutonomyMode,
        lease_minutes: int = 120,
        absolute_limit_minutes: int | None = None,
        clock: Callable[[], float] = time.monotonic,
        start_paused: bool = False,
        historical_active_seconds: float = 0.0,
        current_lease_active_seconds: float = 0.0,
        renewals: int = 0,
    ) -> None:
        if lease_minutes < 1:
            raise ValueError("lease_minutes must be positive")
        if absolute_limit_minutes is not None and absolute_limit_minutes < lease_minutes:
            raise ValueError("absolute_limit_minutes cannot be shorter than the initial lease")
        self.profile = profile
        self.autonomy = autonomy
        self.lease_minutes = lease_minutes
        self._absolute_limit_seconds = (
            None if absolute_limit_minutes is None else absolute_limit_minutes * 60.0
        )
        self._clock = clock
        self._wall_started = clock()
        self._active_segment_started: float | None = (
            None if start_paused else self._wall_started
        )
        self._historical_active = max(0.0, historical_active_seconds)
        self._lease_active = max(0.0, current_lease_active_seconds)
        self._renewals = max(0, renewals)
        self._attempt_started: float | None = None

    @property
    def wall_clock_seconds(self) -> float:
        return max(0.0, self._clock() - self._wall_started)

    @property
    def historical_active_seconds(self) -> float:
        return self._historical_active + self._open_segment_seconds()

    @property
    def current_lease_active_seconds(self) -> float:
        return self._lease_active + self._open_segment_seconds()

    @property
    def remaining_active_seconds(self) -> float:
        return max(0.0, self.lease_minutes * 60.0 - self.current_lease_active_seconds)

    @property
    def paused(self) -> bool:
        return self._active_segment_started is None

    @property
    def renewals(self) -> int:
        return self._renewals

    @property
    def attempt_active_seconds(self) -> float:
        if self._attempt_started is None:
            return 0.0
        return max(0.0, self._clock() - self._attempt_started)

    def start_attempt(self) -> None:
        """Start a fresh local timer for one tool attempt."""
        self._attempt_started = self._clock()

    def finish_attempt(self) -> None:
        """Close the local timer without changing the engagement lease."""
        self._attempt_started = None

    def _open_segment_seconds(self) -> float:
        if self._active_segment_started is None:
            return 0.0
        return max(0.0, self._clock() - self._active_segment_started)

    def _accumulate_open_segment(self) -> None:
        elapsed = self._open_segment_seconds()
        self._historical_active += elapsed
        self._lease_active += elapsed

    def pause(self, reason: str = "pause") -> None:
        if self._active_segment_started is None:
            return
        elapsed = self._open_segment_seconds()
        self._historical_active += elapsed
        self._lease_active += elapsed
        self._active_segment_started = None

    def resume(self) -> None:
        if self._active_segment_started is None:
            self._active_segment_started = self._clock()

    def can_renew(
        self,
        *,
        objectives_incomplete: bool,
        branch_available: bool,
        policy_change: bool = False,
    ) -> bool:
        if self.profile not in {EnvironmentProfile.HTB, EnvironmentProfile.CTF}:
            return False
        if self.autonomy is not AutonomyMode.FULL:
            return False
        if not objectives_incomplete or not branch_available or policy_change:
            return False
        if self._absolute_limit_seconds is not None:
            return self.historical_active_seconds < self._absolute_limit_seconds
        return True

    def ensure_available(
        self,
        *,
        objectives_incomplete: bool,
        branch_available: bool,
        reason: str,
        evidence: str,
        policy_change: bool = False,
    ) -> LeaseRenewal | None:
        if self.remaining_active_seconds > 0:
            return None
        if not self.can_renew(
            objectives_incomplete=objectives_incomplete,
            branch_available=branch_available,
            policy_change=policy_change,
        ):
            return None
        previous = self.lease_minutes
        self._accumulate_open_segment()
        increment = self.RENEWAL_INCREMENT_MINUTES
        if self._absolute_limit_seconds is not None:
            available = self._absolute_limit_seconds - self.historical_active_seconds
            increment = min(increment, max(0, int(available // 60)))
        if increment < 1:
            return None
        self.lease_minutes += increment
        self._lease_active = 0.0
        self._renewals += 1
        now = self._clock()
        if not self.paused:
            self._active_segment_started = now
        return LeaseRenewal(
            previous_lease_minutes=previous,
            new_lease_minutes=self.lease_minutes,
            reason=reason,
            progress_evidence=evidence,
            renewed_at=now,
        )
