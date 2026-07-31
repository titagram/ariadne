from __future__ import annotations

from ariadne.core.enums import AutonomyMode, EnvironmentProfile
from ariadne.core.timing import (
    ActiveTimeLease,
    LeaseRenewal,
    admitted_duration_seconds,
)


def test_playbook_budget_is_capped_to_remaining_lease() -> None:
    assert admitted_duration_seconds(300, 295.9) == 295
    assert admitted_duration_seconds(300, 0.5) is None


def test_attempt_timer_resets_for_a_fallback() -> None:
    clock = [0.0]
    lease = ActiveTimeLease(
        profile=EnvironmentProfile.HTB,
        autonomy=AutonomyMode.FULL,
        lease_minutes=10,
        clock=lambda: clock[0],
    )
    lease.start_attempt()
    clock[0] = 20.0
    assert lease.attempt_active_seconds == 20.0
    lease.finish_attempt()
    clock[0] = 100.0  # waiting/fallback selection is not this attempt
    lease.start_attempt()
    assert lease.attempt_active_seconds == 0.0


def test_repeated_expiry_without_a_branch_closes_the_lease() -> None:
    clock = [0.0]
    lease = ActiveTimeLease(
        profile=EnvironmentProfile.HTB,
        autonomy=AutonomyMode.FULL,
        lease_minutes=1,
        clock=lambda: clock[0],
    )
    clock[0] = 61.0
    assert lease.ensure_available(
        objectives_incomplete=True,
        branch_available=False,
        reason="no eligible branch",
        evidence="same failure",
    ) is None


def test_training_lease_renews_without_changing_contract() -> None:
    clock = [0.0]
    lease = ActiveTimeLease(
        profile=EnvironmentProfile.HTB,
        autonomy=AutonomyMode.FULL,
        lease_minutes=2,
        clock=lambda: clock[0],
    )

    clock[0] = 121.0
    renewal = lease.ensure_available(
        objectives_incomplete=True,
        branch_available=True,
        reason="validated web branch remains",
        evidence="observation-1",
    )

    assert isinstance(renewal, LeaseRenewal)
    assert renewal.previous_lease_minutes == 2
    assert renewal.new_lease_minutes == 32
    assert lease.historical_active_seconds == 121.0
    assert lease.current_lease_active_seconds == 0.0


def test_lease_renewal_denied_for_scope_or_policy_change() -> None:
    lease = ActiveTimeLease(
        profile=EnvironmentProfile.HTB,
        autonomy=AutonomyMode.FULL,
        lease_minutes=1,
        clock=lambda: 61.0,
    )

    assert lease.ensure_available(
        objectives_incomplete=True,
        branch_available=True,
        reason="scope amendment required",
        evidence="scope-candidate",
        policy_change=True,
    ) is None


def test_pause_is_excluded_from_active_time() -> None:
    clock = [0.0]
    lease = ActiveTimeLease(
        profile=EnvironmentProfile.HTB,
        autonomy=AutonomyMode.FULL,
        lease_minutes=10,
        clock=lambda: clock[0],
    )
    clock[0] = 10.0
    lease.pause("user confirmation")
    clock[0] = 100.0
    lease.resume()
    clock[0] = 110.0

    assert lease.historical_active_seconds == 20.0
    assert lease.wall_clock_seconds == 110.0


def test_lease_event_has_audit_fields() -> None:
    clock = [0.0]
    lease = ActiveTimeLease(
        profile=EnvironmentProfile.CTF,
        autonomy=AutonomyMode.FULL,
        lease_minutes=1,
        clock=lambda: clock[0],
    )
    clock[0] = 61.0
    renewal = lease.ensure_available(
        objectives_incomplete=True,
        branch_available=True,
        reason="new hypothesis",
        evidence="observation-2",
    )

    assert renewal is not None
    payload = renewal.event_payload()
    assert payload["event_type"] == "execution_lease_renewed"
    assert payload["motivation"] == "new hypothesis"
    assert payload["progress_evidence"] == "observation-2"
