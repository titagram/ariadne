"""Task 3: immutable engagement snapshot contract tests."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from ariadne.core.canonical import canonical_digest
from ariadne.core.engagement import (
    Confirmation,
    EngagementConstraints,
    EngagementDraft,
    Objective,
    TargetSpec,
    amend_engagement,
    amend_scope,
    calculate_snapshot_hash,
)
from ariadne.core.engagement import (
    lock_engagement as _lock_engagement,
)
from ariadne.core.enums import AutonomyMode, EnvironmentProfile
from ariadne.core.errors import ConfirmationError, ScopeError

POLICY_SOURCE_DIGESTS = ("a" * 64, "b" * 64, "c" * 64)


def lock_engagement(
    draft: EngagementDraft,
    confirmation: Confirmation,
    **kwargs: object,
):
    """Create a non-legacy snapshot in unit contracts by default."""
    kwargs.setdefault("policy_source_digests", POLICY_SOURCE_DIGESTS)
    return _lock_engagement(draft, confirmation, **kwargs)


@pytest.fixture
def confirmed_draft() -> EngagementDraft:
    """A valid draft ready for confirmation."""
    return EngagementDraft(
        authorization_attested=True,
        disclaimer_version="2026-07-27",
        profile=EnvironmentProfile.HTB,
        autonomy=AutonomyMode.CONTROLLED,
        target=TargetSpec(host="10.10.10.1"),
        objectives=[Objective(kind="user_flag", description="Obtain user flag")],
    )


@pytest.fixture
def confirmation(confirmed_draft: EngagementDraft) -> Confirmation:
    """A valid confirmation matching the fixture draft."""
    now = datetime.now(UTC)
    return Confirmation(
        challenge_id="challenge-001",
        challenge_digest=canonical_digest(confirmed_draft),
        confirmed_at=now,
        expires_at=now + timedelta(minutes=4),
        actor="user",
    )


# ── Immutability ────────────────────────────────────────────────────────────


def test_snapshot_is_frozen(confirmed_draft: EngagementDraft, confirmation: Confirmation) -> None:
    """Direct attribute mutation on a snapshot must raise ValidationError."""
    snap = lock_engagement(confirmed_draft, confirmation)
    with pytest.raises(ValidationError):
        snap.authorization_attested = False  # type: ignore[misc]


def test_public_snapshot_hash_recalculation_matches_locked_snapshot(
    confirmed_draft: EngagementDraft,
    confirmation: Confirmation,
) -> None:
    snapshot = lock_engagement(confirmed_draft, confirmation)
    assert calculate_snapshot_hash(snapshot) == snapshot.snapshot_hash


def test_public_snapshot_hash_recalculation_detects_tampered_content(
    confirmed_draft: EngagementDraft,
    confirmation: Confirmation,
) -> None:
    snapshot = lock_engagement(confirmed_draft, confirmation)
    tampered = snapshot.model_copy(
        update={"targets": (TargetSpec(host="10.10.10.99"),)}
    )
    assert calculate_snapshot_hash(tampered) != tampered.snapshot_hash


def test_snapshot_hash_covers_policy_source_digests(
    confirmed_draft: EngagementDraft,
    confirmation: Confirmation,
) -> None:
    """Changing frozen policy provenance must invalidate the self-hash."""
    snapshot = lock_engagement(
        confirmed_draft,
        confirmation,
        policy_source_digests=("a" * 64, "b" * 64, "c" * 64),
    )
    changed = snapshot.model_copy(
        update={"policy_source_digests": ("d" * 64,)},
    )

    assert snapshot.policy_source_digests == (
        "a" * 64,
        "b" * 64,
        "c" * 64,
    )
    assert calculate_snapshot_hash(changed) != snapshot.snapshot_hash


def test_attested_lock_rejects_empty_policy_provenance(
    confirmed_draft: EngagementDraft,
) -> None:
    """Operational engagement creation must never produce legacy provenance."""
    from ariadne.core.engagement import lock_attested_engagement

    with pytest.raises(ConfirmationError, match="(?i)policy provenance"):
        lock_attested_engagement(confirmed_draft)


def test_confirmed_lock_rejects_empty_policy_provenance(
    confirmed_draft: EngagementDraft,
    confirmation: Confirmation,
) -> None:
    with pytest.raises(ConfirmationError, match="(?i)policy provenance"):
        _lock_engagement(confirmed_draft, confirmation)


# ── Confirmation validation ─────────────────────────────────────────────────


def test_lock_rejects_digest_mismatch(
    confirmed_draft: EngagementDraft, confirmation: Confirmation
) -> None:
    """A confirmation whose challenge_digest does not match the draft must be rejected."""
    bad = Confirmation(
        challenge_id=confirmation.challenge_id,
        challenge_digest="0" * 64,
        confirmed_at=confirmation.confirmed_at,
        expires_at=confirmation.expires_at,
        actor=confirmation.actor,
    )
    with pytest.raises(ConfirmationError, match="digest mismatch"):
        lock_engagement(confirmed_draft, bad)


def test_lock_rejects_stale_confirmation_with_far_future_expiry(
    confirmed_draft: EngagementDraft, confirmation: Confirmation
) -> None:
    """A confirmation whose confirmed_at is older than 5 minutes must be
    rejected even when expires_at is far in the future."""
    stale = Confirmation(
        challenge_id=confirmation.challenge_id,
        challenge_digest=confirmation.challenge_digest,
        confirmed_at=datetime.now(UTC) - timedelta(minutes=10),
        expires_at=datetime.now(UTC) + timedelta(minutes=30),
        actor=confirmation.actor,
    )
    with pytest.raises(ConfirmationError, match="older than 5 minutes"):
        lock_engagement(confirmed_draft, stale)


def test_lock_rejects_expired_confirmation(
    confirmed_draft: EngagementDraft, confirmation: Confirmation
) -> None:
    """A confirmation whose expires_at is in the past must be rejected."""
    now = datetime.now(UTC)
    expired = Confirmation(
        challenge_id=confirmation.challenge_id,
        challenge_digest=confirmation.challenge_digest,
        confirmed_at=now - timedelta(minutes=3),
        expires_at=now - timedelta(minutes=1),
        actor=confirmation.actor,
    )
    with pytest.raises(ConfirmationError, match="expired"):
        lock_engagement(confirmed_draft, expired)


def test_lock_rejects_invalid_actor(
    confirmed_draft: EngagementDraft, confirmation: Confirmation
) -> None:
    """Only 'user' is a valid actor for v1 confirmations."""
    with pytest.raises(ValidationError):
        Confirmation(
            challenge_id=confirmation.challenge_id,
            challenge_digest=confirmation.challenge_digest,
            confirmed_at=confirmation.confirmed_at,
            expires_at=confirmation.expires_at,
            actor="model",  # type: ignore[arg-type]
        )


# ── Snapshot creation ───────────────────────────────────────────────────────


def test_lock_engagement_creates_first_snapshot(
    confirmed_draft: EngagementDraft, confirmation: Confirmation
) -> None:
    """First lock creates revision 1 with no previous hash."""
    snap = lock_engagement(confirmed_draft, confirmation)
    assert snap.revision == 1
    assert snap.previous_snapshot_hash is None
    assert snap.snapshot_hash is not None
    assert len(snap.snapshot_hash) == 64
    assert snap.snapshot_hash.islower()
    assert snap.snapshot_hash.isalnum()


def test_lock_engagement_copies_draft_fields(
    confirmed_draft: EngagementDraft, confirmation: Confirmation
) -> None:
    """The snapshot carries the draft's authorization, profile, autonomy, and disclaimer."""
    snap = lock_engagement(confirmed_draft, confirmation)
    assert snap.authorization_attested == confirmed_draft.authorization_attested
    assert snap.profile == confirmed_draft.profile
    assert snap.autonomy == confirmed_draft.autonomy
    assert snap.disclaimer_version == confirmed_draft.disclaimer_version


def test_lock_engagement_promotes_target_to_tuple(
    confirmed_draft: EngagementDraft, confirmation: Confirmation
) -> None:
    """The draft's single target becomes a singleton tuple on the snapshot."""
    snap = lock_engagement(confirmed_draft, confirmation)
    assert isinstance(snap.targets, tuple)
    assert len(snap.targets) == 1
    assert snap.targets[0].host == confirmed_draft.target.host


def test_lock_engagement_hash_excludes_previous_hash(
    confirmed_draft: EngagementDraft, confirmation: Confirmation
) -> None:
    """The snapshot_hash must be computed from all fields except itself."""
    snap = lock_engagement(confirmed_draft, confirmation)
    # Hash is a 64-char lowercase hex string
    assert len(snap.snapshot_hash) == 64
    assert snap.snapshot_hash.islower()
    assert all(c in "0123456789abcdef" for c in snap.snapshot_hash)


def test_lock_engagement_differs_for_different_drafts() -> None:
    """Different drafts produce different snapshot hashes."""
    draft_a = EngagementDraft(
        authorization_attested=True,
        disclaimer_version="2026-07-27",
        profile=EnvironmentProfile.HTB,
        autonomy=AutonomyMode.CONTROLLED,
        target=TargetSpec(host="10.10.10.1"),
        objectives=[Objective(kind="user_flag", description="Flag A")],
    )
    draft_b = EngagementDraft(
        authorization_attested=True,
        disclaimer_version="2026-07-27",
        profile=EnvironmentProfile.HTB,
        autonomy=AutonomyMode.CONTROLLED,
        target=TargetSpec(host="10.10.10.2"),
        objectives=[Objective(kind="user_flag", description="Flag B")],
    )
    now = datetime.now(UTC)
    conf_a = Confirmation(
        challenge_id="c1",
        challenge_digest=canonical_digest(draft_a),
        confirmed_at=now,
        expires_at=now + timedelta(minutes=4),
        actor="user",
    )
    conf_b = Confirmation(
        challenge_id="c2",
        challenge_digest=canonical_digest(draft_b),
        confirmed_at=now,
        expires_at=now + timedelta(minutes=4),
        actor="user",
    )
    snap_a = lock_engagement(draft_a, conf_a)
    snap_b = lock_engagement(draft_b, conf_b)
    assert snap_a.snapshot_hash != snap_b.snapshot_hash


def test_lock_engagement_sets_constraints(
    confirmed_draft: EngagementDraft, confirmation: Confirmation
) -> None:
    """The snapshot carries default EngagementConstraints."""
    snap = lock_engagement(confirmed_draft, confirmation)
    assert isinstance(snap.constraints, EngagementConstraints)
    assert snap.constraints.max_concurrent_checks >= 1


# ── Scope amendment ─────────────────────────────────────────────────────────


def test_scope_amendment_creates_new_linked_snapshot(
    confirmed_draft: EngagementDraft, confirmation: Confirmation
) -> None:
    """Amendment increments revision, references previous hash, and produces a new one."""
    first = lock_engagement(confirmed_draft, confirmation)
    second = amend_scope(
        first,
        targets=first.targets + (TargetSpec(host="10.10.10.20"),),
        confirmation=confirmation,
    )
    assert second.revision == first.revision + 1
    assert second.previous_snapshot_hash == first.snapshot_hash
    assert second.snapshot_hash != first.snapshot_hash


def test_contract_amendment_versions_intensity_and_exclusions(
    confirmed_draft: EngagementDraft,
    confirmation: Confirmation,
) -> None:
    first = lock_engagement(confirmed_draft, confirmation)
    second = amend_engagement(
        first,
        intensity="high",
        exclusions=("dos", " password spraying ", "dos"),
    )

    assert second.revision == first.revision + 1
    assert second.previous_snapshot_hash == first.snapshot_hash
    assert second.intensity == "high"
    assert second.exclusions == ("dos", "password spraying")
    assert first.intensity == "normal"
    assert first.exclusions == ()


def test_scope_amendment_preserves_original_fields(
    confirmed_draft: EngagementDraft, confirmation: Confirmation
) -> None:
    """Amendment keeps engagement_id and all original fields."""
    first = lock_engagement(confirmed_draft, confirmation)
    second = amend_scope(
        first,
        targets=first.targets + (TargetSpec(host="10.10.10.20"),),
        confirmation=confirmation,
    )
    assert second.engagement_id == first.engagement_id
    assert second.authorization_attested == first.authorization_attested
    assert second.profile == first.profile
    assert second.autonomy == first.autonomy
    assert second.disclaimer_version == first.disclaimer_version


def test_scope_amendment_adds_targets(
    confirmed_draft: EngagementDraft, confirmation: Confirmation
) -> None:
    """Amendment replaces the targets tuple."""
    first = lock_engagement(confirmed_draft, confirmation)
    new_target = TargetSpec(host="10.10.10.20")
    second = amend_scope(first, targets=(new_target,), confirmation=confirmation)
    assert len(second.targets) == 1
    assert second.targets[0].host == "10.10.10.20"


def test_amend_scope_rejects_empty_targets(
    confirmed_draft: EngagementDraft, confirmation: Confirmation
) -> None:
    """An empty targets tuple must raise ScopeError."""
    snap = lock_engagement(confirmed_draft, confirmation)
    with pytest.raises(ScopeError, match="requires at least one target"):
        amend_scope(snap, targets=(), confirmation=confirmation)


def test_amend_scope_rejects_expired_confirmation(
    confirmed_draft: EngagementDraft, confirmation: Confirmation
) -> None:
    """A confirmation whose expires_at is in the past must be rejected."""
    snap = lock_engagement(confirmed_draft, confirmation)
    now = datetime.now(UTC)
    expired = Confirmation(
        challenge_id=confirmation.challenge_id,
        challenge_digest=confirmation.challenge_digest,
        confirmed_at=now - timedelta(minutes=3),
        expires_at=now - timedelta(minutes=1),
        actor=confirmation.actor,
    )
    with pytest.raises(ConfirmationError, match="has expired"):
        amend_scope(snap, targets=snap.targets, confirmation=expired)


def test_amend_scope_rejects_stale_confirmation(
    confirmed_draft: EngagementDraft, confirmation: Confirmation
) -> None:
    """A confirmation whose confirmed_at is older than 5 minutes must be
    rejected even when expires_at is far in the future."""
    snap = lock_engagement(confirmed_draft, confirmation)
    stale = Confirmation(
        challenge_id=confirmation.challenge_id,
        challenge_digest=confirmation.challenge_digest,
        confirmed_at=datetime.now(UTC) - timedelta(minutes=10),
        expires_at=datetime.now(UTC) + timedelta(minutes=30),
        actor=confirmation.actor,
    )
    with pytest.raises(ConfirmationError, match="older than 5 minutes"):
        amend_scope(snap, targets=snap.targets, confirmation=stale)
