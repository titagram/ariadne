"""Tests for the run-store integrity verification."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from ariadne.core.canonical import canonical_digest
from ariadne.core.engagement import (
    Confirmation,
    EngagementDraft,
    EngagementSnapshot,
    Objective,
    TargetSpec,
)
from ariadne.core.enums import AutonomyMode, EnvironmentProfile
from ariadne.store.integrity import verify_run
from ariadne.store.run_store import ArtifactInput, Event, IntegrityResult, RunStore

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def snapshot() -> EngagementSnapshot:
    """A valid, locked engagement snapshot for testing."""
    draft = EngagementDraft(
        authorization_attested=True,
        disclaimer_version="2026-07-27",
        profile=EnvironmentProfile.HTB,
        autonomy=AutonomyMode.CONTROLLED,
        target=TargetSpec(host="10.10.10.10"),
        objectives=[Objective(kind="user_flag", description="Obtain user flag")],
    )
    confirmation = Confirmation(
        challenge_id="ch-1",
        challenge_digest=canonical_digest(draft),
        confirmed_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        actor="user",
    )
    from ariadne.core.engagement import lock_engagement

    return lock_engagement(draft, confirmation)


@pytest.fixture
def store(tmp_path: pytest.TempPathFactory) -> RunStore:
    """A RunStore rooted at a temporary directory."""
    return RunStore(base_path=tmp_path)


@pytest.fixture
def evidence() -> ArtifactInput:
    """An artifact input for testing."""
    return ArtifactInput(
        media_type="text/plain",
        evidence_type="terminal",
        source_name="test",
        maximum_bytes=1024 * 1024,
    )


# ── Integrity tests ───────────────────────────────────────────────────────────


def test_integrity_ok_for_intact_store(
    store: RunStore, snapshot: EngagementSnapshot, evidence: ArtifactInput
) -> None:
    """An untouched store with no tampering passes verification."""
    handle = store.create(snapshot)
    store.add_bytes(handle, b"original", evidence)
    # Append an event using the proper API
    store.append_event(
        handle,
        Event(
            event_type="artifact_stored",
            payload={"artifact_id": str(uuid4()), "size": 8},
            timestamp=datetime.now(UTC),
        ),
    )
    result = verify_run(handle.path)
    assert result.valid, f"Expected valid integrity, got errors: {result.errors}"


def test_integrity_ok_with_events_only(
    store: RunStore, snapshot: EngagementSnapshot,
) -> None:
    """A store with only events and no artifacts still passes."""
    handle = store.create(snapshot)
    store.append_event(
        handle,
        Event(
            event_type="test_event", payload={"key": "val"}, timestamp=datetime.now(UTC)
        ),
    )
    result = verify_run(handle.path)
    assert result.valid, f"Expected valid integrity, got errors: {result.errors}"


def test_integrity_detects_artifact_tampering(
    store: RunStore, snapshot: EngagementSnapshot, evidence: ArtifactInput
) -> None:
    """Changing an artifact file after storage is detected."""
    handle = store.create(snapshot)
    artifact = store.add_bytes(handle, b"original", evidence)
    # Tamper with the file
    artifact.path.write_bytes(b"changed")
    result = verify_run(handle.path)
    assert not result.valid


def test_integrity_detects_event_tampering(
    store: RunStore, snapshot: EngagementSnapshot, evidence: ArtifactInput
) -> None:
    """Changing an event's content in the JSONL file is detected."""
    handle = store.create(snapshot)
    store.add_bytes(handle, b"some data", evidence)
    # Append an event to create events.jsonl
    store.append_event(
        handle,
        Event(
            event_type="artifact_stored",
            payload={"size": 8},
            timestamp=datetime.now(UTC),
        ),
    )
    events_file = handle.path / "events.jsonl"
    lines = events_file.read_text().strip().split("\n")
    # Tamper with an existing event's payload
    import json
    tampered = json.loads(lines[-1])
    tampered["payload"]["tampered"] = True
    lines[-1] = json.dumps(tampered, separators=(",", ":"), ensure_ascii=False)
    events_file.write_text("\n".join(lines) + "\n")
    result = verify_run(handle.path)
    # Should fail because event hash no longer matches manifest or chain
    assert not result.valid, f"Expected invalid, got errors: {result.errors}"


def test_integrity_reports_errors_list(
    store: RunStore, snapshot: EngagementSnapshot,
) -> None:
    """A tampered store returns non-empty errors list."""
    handle = store.create(snapshot)
    # Create the lock file manually (just for the dir existence), then delete it
    lock_file = handle.path / "engagement.lock.yaml"
    lock_file.write_text("{}")
    result = verify_run(handle.path)
    assert not result.valid
    assert len(result.errors) > 0


# ── IntegrityResult model tests ───────────────────────────────────────────────


def test_integrity_result_defaults_to_valid() -> None:
    """IntegrityResult defaults to valid with no errors."""
    result = IntegrityResult()
    assert result.valid
    assert result.errors == []


def test_integrity_result_rejects_extra_fields() -> None:
    """IntegrityResult must forbid extra fields."""
    with pytest.raises(ValueError, match="extra_forbidden"):
        IntegrityResult(valid=True, extra_field="nope")  # type: ignore[call-arg]



