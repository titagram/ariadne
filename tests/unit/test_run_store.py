"""Tests for the append-only run store."""

from __future__ import annotations

import json
import stat
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from ariadne.core.engagement import (
    Confirmation,
    EngagementDraft,
    EngagementSnapshot,
    Objective,
    TargetSpec,
)
from ariadne.core.enums import AutonomyMode, EnvironmentProfile
from ariadne.store.run_store import ArtifactInput, Event, RunStore

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
        challenge_digest="",  # overridden below
        confirmed_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        actor="user",
    )
    # Hydrate the digest after construction
    from ariadne.core.canonical import canonical_digest

    confirmation = confirmation.model_copy(
        update={"challenge_digest": canonical_digest(draft)}
    )
    from ariadne.core.engagement import lock_engagement

    return lock_engagement(draft, confirmation)


@pytest.fixture
def store(tmp_path: pytest.TempPathFactory) -> RunStore:
    """A RunStore rooted at a temporary directory."""
    return RunStore(base_path=tmp_path)


@pytest.fixture
def event() -> Event:
    """A basic event fixture."""
    return Event(
        event_type="snapshot_locked",
        payload={"engagement_id": str(uuid4()), "revision": 1},
        timestamp=datetime.now(UTC),
    )


@pytest.fixture
def evidence() -> ArtifactInput:
    """An artifact input for testing."""
    return ArtifactInput(
        media_type="text/plain",
        evidence_type="terminal",
        source_name="test",
        maximum_bytes=1024 * 1024,
    )


# ── Permission tests ──────────────────────────────────────────────────────────


def test_store_uses_restrictive_permissions(store: RunStore, snapshot: EngagementSnapshot) -> None:
    """The run directory must be 0o700 and the lock file 0o600."""
    handle = store.create(snapshot)
    assert stat.S_IMODE(handle.path.stat().st_mode) == 0o700
    lock_file = handle.path / "engagement.lock.yaml"
    assert lock_file.is_file()
    assert stat.S_IMODE(lock_file.stat().st_mode) == 0o600


def test_store_stores_snapshot_as_readable_lock_yaml(
    store: RunStore, snapshot: EngagementSnapshot
) -> None:
    """The lock file should contain valid JSON-serialised snapshot metadata."""
    handle = store.create(snapshot)
    lock_file = handle.path / "engagement.lock.yaml"
    raw = lock_file.read_text()
    assert "engagement_id" in raw
    assert str(snapshot.engagement_id) in raw


# ── Event / JSONL tests ───────────────────────────────────────────────────────


def test_append_event_writes_jsonl_line(
    store: RunStore, snapshot: EngagementSnapshot, event: Event,
) -> None:
    """Appending an event creates the JSONL file with one line."""
    handle = store.create(snapshot)
    store.append_event(handle, event)
    events_file = handle.path / "events.jsonl"
    assert events_file.is_file()
    lines = events_file.read_text().strip().split("\n")
    assert len(lines) == 1


def test_jsonl_sequence_numbering(
    store: RunStore, snapshot: EngagementSnapshot, event: Event,
) -> None:
    """Events get sequential sequence numbers."""
    handle = store.create(snapshot)
    store.append_event(handle, event)
    store.append_event(handle, event)
    store.append_event(handle, event)
    events_file = handle.path / "events.jsonl"
    lines = events_file.read_text().strip().split("\n")
    for i, line in enumerate(lines, start=1):
        parsed = json.loads(line)
        assert parsed["sequence"] == i


def test_jsonl_hash_chain(store: RunStore, snapshot: EngagementSnapshot, event: Event) -> None:
    """Each event chains cryptographically to the previous one."""
    handle = store.create(snapshot)
    store.append_event(handle, event)
    store.append_event(handle, event)
    events_file = handle.path / "events.jsonl"
    lines = events_file.read_text().strip().split("\n")
    first = json.loads(lines[0])
    second = json.loads(lines[1])
    # First event's previous_event_hash must be all zeros
    assert first["previous_event_hash"] == "0" * 64
    assert first["event_hash"] != ""
    # Second event chains from first
    assert second["previous_event_hash"] == first["event_hash"]
    assert second["event_hash"] != first["event_hash"]


def test_jsonl_rejects_sequence_gap(
    store: RunStore, snapshot: EngagementSnapshot, event: Event,
) -> None:
    """Manually creating a sequence gap is rejected on read."""
    handle = store.create(snapshot)
    store.append_event(handle, event)
    # Append a second event, then manually insert a gap
    store.append_event(handle, event)
    events_file = handle.path / "events.jsonl"
    lines = events_file.read_text().strip().split("\n")
    # Manually edit the second event to have sequence=5 (gap)
    second = json.loads(lines[1])
    second["sequence"] = 5
    events_file.write_text(lines[0] + "\n" + json.dumps(second) + "\n")
    # Reading back via the store should detect the gap
    from ariadne.store.run_store import verify_events_integrity

    result = verify_events_integrity(events_file)
    assert not result.valid
    assert any("gap" in e.lower() for e in result.errors)


def test_jsonl_rejects_hash_mismatch(
    store: RunStore, snapshot: EngagementSnapshot, event: Event,
) -> None:
    """Tampering with event content breaks the hash chain."""
    handle = store.create(snapshot)
    store.append_event(handle, event)
    store.append_event(handle, event)
    events_file = handle.path / "events.jsonl"
    lines = events_file.read_text().strip().split("\n")
    # Tamper with the second event
    second = json.loads(lines[1])
    second["payload"]["tampered"] = True
    events_file.write_text(lines[0] + "\n" + json.dumps(second) + "\n")
    from ariadne.store.run_store import verify_events_integrity

    result = verify_events_integrity(events_file)
    assert not result.valid
    assert any("hash" in e.lower() for e in result.errors)


# ── Artifact tests ────────────────────────────────────────────────────────────


def test_add_artifact_stores_bytes_and_hashes(
    store: RunStore, snapshot: EngagementSnapshot, evidence: ArtifactInput
) -> None:
    """Adding an artifact stores the bytes and returns metadata."""
    handle = store.create(snapshot)
    artifact = store.add_bytes(handle, b"hello world", evidence)
    assert artifact.artifact_id is not None
    assert artifact.size_bytes == 11
    assert len(artifact.sha256) == 64  # hex digest
    assert artifact.path.is_file()
    assert artifact.path.read_bytes() == b"hello world"


def test_add_artifact_respects_permissions(
    store: RunStore, snapshot: EngagementSnapshot, evidence: ArtifactInput
) -> None:
    """Artifact files must be 0o600."""
    handle = store.create(snapshot)
    artifact = store.add_bytes(handle, b"data", evidence)
    assert stat.S_IMODE(artifact.path.stat().st_mode) == 0o600


def test_add_artifact_rejects_oversized(
    store: RunStore, snapshot: EngagementSnapshot, evidence: ArtifactInput
) -> None:
    """Adding an artifact exceeding maximum_bytes must raise."""
    handle = store.create(snapshot)
    small = evidence.model_copy(update={"maximum_bytes": 5})
    with pytest.raises(ValueError, match="exceeds maximum"):
        store.add_bytes(handle, b"hello world", small)


# ── RunHandle tests ───────────────────────────────────────────────────────────


def test_create_returns_handle_with_correct_path(
    store: RunStore, snapshot: EngagementSnapshot
) -> None:
    """RunHandle.path points to the engagement run directory."""
    handle = store.create(snapshot)
    assert handle.engagement_id == snapshot.engagement_id
    assert handle.path.is_dir()
    assert snapshot.engagement_id.hex in str(handle.path)


def test_create_creates_run_directory(store: RunStore, snapshot: EngagementSnapshot) -> None:
    """The run directory must exist immediately after create()."""
    handle = store.create(snapshot)
    assert handle.path.is_dir()
    assert handle.path.stat().st_mode & 0o700


# ── Event model tests ─────────────────────────────────────────────────────────


def test_event_model_rejects_extra_fields() -> None:
    """Event must forbid extra fields."""
    with pytest.raises(ValueError, match="extra_forbidden"):
        Event(
            event_type="test",
            payload={"key": "val"},
            timestamp=datetime.now(UTC),
            extra_field="nope",  # type: ignore[call-arg]
        )


def test_artifact_input_rejects_extra_fields() -> None:
    """ArtifactInput must forbid extra fields."""
    with pytest.raises(ValueError, match="extra_forbidden"):
        ArtifactInput(
            media_type="text/plain",
            evidence_type="terminal",
            source_name="test",
            maximum_bytes=100,
            extra_field="nope",  # type: ignore[call-arg]
        )


# ── Test summary marker ───────────────────────────────────────────────────────
# Run with: uv run pytest tests/unit/test_run_store.py -v
