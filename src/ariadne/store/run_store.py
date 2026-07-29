"""Append-only run store for engagement artifacts and events.

Provides ``RunStore.create()``, ``append_event()``, and
``add_artifact()`` along with supporting domain models.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
from datetime import datetime
from pathlib import Path
from typing import BinaryIO
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict

from ariadne.core.engagement import EngagementSnapshot
from ariadne.store.jsonl import (
    append_event as _append_jsonl,
)
from ariadne.store.jsonl import (
    build_event,
    verify_chain,
)
from ariadne.store.jsonl import (
    read_all as _read_jsonl,
)
from ariadne.store.paths import safe_artifact_path, set_strict_permissions

# ── Domain models ─────────────────────────────────────────────────────────────


class Event(BaseModel):
    """A single engagement event to be recorded in the JSONL log.

    The ``event_hash`` chain linkage is added internally during storage.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_type: str
    payload: dict
    timestamp: datetime


class ArtifactInput(BaseModel):
    """Metadata describing an artifact to be stored."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    media_type: str
    evidence_type: str
    source_name: str
    maximum_bytes: int


class StoredArtifact(BaseModel):
    """Metadata about a stored artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_id: UUID
    path: Path
    size_bytes: int
    sha256: str


class RunHandle:
    """Opaque handle to an active engagement run directory.

    Attributes:
        engagement_id: The UUID of the locked engagement.
        path: Absolute path to the ``runs/<engagement-id>/`` directory.
        snapshot: The ``EngagementSnapshot`` that was used to create this run.
    """

    __slots__ = ("engagement_id", "path", "snapshot")

    def __init__(self, engagement_id: UUID, path: Path, snapshot: EngagementSnapshot) -> None:
        self.engagement_id = engagement_id
        self.path = path
        self.snapshot = snapshot


# ── Integrity result model ────────────────────────────────────────────────────


class IntegrityResult(BaseModel):
    """Outcome of a run-store integrity verification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    valid: bool = True
    errors: list[str] = []


# ── Integrity verification ────────────────────────────────────────────────────


def verify_events_integrity(path: Path) -> IntegrityResult:
    """Verify the JSONL events file at *path*.

    Checks sequence contiguity and the cryptographic hash chain.
    """
    valid, errors = verify_chain(path)
    return IntegrityResult(valid=valid, errors=errors)


# ── RunStore ──────────────────────────────────────────────────────────────────


class RunStore:
    """Append-only, permission-restricted store for engagement runs.

    Each engagement gets its own ``runs/<engagement-id>/`` directory with::

        engagement.lock.yaml   immutable snapshot (0o600)
        events.jsonl            hash-chained JSONL log (0o600)
        artifacts/              stored evidence files (0o600 each)

    All writes go through temp-file + fsync + ``os.replace``.
    """

    def __init__(self, base_path: Path | None = None) -> None:
        """Initialise with an optional root override (for testing).

        When *base_path* is ``None``, resolves paths via
        :func:`ariadne.store.paths.ariadne_home`.
        """
        self._base_path = base_path

    @property
    def base_path(self) -> Path | None:
        """Return the configured storage root override."""
        return self._base_path

    def _engagement_path(self, engagement_id: UUID) -> Path:
        """Resolve the run directory path, creating it with 0o700."""
        from ariadne.store.paths import run_dir

        path = run_dir(engagement_id, base=self._base_path)
        set_strict_permissions(path, 0o700)
        return path

    @staticmethod
    def _update_manifest(path: Path, filename: str, sha256_hex: str) -> None:
        """Record *filename* with its SHA-256 in the integrity manifest."""
        import json

        manifest_path = path / "integrity.manifest"
        manifest: dict[str, str] = {}
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text())
        manifest[filename] = sha256_hex
        # Atomic write
        import os
        import tempfile

        fd, tmp = tempfile.mkstemp(dir=str(path), prefix=".manifest_tmp_")
        try:
            os.write(fd, json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, manifest_path)
        set_strict_permissions(manifest_path, 0o600)

    def create(self, snapshot: EngagementSnapshot) -> RunHandle:
        """Create a new run directory for *snapshot*.

        Writes ``engagement.lock.yaml`` with the snapshot's canonical
        JSON representation.  Permissions are set to 0o700 for the
        directory and 0o600 for the lock file.
        """
        path = self._engagement_path(snapshot.engagement_id)
        lock_path = path / "engagement.lock.yaml"


        # We store the snapshot's canonical JSON (including the hash)
        import json

        lock_data = json.dumps(
            snapshot.model_dump(mode="json"),
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
        )

        # Atomic write through temp file
        import os
        import tempfile

        fd, tmp = tempfile.mkstemp(dir=str(path), prefix=".lock_tmp_")
        try:
            os.write(fd, lock_data.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

        os.replace(tmp, lock_path)
        set_strict_permissions(lock_path, 0o600)

        # Record the lock file in the integrity manifest
        import hashlib

        lock_digest = hashlib.sha256(lock_data.encode("utf-8")).hexdigest()
        self._update_manifest(path, "engagement.lock.yaml", lock_digest)

        return RunHandle(
            engagement_id=snapshot.engagement_id,
            path=path,
            snapshot=snapshot,
        )

    def append_event(self, handle: RunHandle, event: Event) -> None:
        """Append a hash-chained event to the run's JSONL log.

        The event is assigned an auto-incrementing sequence number and
        linked cryptographically to the previous event.
        """
        events_path = handle.path / "events.jsonl"

        # Determine next sequence and previous hash
        existing = _read_jsonl(events_path)
        next_seq = len(existing) + 1
        prev_hash = existing[-1].event_hash if existing else "0" * 64

        timestamp = event.timestamp.isoformat()
        payload = dict(event.payload)

        jsonl_event = build_event(
            sequence=next_seq,
            previous_event_hash=prev_hash,
            event_type=event.event_type,
            payload=payload,
            timestamp=timestamp,
        )

        _append_jsonl(events_path, jsonl_event)

        # Ensure restrictive permissions on the events file
        if events_path.exists():
            set_strict_permissions(events_path, 0o600)

        # Update integrity manifest for the events file
        import hashlib
        events_digest = hashlib.sha256(events_path.read_bytes()).hexdigest()
        self._update_manifest(handle.path, "events.jsonl", events_digest)

    def _write_artifact_atomically(
        self,
        path: Path,
        source: BinaryIO,
        max_bytes: int,
    ) -> tuple[int, str]:
        """Stream *source* to *path* through temp file with hashing.

        Returns ``(size_bytes, sha256_hex)``.

        Raises ``ValueError`` if the stream exceeds ``max_bytes``.
        """
        import os
        import tempfile

        dir_path = path.parent
        dir_path.mkdir(parents=True, exist_ok=True)
        set_strict_permissions(dir_path, 0o700)

        hasher = hashlib.sha256()
        total = 0
        chunk_size = 64 * 1024

        fd, tmp_path = tempfile.mkstemp(dir=str(dir_path), prefix=".artifact_tmp_")
        try:
            while True:
                chunk = source.read(chunk_size)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(
                        f"Artifact stream exceeds maximum_bytes ({max_bytes})"
                    )
                hasher.update(chunk)
                os.write(fd, chunk)
            os.fsync(fd)
        except BaseException:
            os.close(fd)
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)
            raise
        else:
            os.close(fd)

        os.replace(tmp_path, path)
        set_strict_permissions(path, 0o600)
        digest = hasher.hexdigest()
        # Store relative path from the run directory (parent of artifacts/)
        artifacts_dir = dir_path.parent
        relative = f"artifacts/{path.name}"
        self._update_manifest(artifacts_dir, relative, digest)
        return total, digest

    def add_artifact(
        self,
        handle: RunHandle,
        source: BinaryIO,
        metadata: ArtifactInput,
    ) -> StoredArtifact:
        """Stream *source* to the run directory as a stored artifact.

        The artifact is written atomically through a temp file, hashed
        during streaming, and permission-restricted to 0o600.

        Returns a ``StoredArtifact`` with the generated UUID, path,
        size, and SHA-256 digest.
        """
        artifact_id = uuid4()
        ext = "bin"
        if metadata.media_type == "text/plain":
            ext = "txt"
        elif metadata.media_type == "application/json":
            ext = "json"
        elif metadata.media_type == "image/png":
            ext = "png"
        elif metadata.media_type == "image/jpeg":
            ext = "jpg"

        path = safe_artifact_path(handle.path, artifact_id, ext)
        size_bytes, sha256 = self._write_artifact_atomically(path, source, metadata.maximum_bytes)

        return StoredArtifact(
            artifact_id=artifact_id,
            path=path,
            size_bytes=size_bytes,
            sha256=sha256,
        )

    def add_bytes(
        self,
        handle: RunHandle,
        data: bytes,
        metadata: ArtifactInput,
    ) -> StoredArtifact:
        """Convenience: add an in-memory byte string as an artifact."""
        return self.add_artifact(handle, io.BytesIO(data), metadata)

    def has_snapshot(self, engagement_id: UUID) -> bool:
        """Check whether a run directory exists for *engagement_id*."""
        path = self._engagement_path(engagement_id)
        lock = path / "engagement.lock.yaml"
        return lock.is_file()

    def iter_snapshots(self) -> tuple[EngagementSnapshot, ...]:
        """Load all immutable engagement snapshots without mutating storage."""
        import json

        from ariadne.store.paths import ariadne_home

        runs = ariadne_home(override=self._base_path) / "runs"
        if not runs.is_dir():
            return ()
        snapshots: list[EngagementSnapshot] = []
        for lock_path in sorted(runs.glob("*/engagement.lock.yaml")):
            try:
                snapshots.append(
                    EngagementSnapshot.model_validate(
                        json.loads(lock_path.read_text(encoding="utf-8"))
                    )
                )
            except (OSError, ValueError):
                continue
        return tuple(snapshots)

    def open(self, engagement_id: UUID) -> RunHandle | None:
        """Open an existing run without creating a replacement snapshot."""
        for snapshot in self.iter_snapshots():
            if snapshot.engagement_id == engagement_id:
                path = self._engagement_path(snapshot.engagement_id)
                if (path / "engagement.lock.yaml").is_file():
                    return RunHandle(snapshot.engagement_id, path, snapshot)
        return None

    def find_session_binding(self, session_id: str) -> dict[str, str] | None:
        """Recover the latest durable session binding from append-only events."""
        if not session_id:
            return None
        latest: dict[str, str] | None = None
        latest_timestamp = ""
        for snapshot in self.iter_snapshots():
            handle = self.open(snapshot.engagement_id)
            if handle is None:
                continue
            if not verify_events_integrity(handle.path / "events.jsonl").valid:
                continue
            for event in self.read_events(handle):
                payload = event.get("payload", {})
                if (
                    event.get("event_type") == "session_bound"
                    and payload.get("session_id") == session_id
                    and event.get("timestamp", "") >= latest_timestamp
                ):
                    latest_timestamp = event.get("timestamp", "")
                    latest = {
                        "session_id": session_id,
                        "engagement_id": str(snapshot.engagement_id),
                        "snapshot_hash": snapshot.snapshot_hash,
                    }
        return latest

    def read_events(self, handle: RunHandle) -> list[dict]:
        """Read all events from the run's JSONL log.

        Returns events in chronological order (oldest first) as raw dicts
        with keys: sequence, previous_event_hash, event_hash, event_type,
        payload, timestamp.

        Returns an empty list if the events file does not exist.
        """
        from ariadne.store.jsonl import read_all as _read_jsonl

        events_path = handle.path / "events.jsonl"
        if not events_path.is_file():
            return []
        return [evt.to_dict() for evt in _read_jsonl(events_path)]
