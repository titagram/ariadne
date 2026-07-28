"""Shared fixtures for reporting tests.

Provides ``load_run`` (constructs a RunHandle from a broken-fixture name)
and ``default_options`` (plain ReportOptions).
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from ariadne.core.engagement import (
    EngagementConstraints,
    EngagementSnapshot,
    Objective,
    TargetSpec,
)
from ariadne.core.enums import AutonomyMode, EnvironmentProfile
from ariadne.reporting.validation import ReportOptions
from ariadne.store.run_store import RunHandle

# ── Helpers ────────────────────────────────────────────────────────────────────


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fake_snapshot() -> EngagementSnapshot:
    """Return a minimal valid EngagementSnapshot."""
    return EngagementSnapshot(
        engagement_id=uuid4(),
        revision=1,
        previous_snapshot_hash=None,
        snapshot_hash="0" * 64,
        confirmed_at=datetime.now(UTC),
        authorization_attested=True,
        disclaimer_version="1.0",
        profile=EnvironmentProfile.PRIVATE_LAB,
        autonomy=AutonomyMode.CONTROLLED,
        targets=(TargetSpec(host="10.0.0.1"),),
        objectives=(Objective(kind="proof", description="Capture the root flag"),),
        constraints=EngagementConstraints(),
    )


def _write_lock(path: Path, snapshot: EngagementSnapshot) -> str:
    """Write engagement.lock.yaml and return its SHA-256."""
    path.mkdir(parents=True, exist_ok=True)
    data = json.dumps(snapshot.model_dump(mode="json"), sort_keys=True, indent=2)
    lock_path = path / "engagement.lock.yaml"
    lock_path.write_text(data)
    lock_path.chmod(0o600)
    return _sha256(data.encode("utf-8"))


def _write_events(path: Path, events: list[dict]) -> str:
    """Write events.jsonl and return its SHA-256."""
    lines = []
    for i, evt in enumerate(events):
        evt["sequence"] = i + 1
        evt["previous_event_hash"] = "0" * 64 if i == 0 else lines[-1]["event_hash"]
        evt["event_hash"] = _sha256(json.dumps(evt, sort_keys=True).encode("utf-8"))
        lines.append(evt)
    jsonl_text = "\n".join(json.dumps(e, sort_keys=True) for e in lines) + "\n"
    events_path = path / "events.jsonl"
    events_path.write_text(jsonl_text)
    events_path.chmod(0o600)
    return _sha256(jsonl_text.encode("utf-8"))


def _write_artifact(path: Path, name: str, content: bytes) -> tuple[Path, str]:
    """Write an artifact file; returns (path, sha256)."""
    artifacts_dir = path / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    full = artifacts_dir / name
    full.write_bytes(content)
    full.chmod(0o600)
    return full, _sha256(content)


def _write_manifest(path: Path, entries: dict[str, str]) -> None:
    """Write integrity.manifest."""
    manifest_path = path / "integrity.manifest"
    manifest_path.write_text(json.dumps(entries, sort_keys=True, indent=2))
    manifest_path.chmod(0o600)


# ── Run directory builders for each broken fixture ──────────────────────────────


_BUILDERS: dict[str, callable] = {}


def _builder(name: str):
    """Decorator to register a run-directory builder."""
    def wrapper(fn):
        _BUILDERS[name] = fn
        return fn
    return wrapper


@_builder("missing-snapshot")
def _build_missing_snapshot(path: Path) -> None:
    """No engagement.lock.yaml at all."""
    path.mkdir(parents=True, exist_ok=True)
    _write_events(path, [])
    _write_manifest(path, {})


@_builder("finding-without-evidence")
def _build_finding_without_evidence(path: Path) -> None:
    """Snapshot exists but no evidence-collected events."""
    snapshot = _fake_snapshot()
    lock_digest = _write_lock(path, snapshot)
    _write_events(path, [])
    _write_manifest(path, {
        "engagement.lock.yaml": lock_digest,
        "events.jsonl": _sha256(b""),
    })


@_builder("missing-image")
def _build_missing_image(path: Path) -> None:
    """A screenshot evidence event references an artifact that doesn't exist."""
    snapshot = _fake_snapshot()
    lock_digest = _write_lock(path, snapshot)
    events = [
        {
            "event_type": "evidence_collected",
            "payload": {
                "artifact": "screenshot_01.png",
                "finding": "Finding 1",
                "asset": "10.0.0.1",
            },
        },
    ]
    events_digest = _write_events(path, events)
    _write_manifest(path, {
        "engagement.lock.yaml": lock_digest,
        "events.jsonl": events_digest,
    })


@_builder("bad-hash")
def _build_bad_hash(path: Path) -> None:
    """Integrity manifest has a wrong SHA-256."""
    snapshot = _fake_snapshot()
    lock_digest = _write_lock(path, snapshot)
    events_digest = _write_events(path, [])
    _write_manifest(path, {
        "engagement.lock.yaml": lock_digest,
        "events.jsonl": events_digest,
        "artifacts/screenshot.png": (
            "0000000000000000000000000000000000000000000000000000000000000000"
        ),
    })


@_builder("out-of-scope-asset")
def _build_out_of_scope_asset(path: Path) -> None:
    """Evidence references an asset outside the snapshot scope."""
    snapshot = _fake_snapshot()  # targets: 10.0.0.1
    lock_digest = _write_lock(path, snapshot)
    evt = {
        "event_type": "evidence_collected",
        "payload": {
            "artifact": "scan.txt",
            "finding": "Out-of-scope scan",
            "asset": "10.0.99.99",
        },
    }
    events_digest = _write_events(path, [evt])
    art_path, art_digest = _write_artifact(path, "scan.txt", b"nmap scan data")
    _write_manifest(path, {
        "engagement.lock.yaml": lock_digest,
        "events.jsonl": events_digest,
        f"artifacts/{art_path.name}": art_digest,
    })


@_builder("objective-without-proof")
def _build_objective_without_proof(path: Path) -> None:
    """No objective_completed event exists."""
    snapshot = _fake_snapshot()
    lock_digest = _write_lock(path, snapshot)
    events_digest = _write_events(path, [])
    _write_manifest(path, {
        "engagement.lock.yaml": lock_digest,
        "events.jsonl": events_digest,
    })


@_builder("secret-leak")
def _build_secret_leak(path: Path) -> None:
    """Evidence artifact contains an unredacted secret pattern."""
    snapshot = _fake_snapshot()
    lock_digest = _write_lock(path, snapshot)
    evt = {
        "event_type": "evidence_collected",
        "payload": {
            "artifact": "config.txt",
            "finding": "Config dump",
            "asset": "10.0.0.1",
        },
    }
    events_digest = _write_events(path, [evt])
    art_path, art_digest = _write_artifact(
        path, "config.txt", b"password=super_secret_123\napi_key=ABCD-1234-EFGH\n",
    )
    _write_manifest(path, {
        "engagement.lock.yaml": lock_digest,
        "events.jsonl": events_digest,
        f"artifacts/{art_path.name}": art_digest,
    })


@_builder("missing-remediation")
def _build_missing_remediation(path: Path) -> None:
    """No cleanup or remediation events."""
    snapshot = _fake_snapshot()
    lock_digest = _write_lock(path, snapshot)
    evt = {
        "event_type": "finding_validated",
        "payload": {
            "finding_id": str(uuid4()),
            "title": "Open port 445",
        },
    }
    events_digest = _write_events(path, [evt])
    art_path, art_digest = _write_artifact(path, "scan.txt", b"SMB port found")
    _write_manifest(path, {
        "engagement.lock.yaml": lock_digest,
        "events.jsonl": events_digest,
        f"artifacts/{art_path.name}": art_digest,
    })


@_builder("valid")
def _build_valid(path: Path) -> None:
    """A fully valid run with snapshot, evidence, artifact, objective, and cleanup."""
    snapshot = _fake_snapshot()
    lock_digest = _write_lock(path, snapshot)
    evt_evidence = {
        "event_type": "evidence_collected",
        "payload": {
            "artifact": "nmap_result.txt",
            "finding": "Open port 80",
            "asset": "10.0.0.1",
        },
    }
    evt_validated = {
        "event_type": "finding_validated",
        "payload": {
            "finding_id": str(uuid4()),
            "title": "Open port 80",
        },
    }
    evt_objective = {
        "event_type": "objective_completed",
        "payload": {
            "objective_kind": "proof",
            "description": "Captured the root flag",
        },
    }
    evt_cleanup = {
        "event_type": "cleanup_completed",
        "payload": {
            "description": "Cleaned up all artifacts",
        },
    }
    events_digest = _write_events(
        path, [evt_evidence, evt_validated, evt_objective, evt_cleanup],
    )
    art_path, art_digest = _write_artifact(path, "nmap_result.txt", b"80/tcp open http")
    _write_manifest(path, {
        "engagement.lock.yaml": lock_digest,
        "events.jsonl": events_digest,
        f"artifacts/{art_path.name}": art_digest,
    })


# ── Pytest fixtures ────────────────────────────────────────────────────────────


@pytest.fixture
def default_options() -> ReportOptions:
    """Return default report options (no flags, no secrets)."""
    return ReportOptions()


@pytest.fixture
def load_run(tmp_path: Path):
    """Return a callable that builds a run directory for a named fixture."""

    def _load(name: str) -> RunHandle:
        dest = tmp_path / f"run-{name}"
        if name in _BUILDERS:
            _BUILDERS[name](dest)
        else:
            msg = f"Unknown run fixture: {name!r}"
            raise ValueError(msg)
        return RunHandle(
            engagement_id=uuid4(),
            path=dest,
            snapshot=_fake_snapshot(),
        )

    return _load


@pytest.fixture
def valid_run(load_run) -> RunHandle:
    """Return a fully valid run handle."""
    return load_run("valid")
