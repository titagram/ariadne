"""Integrity manifest generation and verification for run directories.

``verify_run()`` reads the ``integrity.manifest`` file written by
``RunStore`` and checks that every recorded file still has the same
SHA-256 digest, detecting tampering.

It also verifies the hash-chain integrity of ``events.jsonl``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ariadne.store.run_store import IntegrityResult, verify_events_integrity


def verify_run(path: Path) -> IntegrityResult:
    """Verify the integrity of a run directory.

    Checks:
    1. The ``integrity.manifest`` file exists and is valid JSON.
    2. Every file listed in the manifest has the same SHA-256 digest.
    3. The ``events.jsonl`` hash-chain is intact.

    Returns an ``IntegrityResult``.
    """
    errors: list[str] = []

    manifest_path = path / "integrity.manifest"
    if not manifest_path.is_file():
        return IntegrityResult(valid=False, errors=["integrity.manifest not found"])

    try:
        manifest: dict[str, str] = json.loads(manifest_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        return IntegrityResult(
            valid=False, errors=[f"integrity.manifest is corrupt: {exc}"]
        )

    if not manifest:
        return IntegrityResult(valid=False, errors=["integrity.manifest is empty"])

    # Check each file listed in the manifest
    for relative_path, expected_digest in manifest.items():
        full_path = path / relative_path
        if not full_path.is_file():
            errors.append(f"Missing file: {relative_path}")
            continue
        try:
            actual_digest = hashlib.sha256(full_path.read_bytes()).hexdigest()
        except OSError as exc:
            errors.append(f"Cannot read {relative_path}: {exc}")
            continue

        if actual_digest != expected_digest:
            errors.append(
                f"SHA-256 mismatch for {relative_path}: "
                f"expected {expected_digest}, got {actual_digest}"
            )

    # Check for any untracked files in the artifacts directory
    artifacts_dir = path / "artifacts"
    if artifacts_dir.is_dir():
        for artifact_file in sorted(artifacts_dir.iterdir()):
            if artifact_file.is_file():
                relative_path = f"artifacts/{artifact_file.name}"
                if relative_path not in manifest:
                    errors.append(f"Untracked artifact file: {artifact_file.name}")

    # Also check for untracked top-level files
    for child in sorted(path.iterdir()):
        if child.is_file() and child.name not in manifest and child.name != "integrity.manifest":
            errors.append(f"Untracked file: {child.name}")

    # If events.jsonl is in the manifest, also verify its hash chain
    events_path = path / "events.jsonl"
    if events_path.is_file():
        events_result = verify_events_integrity(events_path)
        if not events_result.valid:
            errors.extend(events_result.errors)

    if errors:
        return IntegrityResult(valid=False, errors=errors)

    return IntegrityResult(valid=True, errors=[])
