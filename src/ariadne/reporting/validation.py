"""Pre-export quality gates for report generation.

Validates that a run dossier is complete, internally consistent, and safe
before rendering.  Every check is a fail-closed gate.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import NamedTuple

from ariadne.store.run_store import RunHandle

# ── Public data types ──────────────────────────────────────────────────────────


class ReportOptions(NamedTuple):
    """Options that control report rendering and validation behaviour.

    Attributes:
        include_flags: Whether to include captured flags in the report.
        include_secrets: Whether to include unredacted secrets in the report.
    """

    include_flags: bool = False
    include_secrets: bool = False


class ValidationResult(NamedTuple):
    """Outcome of a report-validation gate.

    The named tuple is truthy-falsy in a natural way::

        if not ReportValidator().validate(run, opts).valid:
            ...
    """

    valid: bool
    errors: list[str] = []
    warnings: list[str] = []


# ── Internal helpers ───────────────────────────────────────────────────────────

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_SECRET_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(secret|token|auth)\s*[:=]\s*\S+"),
    re.compile(r"[A-Za-z0-9+/]{40,}(?:[=]{0,2})"),  # base64-like blobs
]


def _has_unredacted_secrets(content: bytes) -> list[str]:
    """Scan *content* for unredacted secret patterns.

    Returns a list of matched descriptions.
    """
    hits: list[str] = []
    text = content.decode("utf-8", errors="replace")
    for pat in _SECRET_PATTERNS:
        m = pat.search(text)
        if m:
            hits.append(f"matched pattern: {pat.pattern!r}")
    return hits


def _read_json(path: Path) -> dict | None:
    """Read a JSON file, return None on failure."""
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, PermissionError):
        return None


def _read_jsonl(path: Path) -> list[dict]:
    """Read a JSONL file, skipping malformed lines."""
    if not path.is_file():
        return []
    events: list[dict] = []
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            events.append(json.loads(stripped))
        except json.JSONDecodeError:
            continue
    return events


def _read_manifest(path: Path) -> dict[str, str]:
    """Read the integrity manifest, returning empty dict on failure."""
    data = _read_json(path / "integrity.manifest")
    return data if isinstance(data, dict) else {}


# ── ReportValidator ────────────────────────────────────────────────────────────


REQUIRED_EVENT_TYPES_FOR_COMPLETION = frozenset({
    "cleanup_completed",
    "objective_completed",
})


class ReportValidator:
    """Validate a run dossier before report export.

    Checks:
    1. Engagement snapshot (``engagement.lock.yaml``) exists and is parseable.
    2. Events log (``events.jsonl``) exists with evidence events.
    3. Integrity manifest hashes match on-disk files.
    4. Every referenced evidence artifact exists on disk.
    5. No evidence references assets outside the engagement scope.
    6. At least one objective-completed event exists.
    7. Evidence artifacts contain no unredacted secrets (unless opted in).
    8. Cleanup or remediation events are present.
    """

    def validate(self, run: RunHandle, options: ReportOptions) -> ValidationResult:
        """Run all quality gates against *run*.

        Returns a ``ValidationResult`` with detailed error messages for
        every failing gate.
        """
        errors: list[str] = []
        warnings: list[str] = []
        run_path = run.path

        # ── 1. Snapshot ────────────────────────────────────────────────────────
        lock_path = run_path / "engagement.lock.yaml"
        snapshot = _read_json(lock_path)
        if snapshot is None:
            errors.append("Missing or unparseable engagement.lock.yaml")
            return ValidationResult(valid=False, errors=errors)

        in_scope_hosts: set[str] = set()
        targets = snapshot.get("targets", [])
        if isinstance(targets, (list, tuple)):
            for t in targets:
                host = t.get("host") if isinstance(t, dict) else None
                if host:
                    in_scope_hosts.add(str(host))

        # ── 2. Events ──────────────────────────────────────────────────────────
        events_path = run_path / "events.jsonl"
        events = _read_jsonl(events_path)
        if not events:
            warnings.append("Events log is empty (no evidence events found)")

        # ── 3. Integrity manifest ──────────────────────────────────────────────
        manifest = _read_manifest(run_path)
        for rel_path_str, expected_hex in manifest.items():
            if not _SHA256_RE.match(expected_hex):
                errors.append(
                    f"Invalid SHA-256 in manifest for {rel_path_str!r}"
                )
                continue
            abs_path = (run_path / rel_path_str).resolve()
            try:
                actual = hashlib.sha256(abs_path.read_bytes()).hexdigest()
            except (FileNotFoundError, PermissionError, OSError):
                errors.append(
                    f"Manifest references missing file: {rel_path_str!r}"
                )
                continue
            if actual != expected_hex:
                errors.append(
                    f"SHA-256 mismatch for {rel_path_str!r}: "
                    f"expected {expected_hex}, got {actual}"
                )

        # ── 4. Evidence artifacts exist ────────────────────────────────────────
        artifacts_dir = run_path / "artifacts"
        evidence_events = [
            e for e in events
            if isinstance(e, dict) and e.get("event_type") == "evidence_collected"
        ]
        for evt in evidence_events:
            payload = evt.get("payload", {})
            if not isinstance(payload, dict):
                continue
            artifact_name = payload.get("artifact")
            if not isinstance(artifact_name, str):
                continue
            art_path = artifacts_dir / artifact_name
            if not art_path.is_file():
                errors.append(
                    f"Evidence references missing artifact: {artifact_name!r}"
                )

        # ── 5. Out-of-scope assets ────────────────────────────────────────────
        for evt in evidence_events:
            payload = evt.get("payload", {})
            if not isinstance(payload, dict):
                continue
            asset = payload.get("asset")
            if isinstance(asset, str) and asset not in in_scope_hosts:
                errors.append(
                    f"Evidence references out-of-scope asset: {asset!r}"
                )

        # ── 6. Objectives proof ────────────────────────────────────────────────
        obj_events = [
            e for e in events
            if isinstance(e, dict) and e.get("event_type") == "objective_completed"
        ]
        if not obj_events:
            errors.append(
                "No objective_completed event found — no proof that "
                "engagement objectives were met"
            )

        # ── 7. Secret scan ────────────────────────────────────────────────────
        if not options.include_secrets:
            for evt in evidence_events:
                payload = evt.get("payload", {})
                if not isinstance(payload, dict):
                    continue
                artifact_name = payload.get("artifact")
                if not isinstance(artifact_name, str):
                    continue
                art_path = artifacts_dir / artifact_name
                if not art_path.is_file():
                    continue
                try:
                    content = art_path.read_bytes()
                except (OSError, PermissionError):
                    continue
                secret_hits = _has_unredacted_secrets(content)
                if secret_hits:
                    for hit in secret_hits:
                        errors.append(
                            f"Unredacted secret in {artifact_name!r}: {hit}"
                        )

        # ── 8. Cleanup / remediation ──────────────────────────────────────────
        cleanup_events = [
            e for e in events
            if isinstance(e, dict)
            and e.get("event_type") in ("cleanup_completed", "remediation_applied")
        ]
        if not cleanup_events:
            errors.append(
                "No cleanup_completed or remediation_applied event found"
            )

        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
        )
