"""Build the canonical report model from persisted run facts.

The builder deliberately has no scanner, network, or inference dependency.
Snapshot fields, hash-chained events, and real files under ``artifacts/`` are
the only accepted inputs.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ariadne.evidence.redaction import RedactionService
from ariadne.reporting.models import (
    ReportEvidence,
    ReportFinding,
    ReportLifecycleEntry,
    ReportModel,
    ReportObjective,
    ReportTarget,
)
from ariadne.reporting.validation import ReportOptions
from ariadne.store.run_store import RunHandle

_SEVERITIES = ("critical", "high", "medium", "low", "informational")
_FLAG_RE = re.compile(r"\b(?:HTB|FLAG|CTF)\{[^}]*\}")
_ACTIVITY_EVENT_TYPES = frozenset({
    "discovery_completed",
    "enumeration_completed",
    "hypothesis_created",
    "hypothesis_discarded",
    "alternative_discarded",
    "finding_validated",
    "initial_access",
    "access_validated",
    "host_compromised",
    "post_exploitation",
    "privilege_escalation",
    "ad_enumeration",
    "pivot_completed",
    "plan_executed",
    "objective_completed",
    "cleanup_completed",
    "remediation_applied",
})


def _read_events(path: Path) -> list[dict[str, Any]]:
    """Read well-formed JSON object events, preserving their stored order."""
    events_path = path / "events.jsonl"
    if not events_path.is_file():
        return []

    events: list[dict[str, Any]] = []
    for line in events_path.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def _string(payload: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _strings(value: object) -> tuple[str, ...]:
    if isinstance(value, str) and value.strip():
        return (value.strip(),)
    if isinstance(value, (list, tuple)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    return ()


class DossierBuilder:
    """Construct one factual, renderer-independent :class:`ReportModel`."""

    def __init__(self, redactor: RedactionService | None = None) -> None:
        self._redactor = redactor or RedactionService()

    def build(
        self,
        run: RunHandle,
        options: ReportOptions | None = None,
    ) -> ReportModel:
        """Build a report dossier without synthesising absent facts."""
        resolved_options = options or ReportOptions()
        events = _read_events(run.path)
        evidence = self._build_evidence(run.path, events, resolved_options)
        findings = self._build_findings(events, evidence, resolved_options)

        return ReportModel(
            engagement_id=str(run.snapshot.engagement_id),
            snapshot_hash=run.snapshot.snapshot_hash,
            generated_at=self._generated_at(run, events),
            authorization_attested=run.snapshot.authorization_attested,
            profile=run.snapshot.profile.value,
            autonomy=run.snapshot.autonomy.value,
            targets=tuple(ReportTarget(host=target.host) for target in run.snapshot.targets),
            objectives=self._build_objectives(run, events, resolved_options),
            evidence=evidence,
            findings=findings,
            lifecycle=self._build_lifecycle(events, resolved_options),
            cleanup=self._event_texts(
                events,
                {"cleanup_completed"},
                ("description", "summary"),
                resolved_options,
            ),
            remediation=self._event_texts(
                events,
                {"remediation_applied"},
                ("remediation", "description", "summary"),
                resolved_options,
            ),
            compromised=self._event_texts(
                events,
                {"initial_access", "access_validated", "host_compromised"},
                ("description", "summary", "target", "asset", "user"),
                resolved_options,
            ),
            lessons=self._event_texts(
                events,
                {"lesson_learned"},
                ("lesson", "description", "summary"),
                resolved_options,
            ),
            commands=self._commands(events, resolved_options),
            risk_counts=self._risk_counts(findings),
        )

    def _sanitize(self, value: str | None, options: ReportOptions) -> str:
        if not value:
            return ""
        if options.include_secrets and options.include_flags:
            return value
        if options.include_secrets:
            return value if options.include_flags else _FLAG_RE.sub("[REDACTED]", value)
        if not options.include_flags:
            return self._redactor.redact(value).text

        protected: list[str] = []

        def protect(match: re.Match[str]) -> str:
            protected.append(match.group(0))
            return f"ARIADNE_FLAG_PLACEHOLDER_{len(protected) - 1}"

        redacted = self._redactor.redact(_FLAG_RE.sub(protect, value)).text
        for index, flag in enumerate(protected):
            redacted = redacted.replace(f"ARIADNE_FLAG_PLACEHOLDER_{index}", flag)
        return redacted

    def _build_evidence(
        self,
        run_path: Path,
        events: Iterable[dict[str, Any]],
        options: ReportOptions,
    ) -> tuple[ReportEvidence, ...]:
        artifacts_root = (run_path / "artifacts").resolve()
        collected: list[ReportEvidence] = []
        for event in events:
            if event.get("event_type") != "evidence_collected":
                continue
            payload = event.get("payload")
            if not isinstance(payload, dict):
                continue
            artifact = payload.get("artifact")
            if not isinstance(artifact, str) or not artifact.strip():
                continue
            artifact_path = (artifacts_root / artifact).resolve()
            if (
                not artifact_path.is_relative_to(artifacts_root)
                or not artifact_path.is_file()
            ):
                continue
            content = artifact_path.read_bytes()
            collected.append(
                ReportEvidence(
                    filename=artifact,
                    path=artifact_path,
                    sha256=hashlib.sha256(content).hexdigest(),
                    size_bytes=len(content),
                    finding=self._optional_sanitized(payload, "finding", options),
                    asset=self._optional_sanitized(payload, "asset", options),
                    evidence_type=self._optional_sanitized(
                        payload, "evidence_type", options,
                    ),
                    finding_id=self._optional_sanitized(payload, "finding_id", options),
                ),
            )
        return tuple(collected)

    def _build_findings(
        self,
        events: Iterable[dict[str, Any]],
        evidence: tuple[ReportEvidence, ...],
        options: ReportOptions,
    ) -> tuple[ReportFinding, ...]:
        findings: list[ReportFinding] = []
        for event in events:
            event_type = event.get("event_type")
            if event_type not in {"finding_candidate", "finding_validated"}:
                continue
            payload = event.get("payload")
            if not isinstance(payload, dict):
                continue
            title = self._sanitize(_string(payload, "title", "finding"), options)
            if not title:
                continue
            finding_id = self._optional_sanitized(payload, "finding_id", options)
            related = tuple(
                item for item in evidence
                if (
                    finding_id
                    and item.finding_id == finding_id
                    or item.finding == title
                )
            )
            severity_raw = _string(payload, "severity")
            severity = severity_raw.lower() if severity_raw else None
            target = self._optional_sanitized(payload, "target", options)
            if target is None and related:
                target = related[0].asset
            description = self._optional_sanitized(payload, "description", options)
            if description is None and related:
                description = related[0].finding
            remediation = tuple(
                self._sanitize(item, options)
                for item in _strings(payload.get("remediation"))
            )
            findings.append(
                ReportFinding(
                    finding_id=finding_id,
                    title=title,
                    severity=severity,
                    status=(
                        "validated"
                        if event_type == "finding_validated"
                        else "candidate"
                    ),
                    target=target,
                    description=description,
                    evidence=tuple(item.filename for item in related),
                    remediation=remediation,
                ),
            )
        return tuple(findings)

    def _build_objectives(
        self,
        run: RunHandle,
        events: list[dict[str, Any]],
        options: ReportOptions,
    ) -> tuple[ReportObjective, ...]:
        completions: list[dict[str, Any]] = []
        for event in events:
            if event.get("event_type") == "objective_completed":
                payload = event.get("payload")
                completions.append(payload if isinstance(payload, dict) else {})

        objectives: list[ReportObjective] = []
        for objective in run.snapshot.objectives:
            matching = [
                payload for payload in completions
                if payload.get("objective_kind") == objective.kind
                or (
                    objective.description
                    and payload.get("description") == objective.description
                )
            ]
            if not matching and len(run.snapshot.objectives) == 1 and completions:
                matching = [completions[0]]
            proof = _string(matching[0], "description", "proof", "result") if matching else None
            objectives.append(
                ReportObjective(
                    kind=objective.kind,
                    description=self._sanitize(objective.description, options),
                    completed=bool(matching),
                    completion_evidence=self._sanitize(proof, options) or None,
                ),
            )
        return tuple(objectives)

    def _build_lifecycle(
        self,
        events: Iterable[dict[str, Any]],
        options: ReportOptions,
    ) -> tuple[ReportLifecycleEntry, ...]:
        entries: list[ReportLifecycleEntry] = []
        for event in events:
            event_type = event.get("event_type")
            payload = event.get("payload")
            if event_type not in _ACTIVITY_EVENT_TYPES or not isinstance(payload, dict):
                continue
            summary = _string(payload, "summary", "description", "finding", "title")
            if summary is None and event_type == "plan_executed":
                action = _string(payload, "action")
                operation = _string(payload, "operation")
                summary = ":".join(item for item in (action, operation) if item)
            sanitized = self._sanitize(summary, options)
            if not sanitized:
                continue
            timestamp = event.get("timestamp")
            entries.append(
                ReportLifecycleEntry(
                    event_type=str(event_type),
                    summary=sanitized,
                    timestamp=str(timestamp) if timestamp else None,
                    target=self._optional_sanitized(payload, "target", options),
                    status=self._optional_sanitized(payload, "status", options),
                ),
            )
        return tuple(entries)

    def _event_texts(
        self,
        events: Iterable[dict[str, Any]],
        event_types: set[str],
        keys: tuple[str, ...],
        options: ReportOptions,
    ) -> tuple[str, ...]:
        values: list[str] = []
        for event in events:
            if event.get("event_type") not in event_types:
                continue
            payload = event.get("payload")
            if not isinstance(payload, dict):
                continue
            value = self._sanitize(_string(payload, *keys), options)
            if value and value not in values:
                values.append(value)
        return tuple(values)

    def _commands(
        self,
        events: Iterable[dict[str, Any]],
        options: ReportOptions,
    ) -> tuple[str, ...]:
        commands: list[str] = []
        for event in events:
            payload = event.get("payload")
            if not isinstance(payload, dict):
                continue
            raw_command = payload.get("command_redacted")
            if isinstance(raw_command, (list, tuple)):
                command_value = shlex.join(str(part) for part in raw_command)
            else:
                command_value = _string(payload, "command")
            command = self._sanitize(command_value, options)
            if command and command not in commands:
                commands.append(command)
        return tuple(commands)

    @staticmethod
    def _risk_counts(findings: tuple[ReportFinding, ...]) -> dict[str, int]:
        counts = dict.fromkeys(_SEVERITIES, 0)
        for finding in findings:
            if finding.status == "validated" and finding.severity in counts:
                counts[finding.severity] += 1
        return counts

    @staticmethod
    def _generated_at(run: RunHandle, events: list[dict[str, Any]]) -> str:
        for event in reversed(events):
            timestamp = event.get("timestamp")
            if isinstance(timestamp, str) and timestamp:
                return timestamp
        return run.snapshot.confirmed_at.isoformat()

    def _optional_sanitized(
        self,
        payload: dict[str, Any],
        key: str,
        options: ReportOptions,
    ) -> str | None:
        value = self._sanitize(_string(payload, key), options)
        return value or None
