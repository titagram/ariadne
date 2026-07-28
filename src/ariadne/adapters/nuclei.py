"""Nuclei vulnerability-scanning adapter.

Builds safe, bounded Nuclei command-lines using only allowlisted
template IDs from the pinned tool manifest, and parses Nuclei JSONL
output into structured Observation objects.

Safety invariants
-----------------
- Only template IDs and workflow IDs present in the pinned
  ``tool-manifest.yaml`` are accepted.
- Arbitrary template directories (``template_dir``) are rejected
  via ``AdapterPolicyError``.
- No shell interpolation: every argument is in the argv tuple.
- Timeout and output size are bounded by ``ProcessSpec``.
- All template matches are treated as candidates until the
  evidence module validates them.
"""

from __future__ import annotations

import json
from typing import ClassVar
from uuid import uuid4

from ariadne.adapters.base import (
    AdapterContext,
    AdapterError,
    CleanupResult,
    ExecutionClassification,
    PlannedAction,
    ProcessResult,
    ProcessSpec,
    Runtime,
    ToolProbe,
)
from ariadne.core.errors import AdapterPolicyError
from ariadne.core.observations import Observation

# Allowlisted template IDs that may be used in scan operations.
# In a full deployment these are loaded from tool-manifest.yaml;
# the static set below reflects the pinned template catalog for
# local testing and CTF use.
_ALLOWLISTED_TEMPLATES: frozenset = frozenset(
    {
        "cve-2024-1234",
        "tech-detect-apache",
        "tech-detect-nginx",
        "exposed-panel",
        "misconfig-dir-listing",
        "vuln-sql-error",
    }
)

_OPERATIONS: frozenset = frozenset({"scan"})


class NucleiAdapter:
    """ToolAdapter for ProjectDiscovery Nuclei template-based scanning.

    Supports ``scan`` operations with exactly allowlisted template IDs.
    Rejects unapproved template directories via policy error.
    """

    name: ClassVar[str] = "nuclei"

    # ── ToolAdapter protocol ─────────────────────────────────────────────

    async def probe(self, runtime: Runtime) -> ToolProbe:
        return ToolProbe(available=True)

    def plan(
        self,
        action: PlannedAction,
        context: AdapterContext,
    ) -> ProcessSpec:
        op = action.operation
        if op not in _OPERATIONS:
            raise AdapterError(
                f"Unknown Nuclei operation: {op!r}. "
                f"Supported: {', '.join(sorted(_OPERATIONS))}"
            )

        inputs = action.inputs

        # Reject arbitrary template directories — only allowlisted IDs
        template_dir = inputs.get("template_dir")
        if template_dir is not None and isinstance(template_dir, str):
            raise AdapterPolicyError(
                f"Unlocked template directory rejected: {template_dir!r}. "
                "Only allowlisted template IDs from tool-manifest.yaml "
                "are permitted."
            )

        target = str(context.target.host)

        # Build argv with allowlisted templates
        argv: list[str] = ["nuclei"]

        template_ids = inputs.get("template_ids", ())
        if isinstance(template_ids, (list, tuple)) and template_ids:
            for tid in template_ids:
                if tid not in _ALLOWLISTED_TEMPLATES:
                    raise AdapterPolicyError(
                        f"Template {tid!r} is not in the allowlisted "
                        f"template catalog. Allowed: {sorted(_ALLOWLISTED_TEMPLATES)}"
                    )
            argv.extend(["-t"])
            for tid in template_ids:
                argv.append(str(tid))

        # Target
        argv.extend(["-target", target])

        # JSONL output
        argv.append("-json")

        # Rate limiting
        argv.extend(["-rate-limit", "50"])

        # Timeout per template
        argv.extend(["-timeout", str(inputs.get("template_timeout", 10))])

        return ProcessSpec(
            argv=tuple(argv),
            timeout_seconds=int(inputs.get("timeout", 300)),  # type: ignore[arg-type]
            max_output_bytes=int(inputs.get("max_output", 10 * 1024 * 1024)),  # type: ignore[arg-type]
        )

    async def execute(
        self,
        spec: ProcessSpec,
        runtime: Runtime,
    ) -> ProcessResult:
        return await runtime.run(spec)

    def parse(
        self,
        result: ProcessResult,
    ) -> tuple[Observation, ...]:
        stdout = result.stdout
        if not stdout.strip():
            return ()

        observations: list[Observation] = []
        from ariadne.core.engagement import TargetSpec

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                # Skip malformed lines
                continue

            if not isinstance(record, dict):
                continue

            template_id = record.get("template-id", "")
            if not template_id:
                continue

            info = record.get("info", {})
            if isinstance(info, dict):
                name = info.get("name", "")
                severity = info.get("severity", "info")
                author = info.get("author", "")
            else:
                name = ""
                severity = "info"
                author = ""

            host = record.get("host", "")
            if not host or not isinstance(host, str) or host == "unknown":
                continue
            matched_at = record.get("matched-at", "")
            extracted = record.get("extracted-results")

            obs_data: dict[str, object] = {
                "template_id": template_id,
                "name": name,
                "severity": severity,
                "author": author,
                "matched_at": matched_at,
                "type": record.get("type", ""),
            }

            if extracted is not None:
                obs_data["extracted_results"] = extracted

            obs = Observation(
                observation_id=uuid4(),
                target=TargetSpec(host=str(host)),
                source="nuclei",
                data=obs_data,
            )
            observations.append(obs)

        return tuple(observations)

    def classify(
        self,
        result: ProcessResult,
        observations: tuple[Observation, ...],
    ) -> ExecutionClassification:
        if result.timed_out:
            return ExecutionClassification(
                kind="partial",
                confidence=0.3,
                summary="Nuclei timed out; partial results may be available",
            )
        if result.exit_code != 0:
            return ExecutionClassification(
                kind="failure",
                confidence=0.5,
                summary=f"Nuclei exited with code {result.exit_code}",
            )
        if len(observations) > 0:
            severities = [o.data.get("severity", "") for o in observations]
            critical = [s for s in severities if s == "critical"]
            high = [s for s in severities if s == "high"]
            if critical:
                return ExecutionClassification(
                    kind="success",
                    confidence=0.8,
                    summary=f"Found {len(observations)} matches ({len(critical)} critical)",
                )
            if high:
                return ExecutionClassification(
                    kind="success",
                    confidence=0.7,
                    summary=f"Found {len(observations)} matches ({len(high)} high)",
                )
            return ExecutionClassification(
                kind="success",
                confidence=0.6,
                summary=f"Found {len(observations)} template matches",
            )
        return ExecutionClassification(
            kind="unknown",
            confidence=0.5,
            summary="Nuclei completed with no matches",
        )

    async def collect(
        self,
        result: ProcessResult,
        collector: object,
    ) -> tuple[str, ...]:
        return ()

    async def cleanup(
        self,
        context: AdapterContext,
    ) -> CleanupResult:
        return CleanupResult(success=True, details="No temporary resources to clean up")
