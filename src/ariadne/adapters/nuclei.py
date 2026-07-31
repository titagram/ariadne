"""Nuclei vulnerability-scanning adapter.

Builds safe, bounded Nuclei command-lines using only templates selected from
a locally indexed, commit-pinned official catalog, and parses Nuclei JSONL
output into structured Observation objects.

Safety invariants
-----------------
- Only catalog paths selected from observed technologies or validated CVEs
  are accepted.
- Arbitrary template directories (``template_dir``) are rejected
  via ``AdapterPolicyError``.
- No shell interpolation: every argument is in the argv tuple.
- Timeout and output size are bounded by ``ProcessSpec``.
- All template matches are treated as candidates until the
  evidence module validates them.
"""

from __future__ import annotations

import ipaddress
import json
from functools import lru_cache
from typing import ClassVar, cast
from urllib.parse import urlsplit
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
from ariadne.catalog.nuclei import (
    NucleiCatalogError,
    NucleiTemplateCatalog,
)
from ariadne.core.engagement import TargetSpec
from ariadne.core.errors import AdapterPolicyError
from ariadne.core.observations import Observation

_OPERATIONS: frozenset = frozenset({"scan"})


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise AdapterError(f"Nuclei {label} must be a positive integer.")
    try:
        parsed = int(value)
    except ValueError as exc:
        raise AdapterError(f"Nuclei {label} must be a positive integer.") from exc
    if parsed < 1:
        raise AdapterError(f"Nuclei {label} must be a positive integer.")
    return parsed


@lru_cache(maxsize=1)
def _default_catalog() -> NucleiTemplateCatalog:
    return NucleiTemplateCatalog.load()


def is_official_nuclei_template_provenance(value: str) -> bool:
    """Accept only a concrete file at the catalog's pinned official commit."""
    try:
        parsed = urlsplit(value)
        revision = _default_catalog().revision
    except (ValueError, NucleiCatalogError, OSError):
        return False
    segments = parsed.path.split("/")
    return (
        parsed.scheme == "https"
        and parsed.hostname == "github.com"
        and parsed.username is None
        and parsed.password is None
        and parsed.port in {None, 443}
        and len(segments) >= 7
        and segments[1:4] == ["projectdiscovery", "nuclei-templates", "blob"]
        and segments[4] == revision
        and all(segment not in {"", ".", ".."} for segment in segments[5:])
        and segments[-1].endswith(".yaml")
    )


class NucleiAdapter:
    """ToolAdapter for ProjectDiscovery Nuclei template-based scanning.

    Supports ``scan`` operations with catalog-selected template paths.
    Rejects unapproved template directories via policy error.
    """

    name: ClassVar[str] = "nuclei"

    def __init__(
        self,
        catalog: NucleiTemplateCatalog | None = None,
    ) -> None:
        self._catalog = catalog or _default_catalog()

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
                f"Unknown Nuclei operation: {op!r}. Supported: {', '.join(sorted(_OPERATIONS))}"
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

        # Build argv with catalog-selected templates
        argv: list[str] = ["nuclei"]

        raw_candidates = inputs.get("validated_candidates", ())
        if not isinstance(raw_candidates, (list, tuple)) or not raw_candidates:
            raise AdapterPolicyError(
                "Nuclei scan requires a validated template candidate; "
                "do not run the default template set."
            )
        cve_ids: list[str] = []
        technologies: list[str] = []
        required_candidate_keys = {
            "candidate_id",
            "cve_id",
            "product",
            "version",
            "target",
            "validation_status",
            "compatible",
            "applicability_evidence",
            "evidence_id",
            "provenance",
        }
        for candidate in raw_candidates:
            if not isinstance(candidate, dict):
                raise AdapterPolicyError(
                    "Nuclei scan requires a structured validated template "
                    "candidate tied to persisted evidence."
                )
            candidate_map = cast(dict[str, object], candidate)
            if (
                not required_candidate_keys.issubset(candidate_map)
                or candidate_map.get("validation_status") != "validated"
                or candidate_map.get("compatible") is not True
                or not all(
                    isinstance(candidate_map.get(key), str)
                    and bool(str(candidate_map.get(key)).strip())
                    for key in required_candidate_keys - {"compatible", "applicability_evidence"}
                )
                or not isinstance(
                    candidate_map.get("applicability_evidence"),
                    (list, tuple),
                )
                or not candidate_map["applicability_evidence"]
            ):
                raise AdapterPolicyError(
                    "Nuclei scan requires a structured validated template "
                    "candidate tied to persisted evidence."
                )
            if candidate_map["target"] != target:
                raise AdapterPolicyError(
                    "Nuclei validated template candidate is not tied to the current target."
                )
            cve_ids.append(str(candidate_map["cve_id"]))
            technologies.append(str(candidate_map["product"]))
        raw_technologies = inputs.get("observed_technologies", ())
        if not isinstance(raw_technologies, (list, tuple)) or not all(
            isinstance(item, str) and item.strip() for item in raw_technologies
        ):
            raise AdapterPolicyError(
                "Nuclei observed_technologies must contain evidence-derived names"
            )
        technologies.extend(cast(tuple[str, ...], tuple(raw_technologies)))
        try:
            templates = self._catalog.select(
                cve_ids=tuple(cve_ids),
                technologies=tuple(technologies),
                maximum=20,
            )
        except NucleiCatalogError as exc:
            raise AdapterPolicyError(str(exc)) from exc
        if not templates:
            raise AdapterPolicyError(
                "No pinned official Nuclei template matches the validated "
                "CVE or observed technologies."
            )
        for template in templates:
            argv.extend(["-t", self._catalog.container_path(template)])

        # Target
        argv.extend(["-target", target])
        http_host = inputs.get("http_host")
        if http_host is not None:
            if not isinstance(http_host, str):
                raise AdapterError("http_host must be a hostname")
            alias = TargetSpec(host=http_host).host
            if alias == context.target.host:
                raise AdapterError("http_host must be distinct from the network target")
            try:
                ipaddress.ip_address(alias)
            except ValueError:
                argv.extend(("-H", f"Host: {alias}"))
            else:
                raise AdapterError("http_host must be an approved FQDN alias")

        # JSONL output.  Current Nuclei releases use ``-jsonl``; the older
        # ``-json`` spelling exits with code 2 and produces no observations.
        argv.append("-jsonl")

        rate_limit = _positive_int(
            inputs.get(
                "rate_limit",
                context.limits.max_rate or 1,
            ),
            "rate_limit",
        )
        template_timeout = _positive_int(
            inputs.get("template_timeout", 10),
            "template_timeout",
        )
        process_timeout = _positive_int(
            inputs.get(
                "timeout",
                context.limits.max_duration_seconds or 300,
            ),
            "timeout",
        )
        max_output = _positive_int(
            inputs.get(
                "max_output",
                context.limits.max_output_bytes or 10_000_000,
            ),
            "max_output",
        )

        # Rate and timeout defaults come from the already-intersected plan
        # limits so the adapter cannot exceed the engagement policy by default.
        argv.extend(["-rate-limit", str(rate_limit)])
        argv.extend(["-timeout", str(template_timeout)])

        return ProcessSpec(
            argv=tuple(argv),
            timeout_seconds=process_timeout,
            max_output_bytes=max_output,
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
