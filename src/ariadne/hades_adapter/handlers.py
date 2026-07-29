"""Ariadne tool handlers.

Each handler is an async function registered with Hades via
``PluginContext.register_tool(…, handler=<this>, is_async=True)``.

These handlers delegate to ``AriadneCommand`` for engagement lifecycle
operations. Session identity always comes from trusted Hades context.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import shutil
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from pydantic import ValidationError

from ariadne.adapters import AdapterRegistry
from ariadne.adapters.base import AdapterContext, Runtime
from ariadne.catalog.nuclei import NucleiCatalogError, NucleiTemplateCatalog
from ariadne.core.canonical import canonical_digest
from ariadne.core.engagement import (
    EngagementSnapshot,
    TargetSpec,
    intensity_default_limits,
)
from ariadne.core.enums import AssetStatus, EngagementState
from ariadne.core.errors import (
    AdapterPolicyError,
    PolicyConfigurationError,
    ScopeAmendmentRequiredError,
    WorkflowConfigurationError,
)
from ariadne.core.observations import (
    Asset,
    Hypothesis,
    Observation,
    create_scope_candidate,
    discovered_asset_status,
)
from ariadne.core.planner import Planner
from ariadne.core.policy import EffectivePolicy
from ariadne.core.workflow import PlanningContext, Playbook, WorkflowCatalog
from ariadne.evidence.collector import EvidenceCollector
from ariadne.execution.contracts import (
    AuthorizationReason,
    ExecutionContractRegistry,
    ExecutionCoordinator,
    ExecutionEnvelope,
    GuardedRuntime,
)
from ariadne.hades_adapter.commands import CURRENT_DISCLAIMER_VERSION, AriadneCommand
from ariadne.hades_adapter.consent import ConsentDecision, ConsentGateway
from ariadne.hades_adapter.schemas import AmendEngagementInput, PrepareEngagementInput
from ariadne.knowledge import (
    RuntimeVerification,
    ToolCardVerifier,
    ToolDiscovery,
    ToolVerificationBlockedError,
)
from ariadne.knowledge.runtime import GuidanceSource
from ariadne.reporting.models import RenderedReport
from ariadne.reporting.professional import ProfessionalRenderer
from ariadne.reporting.validation import ReportOptions, ReportValidator
from ariadne.reporting.walkthrough import WalkthroughRenderer
from ariadne.runtime.docker import (
    KaliRuntimeUnavailableError,
    LocalFirstRuntime,
    OnDemandKaliRuntime,
)
from ariadne.runtime.process import ProcessRunner
from ariadne.runtime.selection import (
    RuntimeChoice,
    choose_runtime,
    curated_kali_executables,
)
from ariadne.store.run_store import ArtifactInput, Event, RunHandle, RunStore

_DOS_ALIASES = frozenset(
    {
        "dos",
        "denial of service",
        "denial service",
        "resource exhaustion",
        "resource stress",
    }
)
_EXCLUSION_CAPABILITY_ALIASES = {
    "port scan": frozenset({"scan.tcp", "scan.udp"}),
    "port scanning": frozenset({"scan.tcp", "scan.udp"}),
    "password spray": frozenset({"auth.spray", "ad.password_spray"}),
    "password spraying": frozenset({"auth.spray", "ad.password_spray"}),
    "brute force": frozenset({"auth.brute_force"}),
    "active web scan": frozenset({"web.active_scan"}),
    "web fuzzing": frozenset({"web.fuzz"}),
    "metasploit": frozenset({"exploit.metasploit"}),
}


def _tool_id_for_executable(executable: str) -> str:
    """Derive a stable knowledge id from the authorized ProcessSpec."""
    slug = re.sub(
        r"[^a-z0-9_.-]+",
        "-",
        Path(executable).name.casefold(),
    ).strip("-.")
    if not slug or not slug[0].isalpha():
        raise ToolVerificationBlockedError(
            f"Cannot derive a tool-card id from executable {executable!r}"
        )
    return f"tool.{slug}"


def _inspect_planned_tool(
    *,
    verifier: ToolCardVerifier,
    process_argv: tuple[str, ...],
    action_inputs: dict[str, Any],
    allowed_policy: frozenset[str],
    required_policy: tuple[str, ...],
    inspection: tuple[str, str, str, GuidanceSource] | None = None,
) -> RuntimeVerification | None:
    """Inspect a canonical card or discover one declared by the playbook.

    ``tool_card`` is reserved playbook metadata.  Its executable is never
    trusted: the executable and resulting id are derived from the already
    planned, subsequently authorized ``ProcessSpec``.
    """
    tool_id = _tool_id_for_executable(process_argv[0])
    if not set(required_policy).issubset(allowed_policy):
        raise ToolVerificationBlockedError(f"{tool_id}: playbook tool policy is not allowed")
    declaration = action_inputs.get("tool_card")
    if tool_id in verifier.index.nodes:
        return verifier.inspect(
            tool_id,
            allowed_policy=allowed_policy,
            inspection=inspection,
        )
    if declaration is None:
        raise ToolVerificationBlockedError(
            f"{tool_id}: no canonical card or curated playbook tool_card metadata"
        )
    if not isinstance(declaration, dict):
        raise ToolVerificationBlockedError(
            f"{tool_id}: playbook tool_card metadata must be a mapping"
        )

    metadata = cast(dict[str, object], declaration)
    allowed_metadata = {
        "title",
        "official_source_url",
        "source_date",
        "summary",
        "version_args",
        "help_args",
    }
    if set(metadata) - allowed_metadata:
        raise ToolVerificationBlockedError(
            f"{tool_id}: playbook tool_card contains unsupported metadata"
        )
    official_url = metadata.get("official_source_url")
    if not isinstance(official_url, str) or not _safe_official_url(official_url):
        raise ToolVerificationBlockedError(
            f"{tool_id}: playbook tool_card requires a public HTTPS official source"
        )
    source_date = metadata.get("source_date")
    if not isinstance(source_date, str):
        raise ToolVerificationBlockedError(
            f"{tool_id}: playbook tool_card requires an explicit source_date"
        )
    title = metadata.get("title", Path(process_argv[0]).name)
    summary = metadata.get(
        "summary",
        f"Concise runtime guidance for {Path(process_argv[0]).name}.",
    )
    if not isinstance(title, str) or not isinstance(summary, str):
        raise ToolVerificationBlockedError(
            f"{tool_id}: playbook tool_card title and summary must be strings"
        )
    version_args = metadata.get("version_args", ("--version",))
    help_args = metadata.get("help_args", ("--help",))
    if (
        not isinstance(version_args, (list, tuple))
        or not isinstance(help_args, (list, tuple))
        or tuple(version_args) != ("--version",)
        or tuple(help_args) != ("--help",)
    ):
        raise ToolVerificationBlockedError(
            f"{tool_id}: unknown-tool probes are documentation-only and fixed to --version/--help"
        )

    slug = tool_id.removeprefix("tool.")
    try:
        discovery = ToolDiscovery(
            tool_id=tool_id,
            title=title,
            executable=process_argv[0],
            policy=tuple(sorted(required_policy)),
            official_source_id=f"source.{slug}.official",
            official_source_url=official_url,
            source_date=source_date,
            summary=summary,
            version_args=("--version",),
            help_args=("--help",),
        )
    except ValidationError as exc:
        raise ToolVerificationBlockedError(
            f"{tool_id}: invalid playbook tool_card metadata"
        ) from exc
    return verifier.inspect_or_discover(
        discovery,
        allowed_policy=allowed_policy,
        inspection=inspection,
    )


def _safe_official_url(value: str) -> bool:
    """Accept only public HTTPS documentation origins from curated metadata."""
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.fragment
    ):
        return False
    normalized = hostname.casefold().rstrip(".")
    if (
        "." not in normalized
        or normalized == "localhost"
        or normalized.endswith((".localhost", ".local", ".internal", ".lan"))
    ):
        return False
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        return all(
            label
            and len(label) <= 63
            and label[0].isalnum()
            and label[-1].isalnum()
            and all(character.isalnum() or character == "-" for character in label)
            for label in normalized.split(".")
        )
    return False


def _exclusion_conflict(
    playbook: Playbook,
    exclusions: tuple[str, ...],
) -> str | None:
    """Return the exclusion that blocks a playbook, if any."""
    capabilities = set(playbook.capabilities)
    action_names = {
        value
        for action in playbook.actions
        for value in (
            action.adapter,
            action.operation,
            f"{action.adapter}:{action.operation}",
        )
    }
    for raw_exclusion in exclusions:
        normalized = (
            raw_exclusion.casefold().replace("_", " ").replace("-", " ").replace(".", " ").strip()
        )
        if normalized in _DOS_ALIASES and capabilities & {
            "resource.stress",
            "resource.exhaustion",
        }:
            return raw_exclusion
        if capabilities & _EXCLUSION_CAPABILITY_ALIASES.get(
            normalized,
            frozenset(),
        ):
            return raw_exclusion
        candidates = capabilities | action_names
        if any(
            normalized
            == candidate.casefold().replace("_", " ").replace("-", " ").replace(".", " ").strip()
            for candidate in candidates
        ):
            return raw_exclusion
    return None


def _get_command(context: dict[str, Any]) -> AriadneCommand:
    """Extract the AriadneCommand from the handler context."""
    cmd = context.get("ariadne_command")
    if cmd is None:
        raise ValueError(
            "No ariadne_command available in handler context. "
            "The composition root must pass it as a keyword argument."
        )
    if not isinstance(cmd, AriadneCommand):
        raise TypeError(f"Expected AriadneCommand, got {type(cmd).__name__}")
    return cmd


def _get_planner(context: dict[str, Any]) -> Planner:
    """Extract the Planner from the handler context."""
    planner = context.get("planner")
    if planner is None:
        raise ValueError(
            "No planner available in handler context. "
            "The composition root must pass it as a keyword argument."
        )
    if not isinstance(planner, Planner):
        raise TypeError(f"Expected Planner, got {type(planner).__name__}")
    return planner


def _get_catalog(context: dict[str, Any]) -> WorkflowCatalog:
    """Extract the WorkflowCatalog from the handler context."""
    catalog = context.get("catalog")
    if catalog is None:
        raise ValueError("No catalog available in handler context.")
    if not isinstance(catalog, WorkflowCatalog):
        raise TypeError(f"Expected WorkflowCatalog, got {type(catalog).__name__}")
    return catalog


def _get_adapter_registry(context: dict[str, Any]) -> AdapterRegistry:
    """Extract the AdapterRegistry from the handler context."""
    registry = context.get("adapter_registry")
    if registry is None:
        raise ValueError("No adapter_registry available in handler context.")
    if not isinstance(registry, AdapterRegistry):
        raise TypeError(f"Expected AdapterRegistry, got {type(registry).__name__}")
    return registry


def _get_runtime(context: dict[str, Any]) -> Runtime:
    """Extract the Runtime from the handler context."""
    runtime = context.get("runtime")
    if runtime is None:
        raise ValueError("No runtime available in handler context.")
    return runtime


def _get_consent_gateway(context: dict[str, Any]) -> ConsentGateway:
    """Extract the composition-owned trusted consent gateway."""
    gateway = context.get("consent_gateway")
    if not isinstance(gateway, ConsentGateway):
        raise TypeError("No trusted composition consent gateway is available.")
    return gateway


def _get_execution_contract_registry(
    context: dict[str, Any],
) -> ExecutionContractRegistry:
    registry = context.get("execution_contract_registry")
    if not isinstance(registry, ExecutionContractRegistry):
        raise TypeError("No trusted composition execution contract registry is available.")
    return registry


def _get_execution_coordinator(
    context: dict[str, Any],
) -> ExecutionCoordinator:
    coordinator = context.get("execution_coordinator")
    if not isinstance(coordinator, ExecutionCoordinator):
        raise TypeError("No trusted composition execution coordinator is available.")
    return coordinator


def _is_simulated_evidence(
    source: str,
    data: dict[str, Any],
) -> bool:
    summary = data.get("summary")
    return (
        source.casefold() in {"noop", "simulation", "simulated"}
        or data.get("simulated") is True
        or (isinstance(summary, str) and summary.casefold().startswith("simulated"))
    )


def _determine_engagement_state(
    store: RunStore,
    run_handle: RunHandle,
) -> tuple[EngagementState, tuple[Observation, ...]]:
    """Read the run store and determine the current engagement state.

    Checks the events log to find existing evidence types and maps them
    to the correct ``EngagementState``.

    Returns:
        A ``(state, observations)`` tuple where ``observations`` contains
        all past evidence observations reconstructed from store events.
    """
    events = store.read_events(run_handle)

    # Collect evidence type strings from evidence_collected events
    evidence_types: set[str] = set()
    observations: list[Observation] = []

    for evt in events:
        event_type = evt.get("event_type", "")
        payload = evt.get("payload", {})

        # Completion transitions must come from an explicit persisted proof or
        # from an adapter cleanup result.  Do not infer either state from a
        # playbook's declarative ``success_emits`` metadata.
        if event_type == "objective_completed":
            evidence_types.add("objective_proven")
            continue
        if event_type == "cleanup_completed":
            evidence_types.add("cleanup_complete")
            continue

        if event_type == "evidence_collected":
            evidence_type = payload.get("evidence_type", "")
            classification = payload.get("execution_classification")
            observation_data = payload.get("observation_data", {})
            if isinstance(observation_data, dict) and _is_simulated_evidence(
                str(evidence_type),
                observation_data,
            ):
                continue
            if evidence_type and classification in (None, "success"):
                evidence_types.add(evidence_type)
            if (
                classification == "success"
                and isinstance(observation_data, dict)
                and isinstance(observation_data.get("type"), str)
                and observation_data["type"]
            ):
                evidence_types.add(observation_data["type"])

            if classification in (None, "success"):
                # Reconstruct only evidence that is either a trusted imported
                # record or the successful result of an executed action.
                from uuid import uuid4

                obs = Observation(
                    observation_id=uuid4(),
                    target=run_handle.snapshot.targets[0]
                    if run_handle.snapshot.targets
                    else TargetSpec(host="unknown"),
                    source=evidence_type or "unknown",
                    data={
                        "event_type": event_type,
                        "finding": payload.get("finding", ""),
                        "artifact": payload.get("artifact", ""),
                        **(observation_data if isinstance(observation_data, dict) else {}),
                    },
                )
                observations.append(obs)

    # Get already-executed playbook IDs from the store
    executed_playbooks: set[str] = set()
    for evt in events:
        if evt.get("event_type") == "plan_executed":
            payload = evt.get("payload", {})
            if payload.get("status") in (
                "executed",
                "success",
                "failed",
                "blocked_scope_candidate",
            ):
                pb_id = payload.get("playbook_id", "")
                if pb_id:
                    executed_playbooks.add(pb_id)

    # Check evidence types from most advanced to most basic.  Each emitted
    # evidence type advances to the stage of the next playbook.
    if "report_ready" in evidence_types:
        return EngagementState.COMPLETE, tuple(observations)
    if "cleanup_complete" in evidence_types:
        return EngagementState.REPORTING, tuple(observations)
    if "objective_proven" in evidence_types or "objective_completed" in evidence_types:
        return EngagementState.CLEANUP, tuple(observations)
    if "privesc_found" in evidence_types or "privesc_path_identified" in evidence_types:
        return EngagementState.OBJECTIVE_VALIDATION, tuple(observations)
    if (
        "host_info_collected" in evidence_types
        or "host_enumerated" in evidence_types
        or "postex_complete" in evidence_types
    ):
        return EngagementState.PRIVILEGE_ESCALATION, tuple(observations)
    if "foothold_established" in evidence_types:
        return EngagementState.POST_EXPLOITATION, tuple(observations)
    if "vulnerability_validated" in evidence_types or "exploit_succeeded" in evidence_types:
        return EngagementState.FOOTHOLD, tuple(observations)
    target = (
        run_handle.snapshot.targets[0]
        if run_handle.snapshot.targets
        else TargetSpec(host="unknown")
    )
    if _persisted_research_candidates(events, run_handle, target.host):
        return EngagementState.VALIDATION, tuple(observations)
    if "research_complete" in evidence_types:
        if _latest_service_fingerprint(tuple(observations), target) is not None:
            return EngagementState.HYPOTHESIS, tuple(observations)
        return EngagementState.ENUMERATION, tuple(observations)
    if "protocol_routed" in evidence_types:
        return EngagementState.HYPOTHESIS, tuple(observations)
    if "service_fingerprinted" in evidence_types:
        return EngagementState.ENUMERATION, tuple(observations)
    if "port_open" in evidence_types:
        return EngagementState.ENUMERATION, tuple(observations)
    if "preflight_passed" in evidence_types or "research.preflight" in evidence_types:
        return EngagementState.DISCOVERY, tuple(observations)

    # If there are events but no preflight evidence, we're still in preflight
    if events:
        return EngagementState.ENVIRONMENT_PREFLIGHT, tuple(observations)

    # No events at all — brand new engagement, start at preflight
    return EngagementState.ENVIRONMENT_PREFLIGHT, ()


def _typed_progression_observations(
    *,
    playbook_id: str,
    adapter: str,
    operation: str,
    action_inputs: dict[str, Any],
    target: TargetSpec,
    observations: tuple[Observation, ...],
    classification_kind: str,
) -> tuple[Observation, ...]:
    """Add narrowly justified workflow evidence after a successful action."""
    if classification_kind != "success":
        return observations

    from uuid import uuid4

    additions: list[Observation] = []

    def add(kind: str, observation: Observation) -> None:
        if any(
            existing.source == kind and existing.target == observation.target
            and (
                kind != "protocol_routed"
                or (
                    existing.data.get("port") == observation.data.get("port")
                    and existing.data.get("protocol") == observation.data.get("protocol")
                    and existing.data.get("service") == observation.data.get("service")
                )
            )
            for existing in (*observations, *additions)
        ):
            return
        additions.append(
            Observation(
                observation_id=uuid4(),
                target=observation.target,
                source=kind,
                data={**observation.data, "type": kind},
            )
        )

    if (
        playbook_id == "service.protocol-routing.v1"
        and adapter == "nmap"
        and operation == "service_fingerprint"
    ):
        for observation in observations:
            if (
                observation.target == target
                and observation.source == "service_fingerprinted"
                and isinstance(observation.data.get("port"), int)
                and isinstance(observation.data.get("protocol"), str)
                and bool(observation.data.get("protocol"))
                and isinstance(observation.data.get("service"), str)
                and bool(observation.data.get("service"))
            ):
                add("protocol_routed", observation)

    if adapter == "nuclei" and operation == "scan":
        raw_candidates = action_inputs.get("validated_candidates", ())
        validated_candidates = tuple(
            candidate
            for candidate in raw_candidates
            if isinstance(candidate, dict)
            and candidate.get("target") == target.host
            and candidate.get("validation_status") == "validated"
            and candidate.get("compatible") is True
        )
        try:
            selected_templates = NucleiTemplateCatalog.load().select(
                cve_ids=tuple(
                    str(candidate.get("cve_id", "")) for candidate in validated_candidates
                ),
                technologies=tuple(
                    str(candidate.get("product", "")) for candidate in validated_candidates
                ),
            )
            validated_templates = {template.template_id for template in selected_templates}
        except (NucleiCatalogError, OSError, ValueError):
            validated_templates = set()
        for observation in observations:
            if (
                observation.target == target
                and observation.source == "nuclei"
                and observation.data.get("template_id") in validated_templates
                and isinstance(observation.data.get("matched_at"), str)
                and bool(observation.data.get("matched_at"))
            ):
                add("vulnerability_validated", observation)

    if adapter == "httpx" and operation == "scan":
        for observation in observations:
            if (
                observation.target != target
                or observation.source != "httpx"
                or not isinstance(observation.data.get("url"), str)
                or not observation.data["url"]
            ):
                continue
            status_code = observation.data.get("status_code")
            if (
                isinstance(status_code, int)
                and not isinstance(status_code, bool)
                and 0 < status_code <= 599
            ):
                add("web_technologies", observation)
            if isinstance(observation.data.get("title"), str) and observation.data["title"]:
                add("web_title", observation)
            if observation.data.get("redirect") is True:
                add("web_redirect", observation)

    if (
        playbook_id == "foothold.confirmation.v1"
        and adapter == "screenshot"
        and operation == "capture"
        and action_inputs.get("proof_kind") == "initial_access"
    ):
        for observation in observations:
            proof_path = observation.data.get("path")
            if (
                observation.target == target
                and observation.source == "screenshot"
                and isinstance(proof_path, str)
                and Path(proof_path).is_file()
            ):
                add("foothold_established", observation)

    if adapter == "postex":
        for observation in observations:
            observation_type = observation.data.get("type")
            if (
                observation.target == target
                and operation == "identity"
                and observation_type == "user_identity"
                and bool(observation.data.get("identity"))
            ):
                add("host_info_collected", observation)
            elif (
                observation.target == target
                and operation == "sudo_rules"
                and observation_type == "privilege_escalation"
                and bool(observation.data.get("rules"))
            ):
                add("privesc_path_identified", observation)

    return (*observations, *additions)


def _persisted_research_candidates(
    events: list[dict[str, Any]],
    run_handle: RunHandle,
    target: str,
) -> tuple[dict[str, Any], ...]:
    """Recover validated candidates only from integrity-checked research."""
    artifact_root = (run_handle.path / "artifacts").resolve()
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for event in events:
        payload = event.get("payload")
        if event.get("event_type") != "evidence_collected" or not isinstance(payload, dict):
            continue
        evidence_id = payload.get("evidence_id")
        artifact = payload.get("artifact")
        expected_digest = payload.get("sha256")
        observation_data = payload.get("observation_data")
        if (
            not isinstance(evidence_id, str)
            or not evidence_id.strip()
            or not isinstance(artifact, str)
            or not artifact.strip()
            or payload.get("asset") != target
            or payload.get("execution_classification") != "success"
            or payload.get("adapter") != "research"
            or payload.get("source") != "research:investigate"
            or payload.get("evidence_type") != "research_complete"
            or not isinstance(expected_digest, str)
            or not isinstance(observation_data, dict)
        ):
            continue
        artifact_path = (artifact_root / artifact).resolve()
        try:
            artifact_path.relative_to(artifact_root)
        except ValueError:
            continue
        if not artifact_path.is_file():
            continue
        with artifact_path.open("rb") as artifact_stream:
            actual_digest = hashlib.file_digest(
                artifact_stream,
                "sha256",
            ).hexdigest()
        if not hmac.compare_digest(actual_digest, expected_digest):
            continue
        raw_candidates = observation_data.get("candidates")
        fingerprint = observation_data.get("fingerprint")
        fingerprint_port = fingerprint.get("port") if isinstance(fingerprint, dict) else None
        if not isinstance(raw_candidates, list):
            continue
        for candidate in raw_candidates:
            if not isinstance(candidate, dict):
                continue
            required_strings = (
                "candidate_id",
                "cve_id",
                "product",
                "version",
            )
            sources = candidate.get("sources")
            source_urls = candidate.get("source_urls")
            evidence = candidate.get("evidence")
            applicability = candidate.get("applicability_evidence")
            if (
                candidate.get("validation_status") != "validated"
                or candidate.get("compatible") is not True
                or not all(
                    isinstance(candidate.get(field), str) and bool(str(candidate[field]).strip())
                    for field in required_strings
                )
                or not isinstance(sources, list)
                or not {
                    "vendor",
                    "nvd",
                    "cisa-kev",
                }.intersection(sources)
                or not {
                    "local-searchsploit",
                    "metasploit",
                }.intersection(sources)
                or not isinstance(source_urls, list)
                or not isinstance(evidence, list)
                or not evidence
                or not isinstance(applicability, list)
                or not all(isinstance(item, str) and item.strip() for item in applicability)
                or not applicability
                or not all(
                    isinstance(item, dict)
                    and isinstance(item.get("sha256"), str)
                    and bool(item["sha256"])
                    and isinstance(item.get("source"), str)
                    for item in evidence
                )
            ):
                continue
            provenance = next(
                (value for value in source_urls if isinstance(value, str) and value.strip()),
                "",
            )
            if not provenance:
                continue
            key = (
                str(candidate["candidate_id"]),
                str(candidate["cve_id"]),
            )
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                {
                    **candidate,
                    "target": target,
                    "evidence_id": evidence_id,
                    "provenance": provenance,
                    **(
                        {"port": fingerprint_port}
                        if isinstance(fingerprint_port, int)
                        and not isinstance(fingerprint_port, bool)
                        else {}
                    ),
                }
            )

    return tuple(candidates)


def _validated_nuclei_candidates(
    events: list[dict[str, Any]],
    run_handle: RunHandle,
    target: str,
) -> tuple[dict[str, Any], ...]:
    return _persisted_research_candidates(events, run_handle, target)


def _validated_metasploit_candidates(
    events: list[dict[str, Any]],
    run_handle: RunHandle,
    target: str,
) -> tuple[dict[str, Any], ...]:
    """Expand exact compatible MSF modules from persisted research."""
    candidates: list[dict[str, Any]] = []
    for candidate in _persisted_research_candidates(
        events,
        run_handle,
        target,
    ):
        modules = candidate.get("metasploit_modules")
        if candidate.get("check_supported") is not True or not isinstance(
            modules,
            list,
        ):
            continue
        for module in sorted(
            value for value in modules if isinstance(value, str) and value.strip()
        ):
            candidates.append(
                {
                    **candidate,
                    "module": module,
                }
            )
    return tuple(candidates)


def _metasploit_check_evidence(
    events: list[dict[str, Any]],
    run_handle: RunHandle,
    *,
    target: str,
    module: str,
) -> str | None:
    """Return a persisted positive check for one exact module and target."""
    artifact_root = (run_handle.path / "artifacts").resolve()
    for event in reversed(events):
        payload = event.get("payload")
        if (
            event.get("event_type") != "evidence_collected"
            or not isinstance(payload, dict)
            or payload.get("asset") != target
            or payload.get("adapter") != "metasploit"
            or payload.get("source") != "metasploit:check"
            or payload.get("evidence_type") != "metasploit_check_vulnerable"
            or payload.get("execution_classification") != "success"
        ):
            continue
        observation = payload.get("observation_data")
        artifact = payload.get("artifact")
        expected_digest = payload.get("sha256")
        evidence_id = payload.get("evidence_id")
        if (
            not isinstance(observation, dict)
            or observation.get("module") != module
            or observation.get("check_status") != "vulnerable"
            or not isinstance(artifact, str)
            or not isinstance(expected_digest, str)
            or not isinstance(evidence_id, str)
            or not evidence_id.strip()
        ):
            continue
        artifact_path = (artifact_root / artifact).resolve()
        try:
            artifact_path.relative_to(artifact_root)
        except ValueError:
            continue
        if not artifact_path.is_file():
            continue
        with artifact_path.open("rb") as artifact_stream:
            actual = hashlib.file_digest(artifact_stream, "sha256").hexdigest()
        if hmac.compare_digest(actual, expected_digest):
            return evidence_id
    return None


def _latest_service_fingerprint(
    observations: tuple[Observation, ...],
    target: TargetSpec,
) -> dict[str, Any] | None:
    """Return the newest real fingerprint not already covered by research."""
    researched = {
        identity
        for observation in observations
        if observation.target == target
        and observation.source == "research_complete"
        and isinstance(observation.data.get("fingerprint"), dict)
        and (
            identity := _service_fingerprint_identity(
                observation.data["fingerprint"],
            )
        )
        is not None
    }
    seen: set[tuple[str, str, str, int | None, str]] = set()
    for observation in reversed(observations):
        if observation.target != target or observation.source not in {
            "service_fingerprinted",
            "protocol_routed",
        }:
            continue
        identity = _service_fingerprint_identity(observation.data)
        if identity is None or identity in seen or identity in researched:
            continue
        seen.add(identity)
        product = observation.data.get("product")
        if not isinstance(product, str) or not product.strip():
            product = observation.data.get("service")
        if not isinstance(product, str) or not product.strip() or product.casefold() == "unknown":
            continue
        fingerprint: dict[str, Any] = {"product": product.strip()}
        for field in ("version", "protocol", "cpe"):
            value = observation.data.get(field)
            if isinstance(value, str) and value.strip():
                fingerprint[field] = value.strip()
        port = observation.data.get("port")
        if isinstance(port, int) and not isinstance(port, bool) and port > 0:
            fingerprint["port"] = port
        return fingerprint
    return None


def _service_fingerprint_identity(
    data: dict[str, Any],
) -> tuple[str, str, str, int | None, str] | None:
    product = data.get("product")
    if not isinstance(product, str) or not product.strip():
        product = data.get("service")
    if not isinstance(product, str) or not product.strip():
        return None
    version = data.get("version")
    protocol = data.get("protocol")
    port = data.get("port")
    cpe = data.get("cpe")
    return (
        product.strip().casefold(),
        version.strip().casefold() if isinstance(version, str) else "",
        protocol.strip().casefold() if isinstance(protocol, str) else "",
        port if isinstance(port, int) and not isinstance(port, bool) and port > 0 else None,
        cpe.strip().casefold() if isinstance(cpe, str) else "",
    )


def _observed_web_ports(
    observations: tuple[Observation, ...],
    target: TargetSpec,
) -> tuple[int, ...]:
    web_services = {
        "http",
        "https",
        "http-proxy",
        "ssl/http",
    }
    return tuple(
        sorted(
            {
                port
                for observation in observations
                if observation.target == target
                and str(observation.data.get("service", "")).casefold()
                in web_services
                and isinstance((port := observation.data.get("port")), int)
                and not isinstance(port, bool)
                and 0 < port <= 65535
            }
        )
    )


def _get_binding(cmd: AriadneCommand, session_id: str) -> dict[str, Any] | None:
    """Check for an active engagement binding and return its metadata.

    Returns None if the session has no active binding.
    """
    if not session_id:
        return None
    binding = cmd.get_session_binding(session_id)
    if binding is None:
        return None
    return {
        "snapshot_hash": binding.snapshot_hash,
        "engagement_id": binding.engagement_id,
        "session_id": binding.session_id,
    }


async def handle_prepare_engagement(args: dict[str, Any], **context: Any) -> dict[str, Any]:
    """Validate the completed Q/A, then atomically lock and bind it."""
    cmd = _get_command(context)
    if "session_id" in args:
        return {
            "status": "error",
            "message": "session_id must come from trusted Hades context.",
            "engagement_id": "",
            "snapshot_hash": "",
        }
    session_id = context.get("session_id")
    if not isinstance(session_id, str) or not session_id.strip():
        return {
            "status": "error",
            "message": "A trusted Hades session_id is required.",
            "engagement_id": "",
            "snapshot_hash": "",
        }
    try:
        # Ignore the two legacy model-supplied fields for callers upgrading
        # from 0.1. They are never authority; Hades owns the confirmation.
        contract_inputs = dict(args)
        contract_inputs.pop("authorization_attested", None)
        contract_inputs.pop("disclaimer_version", None)
        validated = PrepareEngagementInput.model_validate(contract_inputs)
    except ValidationError as exc:
        return {
            "status": "error",
            "message": f"Invalid engagement answers: {exc}",
            "engagement_id": "",
            "snapshot_hash": "",
        }

    answers = validated.model_dump()
    default_rate, default_concurrency = intensity_default_limits(answers["intensity"])
    answers["max_requests_per_second"] = default_rate
    answers["max_concurrent_checks"] = default_concurrency
    contract_summary = {
        "authorization": "user_attests_authorized_lab_or_ctf_use",
        "disclaimer_version": CURRENT_DISCLAIMER_VERSION,
        "disclaimer": (
            "Use only against systems you own or are explicitly authorized "
            "to test. Ariadne guardrails remain active in every mode."
        ),
        "profile": answers["profile"],
        "target": answers["target_host"],
        "objectives": answers["objectives"],
        "autonomy": answers["autonomy"],
        "intensity": answers["intensity"],
        "exclusions": answers["exclusions"],
        "time_window_minutes": answers["time_window_minutes"],
        "effective_limits": {
            "max_requests_per_second": default_rate,
            "max_concurrent_checks": default_concurrency,
        },
    }
    gateway = context.get("consent_gateway")
    request_contract = getattr(gateway, "request_contract", None)
    if not callable(request_contract):
        return {
            "status": "blocked",
            "message": "Trusted Hades contract confirmation UI is unavailable.",
            "engagement_id": "",
            "snapshot_hash": "",
        }
    try:
        decision = await request_contract(contract_summary)
    except Exception:
        decision = ConsentDecision.UNAVAILABLE
    if decision is not ConsentDecision.ACCEPT:
        label = (
            decision.value
            if isinstance(decision, ConsentDecision)
            else ConsentDecision.UNAVAILABLE.value
        )
        return {
            "status": "blocked",
            "message": f"Engagement contract was not confirmed ({label}).",
            "engagement_id": "",
            "snapshot_hash": "",
        }
    answers["authorization_attested"] = True
    answers["disclaimer_version"] = CURRENT_DISCLAIMER_VERSION
    confirmation_digest = canonical_digest(
        {
            "trusted_session_id": session_id,
            "contract": contract_summary,
        }
    )
    try:
        result = cmd.prepare(
            answers,
            session_id=session_id,
            trusted_confirmation_digest=confirmation_digest,
        )
    except (OSError, PolicyConfigurationError, ValueError, TypeError) as exc:
        return {
            "status": "error",
            "message": f"Engagement was not locked: {exc}",
            "engagement_id": "",
            "snapshot_hash": "",
        }
    return {
        "status": result.status,
        "message": result.message,
        "engagement_id": str(result.engagement_id) if result.engagement_id else "",
        "snapshot_hash": result.snapshot_hash or "",
    }


async def handle_amend_engagement(
    args: dict[str, Any],
    **context: Any,
) -> dict[str, Any]:
    """Resolve a targeted contract boundary and persist a linked version."""
    cmd = _get_command(context)
    if "session_id" in args:
        return {"status": "error", "message": "session_id is Hades-owned."}
    session_id = context.get("session_id", "")
    binding = _get_binding(cmd, session_id)
    if binding is None or binding["engagement_id"] is None:
        return {"status": "error", "message": "No active engagement."}
    try:
        validated = AmendEngagementInput.model_validate(args)
    except ValidationError as exc:
        return {"status": "error", "message": f"Invalid amendment: {exc}"}
    handle = _get_run_handle(cmd.store, binding["engagement_id"])
    if handle is None:
        return {"status": "error", "message": "Active engagement is unavailable."}
    changes = validated.model_dump()
    candidate_id = changes.get("candidate_id", "")
    if candidate_id and any(
        event.get("event_type") == "scope_candidate_blocked"
        and event.get("payload", {}).get("candidate_id") == candidate_id
        for event in cmd.store.read_events(handle)
    ):
        return {
            "status": "blocked",
            "boundary": "scope_candidate_declined",
            "message": (
                "This scope candidate was already declined. Continue with "
                "alternative in-scope branches."
            ),
        }
    summary = {
        "base_snapshot_hash": handle.snapshot.snapshot_hash,
        "base_revision": handle.snapshot.revision,
        "add_targets": changes["add_targets"],
        "objectives": changes["objectives"],
        "intensity": changes["intensity"],
        "exclusions": changes["exclusions"],
        "candidate_id": candidate_id,
        "reason": changes["reason"],
    }
    request_amendment = getattr(
        context.get("consent_gateway"),
        "request_amendment",
        None,
    )
    if not callable(request_amendment):
        return {
            "status": "blocked",
            "boundary": "amendment_consent_unavailable",
            "message": "Trusted Hades amendment confirmation UI is unavailable.",
        }
    try:
        decision = await request_amendment(summary)
    except Exception:
        decision = ConsentDecision.UNAVAILABLE
    if decision is not ConsentDecision.ACCEPT:
        if candidate_id:
            from ariadne.store.run_store import Event

            cmd.store.append_event(
                handle,
                Event(
                    event_type="scope_candidate_blocked",
                    payload={
                        "candidate_id": candidate_id,
                        "target": (changes["add_targets"][0] if changes["add_targets"] else ""),
                        "reason": changes["reason"],
                        "decision": (
                            decision.value
                            if isinstance(decision, ConsentDecision)
                            else "unavailable"
                        ),
                    },
                    timestamp=datetime.now(UTC),
                ),
            )
        return {
            "status": "blocked",
            "boundary": "amendment_declined",
            "message": (
                "Amendment declined; the branch is recorded as blocked. "
                "Continue with alternative in-scope branches."
            ),
        }
    digest = canonical_digest({"trusted_session_id": session_id, "amendment": summary})
    try:
        result = cmd.amend(
            changes,
            session_id=session_id,
            trusted_confirmation_digest=digest,
            expected_snapshot_hash=summary["base_snapshot_hash"],
            expected_revision=summary["base_revision"],
        )
    except (OSError, ValueError, TypeError) as exc:
        return {"status": "error", "message": f"Amendment failed: {exc}"}
    return {
        "status": result.status,
        "engagement_id": str(result.engagement_id or ""),
        "snapshot_hash": result.snapshot_hash or "",
        "message": result.message,
    }


async def handle_status(args: dict[str, Any], **context: Any) -> dict[str, Any]:
    """Return current engagement status.

    Checks the ``AriadneCommand`` for any active engagement in the
    ledger.  Otherwise falls back to the generic non-active response.
    """
    if "session_id" in args:
        return {
            "status": "error",
            "message": "session_id must come from trusted Hades context.",
        }
    try:
        cmd = _get_command(context)
        session_id = context.get("session_id", "")
        if cmd.get_session_binding(session_id) is not None:
            return {
                "status": "active",
                "message": "Active engagement found for this session.",
            }
    except (ValueError, TypeError):
        pass

    return {
        "status": "no_active_engagement",
        "message": "No active engagement.",
    }


async def handle_propose_plan(args: dict[str, Any], **context: Any) -> dict[str, Any]:
    """Propose a bounded action plan.

    Validates:
    - Active engagement binding exists for this session
    - Provided snapshot_hash matches the bound snapshot
    - All playbook preconditions (capabilities allowed, adapters registered)

    Builds a PlanningContext from the engagement snapshot, selects an
    eligible playbook, and constructs a bounded Plan. The plan is recorded in
    the command ledger. Routine curated, in-policy plans are durably
    auto-approved; only explicit manual boundaries await trusted Hades consent.
    """
    cmd = _get_command(context)
    if "session_id" in args:
        return {
            "status": "error",
            "message": "session_id must come from trusted Hades context.",
            "plan_id": "",
        }
    session_id = context.get("session_id", "")
    input_session_id = session_id

    # 1. Check active engagement FIRST (before getting planner/catalog)
    binding_info = _get_binding(cmd, input_session_id)
    if binding_info is None:
        return {
            "status": "error",
            "message": "No active engagement. Please bind an engagement first.",
            "plan_id": "",
        }

    planner = _get_planner(context)
    catalog = _get_catalog(context)

    snapshot_hash = args.get("snapshot_hash", "")
    hypothesis_str = args.get("hypothesis", "")

    # 2. Validate snapshot hash matches binding
    if snapshot_hash != binding_info["snapshot_hash"]:
        return {
            "status": "error",
            "message": (
                f"Snapshot hash mismatch: provided {snapshot_hash}, "
                f"expected {binding_info['snapshot_hash']}"
            ),
            "plan_id": "",
        }

    # 3. Rebuild the EngagementSnapshot from the store
    engagement_id = binding_info["engagement_id"]
    if not engagement_id:
        return {
            "status": "error",
            "message": "No engagement id in binding.",
            "plan_id": "",
        }

    run_handle = _get_run_handle(cmd.store, engagement_id)
    if run_handle is None:
        return {
            "status": "error",
            "message": "Engagement snapshot not found in store.",
            "plan_id": "",
        }

    snapshot = run_handle.snapshot

    # 4. Determine current engagement state from the run store
    state, observations = _determine_engagement_state(cmd.store, run_handle)

    # Also extract executed playbooks from events
    events = cmd.store.read_events(run_handle)
    executed_playbooks: set[str] = set()
    for evt in events:
        if evt.get("event_type") == "plan_executed":
            payload = evt.get("payload", {})
            if payload.get("status") in (
                "executed",
                "success",
                "failed",
                "error",
                "failure",
            ):
                pb_id = payload.get("playbook_id", "")
                if pb_id:
                    executed_playbooks.add(pb_id)

    # Use the first target as the hypothesis target
    first_target = snapshot.targets[0] if snapshot.targets else TargetSpec(host="unknown")

    from uuid import uuid4

    hypothesis = Hypothesis(
        hypothesis_id=uuid4(),
        target=first_target,
        statement=hypothesis_str or "Automated discovery playbook",
        confidence=0.5,
    )

    # Build minimal assets (target is in-scope)
    assets = tuple(
        Asset(
            asset_id=uuid4(),
            target=t,
            status=AssetStatus.IN_SCOPE,
        )
        for t in snapshot.targets
    )

    # Load effective policy from the store's engagement.lock.yaml
    try:
        effective_policy = _load_engagement_policy(snapshot)
    except PolicyConfigurationError as exc:
        return {
            "status": "error",
            "message": (
                f"Policy provenance check failed: {exc}. "
                "Create a new snapshot or explicit scope amendment."
            ),
            "plan_id": "",
        }

    planning_context = PlanningContext(
        snapshot=snapshot,
        state=state,
        observations=observations,
        assets=assets,
        effective_policy=effective_policy,
        hypothesis=hypothesis,
        now=datetime.now(UTC),
    )

    # 5. Find eligible playbooks and build the first plan
    eligible = catalog.eligible(planning_context)
    unresearched_fingerprint = _latest_service_fingerprint(
        observations,
        first_target,
    )
    eligible = tuple(
        playbook
        for playbook in eligible
        if playbook.id not in executed_playbooks
        or (
            playbook.id == "research.service-vulnerability.v1"
            and unresearched_fingerprint is not None
        )
    )
    last_completed_playbook = next(
        (
            event.get("payload", {}).get("playbook_id")
            for event in reversed(events)
            if event.get("event_type") == "plan_executed"
            and event.get("payload", {}).get("status") in {"executed", "success"}
        ),
        None,
    )
    if last_completed_playbook in catalog.playbooks:
        allowed_next = catalog.playbooks[last_completed_playbook].next_playbooks
        preferred = tuple(
            playbook for playbook in eligible if playbook.id in allowed_next
        )
        if preferred:
            eligible = preferred
    excluded = tuple(
        (playbook, conflict)
        for playbook in eligible
        if (conflict := _exclusion_conflict(playbook, snapshot.exclusions)) is not None
    )
    eligible = tuple(
        playbook
        for playbook in eligible
        if _exclusion_conflict(playbook, snapshot.exclusions) is None
    )
    if not eligible:
        if excluded:
            return {
                "status": "blocked",
                "boundary": "contract_exclusion",
                "message": (
                    "Eligible work conflicts with an explicit contract "
                    f"exclusion: {excluded[0][1]!r}. An amendment is required "
                    "to change that exclusion."
                ),
                "plan_id": "",
            }
        # No eligible playbooks — check if any playbook exists at all
        if not catalog.playbooks:
            return {
                "status": "error",
                "message": "No playbooks configured in the workflow catalog.",
                "plan_id": "",
            }
        return {
            "status": "error",
            "message": (
                "No eligible playbooks for the current engagement state and evidence. "
                "Try collecting more evidence first."
            ),
            "plan_id": "",
        }

    playbook = eligible[0]
    terminal_plan_ids = {
        event.get("payload", {}).get("plan_id")
        for event in events
        if event.get("event_type")
        in {
            "plan_executed",
            "plan_rejected",
        }
    }
    for event in reversed(events):
        if event.get("event_type") != "plan_proposed":
            continue
        payload = event.get("payload", {})
        if (
            payload.get("snapshot_hash") == snapshot.snapshot_hash
            and payload.get("playbook_id") == playbook.id
            and payload.get("plan_id") not in terminal_plan_ids
        ):
            return {
                "status": "blocked",
                "boundary": "plan_in_flight",
                "message": (
                    "An equivalent plan is already pending or executing; "
                    "Ariadne will not duplicate it or reset its limits."
                ),
                "plan_id": payload.get("plan_id", ""),
            }
    try:
        plan = planner.build(playbook.id, planning_context)
    except WorkflowConfigurationError as exc:
        return {
            "status": "error",
            "message": f"Plan construction failed: {exc}",
            "plan_id": "",
        }

    if any(
        action.adapter == "research"
        and action.operation == "investigate"
        and action.inputs.get("full_chain")
        for action in plan.actions
    ):
        fingerprint = _latest_service_fingerprint(
            observations,
            plan.target,
        )
        if fingerprint is None:
            return {
                "status": "blocked",
                "boundary": "missing_evidence",
                "message": (
                    "Full vulnerability research requires a real service "
                    "fingerprint with a product name."
                ),
                "plan_id": "",
            }
        plan = plan.model_copy(
            update={
                "actions": tuple(
                    action.model_copy(
                        update={
                            "inputs": {
                                **action.inputs,
                                **fingerprint,
                            },
                        }
                    )
                    if action.adapter == "research" and action.operation == "investigate"
                    else action
                    for action in plan.actions
                ),
            }
        )

    if any(
        action.adapter == "httpx"
        and action.operation == "scan"
        and not action.inputs.get("ports")
        for action in plan.actions
    ):
        web_ports = _observed_web_ports(observations, plan.target)
        if not web_ports:
            return {
                "status": "blocked",
                "boundary": "missing_evidence",
                "message": (
                    "HTTP probing requires a target-bound port observed as an "
                    "HTTP service."
                ),
                "plan_id": "",
            }
        plan = plan.model_copy(
            update={
                "actions": tuple(
                    action.model_copy(
                        update={
                            "inputs": {
                                **action.inputs,
                                "ports": list(web_ports),
                            },
                        }
                    )
                    if action.adapter == "httpx"
                    and action.operation == "scan"
                    and not action.inputs.get("ports")
                    else action
                    for action in plan.actions
                ),
            }
        )

    validated_candidates = _validated_nuclei_candidates(
        events,
        run_handle,
        plan.target.host,
    )
    if validated_candidates:
        plan = plan.model_copy(
            update={
                "actions": tuple(
                    action.model_copy(
                        update={
                            "inputs": {
                                **action.inputs,
                                "validated_candidates": [
                                    dict(candidate) for candidate in validated_candidates
                                ],
                            },
                        }
                    )
                    if action.adapter == "nuclei" and action.operation == "scan"
                    else action
                    for action in plan.actions
                ),
            }
        )

    if any(action.adapter == "metasploit" for action in plan.actions):
        metasploit_candidates = _validated_metasploit_candidates(
            events,
            run_handle,
            plan.target.host,
        )
        if not metasploit_candidates:
            return {
                "status": "blocked",
                "boundary": "validated_metasploit_candidate",
                "message": (
                    "Metasploit requires a compatible module from persisted validated research."
                ),
                "plan_id": "",
            }
        selected_candidate = metasploit_candidates[0]
        selected_module = str(selected_candidate["module"])
        check_evidence_id = _metasploit_check_evidence(
            events,
            run_handle,
            target=plan.target.host,
            module=selected_module,
        )
        if (
            any(
                action.adapter == "metasploit" and action.operation == "run_module"
                for action in plan.actions
            )
            and check_evidence_id is None
        ):
            return {
                "status": "blocked",
                "boundary": "metasploit_check",
                "message": (
                    "Metasploit use requires persisted proof that the exact "
                    "module check reported the target vulnerable."
                ),
                "plan_id": "",
            }
        plan = plan.model_copy(
            update={
                "actions": tuple(
                    action.model_copy(
                        update={
                            "inputs": {
                                **action.inputs,
                                "module": selected_module,
                                "rhost": plan.target.host,
                                **(
                                    {"rport": selected_candidate["port"]}
                                    if isinstance(selected_candidate.get("port"), int)
                                    else {}
                                ),
                                "validated_candidate": dict(selected_candidate),
                                **(
                                    {
                                        "check_status": "vulnerable",
                                        "check_evidence_id": check_evidence_id,
                                    }
                                    if action.operation == "run_module"
                                    and check_evidence_id is not None
                                    else {}
                                ),
                            },
                        }
                    )
                    if action.adapter == "metasploit"
                    else action
                    for action in plan.actions
                ),
            }
        )

    # 6. Persist the proposal before exposing it through the in-memory ledger.
    from ariadne.store.run_store import Event

    capabilities = sorted(playbook.capabilities)
    approval_correlation_id = uuid4().hex
    proposal_payload = {
        "plan_id": plan.plan_id,
        "playbook_id": plan.playbook_id,
        "snapshot_hash": snapshot_hash,
        "session_id": input_session_id,
        "trusted_session_id": input_session_id,
        "plan": plan.model_dump(mode="json"),
        "expires_at": plan.expires_at.isoformat(),
        "approval_state": "pending",
        "approval_correlation_id": approval_correlation_id,
        "autonomy": snapshot.autonomy.value,
        "capabilities": capabilities,
        "requires_manual_approval": plan.requires_manual_approval,
        "manual_capabilities": list(plan.manual_capabilities),
        "approval_reasons": list(plan.approval_reasons),
    }
    try:
        cmd.store.append_event(
            run_handle,
            Event(
                event_type="plan_proposed",
                payload=proposal_payload,
                timestamp=datetime.now(UTC),
            ),
        )
    except Exception as exc:
        # The store is the authorization ledger. Any persistence failure,
        # regardless of backend exception type, must fail closed.
        return {
            "status": "error",
            "message": f"Could not persist plan proposal: {exc}",
            "plan_id": plan.plan_id,
        }

    # 7. Record the plan in the command's plan ledger, initially unapproved.
    cmd.add_plan(
        plan,
        snapshot_hash,
        input_session_id,
        approval_correlation_id=approval_correlation_id,
    )

    should_auto_approve = not plan.requires_manual_approval and not plan.manual_capabilities
    if should_auto_approve:
        approved_at = datetime.now(UTC)
        try:
            cmd.store.append_event(
                run_handle,
                Event(
                    event_type="plan_auto_approved",
                    payload={
                        "plan_id": plan.plan_id,
                        "snapshot_hash": snapshot_hash,
                        "trusted_session_id": input_session_id,
                        "approval_correlation_id": approval_correlation_id,
                        "approval_state": "approved",
                        "approval_source": "curated_in_policy",
                        "approved_at": approved_at.isoformat(),
                        "capabilities": capabilities,
                        "reason": "curated_in_policy_no_manual_boundary",
                    },
                    timestamp=approved_at,
                ),
            )
        except Exception as exc:
            # Never mutate the in-memory approval record unless the durable
            # event chain accepted the approval first.
            return {
                "status": "error",
                "message": (
                    f"Could not persist automatic approval; the plan remains unapproved: {exc}"
                ),
                "plan_id": plan.plan_id,
            }
        cmd.auto_approve_plan(plan.plan_id)

    approval_status = "auto_approved" if should_auto_approve else "awaiting_user_approval"
    message = (
        f"Plan {plan.plan_id[:8]} auto-approved for continuous execution. "
        "Call ariadne_execute_plan now; do not request /ariadne approve."
        if should_auto_approve
        else (
            f"Plan {plan.plan_id[:8]} proposed with {len(plan.actions)} action(s) "
            f"for target {plan.target.host}. "
            "Call ariadne_execute_plan; Hades will request trusted user "
            "consent in the current UI before execution."
        )
    )

    return {
        "status": "plan_auto_approved" if should_auto_approve else "plan_proposed",
        "approval_status": approval_status,
        "plan_id": plan.plan_id,
        "playbook_id": plan.playbook_id,
        "actions": [
            {
                "adapter": a.adapter,
                "operation": a.operation,
            }
            for a in plan.actions
        ],
        "target": plan.target.host,
        "hypothesis": plan.hypothesis,
        "expires_at": plan.expires_at.isoformat(),
        "limits": plan.limits.model_dump(mode="json"),
        "requires_manual_approval": plan.requires_manual_approval,
        "manual_capabilities": list(plan.manual_capabilities),
        "approval_reasons": list(plan.approval_reasons),
        "message": message,
    }


async def handle_execute_plan(args: dict[str, Any], **context: Any) -> dict[str, Any]:
    """Execute an approved plan.

    Validates:
    - Active engagement binding exists for this session
    - Plan exists in the ledger
    - Plan has been manually or durably automatically approved
    - Plan has not expired

    For this vertical slice without real adapters, records the
    execution as an evidence event in the store.
    """
    cmd = _get_command(context)
    if "session_id" in args:
        return {
            "status": "error",
            "message": "session_id must come from trusted Hades context.",
            "plan_id": args.get("plan_id", ""),
        }
    session_id = context.get("session_id", "")
    input_session_id = session_id
    plan_id = args.get("plan_id", "")

    # 1. Check active engagement
    binding_info = _get_binding(cmd, input_session_id)
    if binding_info is None:
        return {
            "status": "error",
            "message": "No active engagement. Please bind an engagement first.",
            "plan_id": plan_id,
        }

    # 2. Check plan exists
    record = cmd.get_plan_record(plan_id)
    if record is None:
        record = cmd.get_plan_record(
            plan_id,
            trusted_session_id=input_session_id,
        )
    if record is None:
        return {
            "status": "error",
            "message": f"Unknown plan: {plan_id!r}",
            "plan_id": plan_id,
        }

    # 3. Bind the plan to its trusted session and current immutable snapshot.
    if record.session_id != input_session_id:
        return {
            "status": "error",
            "message": "Plan belongs to a different trusted Hades session.",
            "plan_id": plan_id,
        }

    engagement_id = binding_info["engagement_id"]
    if not engagement_id:
        return {
            "status": "error",
            "message": "No engagement id in binding.",
            "plan_id": plan_id,
        }
    run_handle = _get_run_handle(cmd.store, engagement_id)
    if run_handle is None:
        return {
            "status": "error",
            "message": "Engagement snapshot not found in store.",
            "plan_id": plan_id,
        }

    from ariadne.core.engagement import calculate_snapshot_hash
    from ariadne.store.integrity import verify_run

    active_hash = binding_info["snapshot_hash"]
    persisted_hash = run_handle.snapshot.snapshot_hash
    if (
        record.snapshot_hash != active_hash
        or record.plan.snapshot_hash != active_hash
        or persisted_hash != active_hash
        or calculate_snapshot_hash(run_handle.snapshot) != persisted_hash
        or not verify_run(run_handle.path).valid
    ):
        return {
            "status": "error",
            "message": "Plan snapshot is stale or the active run failed integrity checks.",
            "plan_id": plan_id,
        }

    # 4. Re-load the frozen policy sources and re-authorize capabilities.
    try:
        execution_policy = _load_engagement_policy(run_handle.snapshot)
    except PolicyConfigurationError as exc:
        return {
            "status": "error",
            "message": (
                f"Policy provenance check failed: {exc}. "
                "Create a new snapshot or explicit scope amendment."
            ),
            "plan_id": plan_id,
        }
    if any(
        capability not in execution_policy.capabilities
        or not execution_policy.capabilities[capability].allowed
        for capability in record.plan.capabilities
    ):
        return {
            "status": "error",
            "message": "Plan capabilities are no longer authorized by effective policy.",
            "plan_id": plan_id,
        }

    # 5. A rejection/revocation is terminal and always wins over approval.
    if record.rejected:
        return {
            "status": "blocked",
            "message": (
                f"Plan {plan_id[:8]} was rejected or revoked and cannot execute. "
                "Propose a new plan if the user wants to continue."
            ),
            "plan_id": plan_id,
        }

    # 6. Check plan has not expired before asking the user for consent.
    if cmd.is_plan_expired(plan_id):
        return {
            "status": "error",
            "message": f"Plan {plan_id[:8]} has expired. Propose a new plan.",
            "plan_id": plan_id,
        }

    # 7. Resolve pending approval in the trusted Hades UI.  This path is
    # independent of model autonomy/--yolo and persists the decision first.
    if not record.approved:
        try:
            decision = await _get_consent_gateway(context).request_plan(record.plan)
        except Exception:
            decision = ConsentDecision.UNAVAILABLE
        if decision == ConsentDecision.ACCEPT:
            response = cmd.approve_plan(
                plan_id,
                trusted_session_id=input_session_id,
                decision_channel="hades_elicitation",
            )
            record = cmd.get_plan_record(plan_id)
            if record is None or not record.approved or record.rejected:
                return {
                    "status": "blocked",
                    "message": (
                        f"User consent was accepted but durable approval failed: {response}"
                    ),
                    "plan_id": plan_id,
                }
        elif decision in {
            ConsentDecision.DECLINE,
            ConsentDecision.CANCEL,
        }:
            reason = "declined" if decision == ConsentDecision.DECLINE else "cancelled"
            response = cmd.reject_plan(
                plan_id,
                trusted_session_id=input_session_id,
                decision_channel="hades_elicitation",
                reason=f"user_{reason}",
            )
            record = cmd.get_plan_record(plan_id)
            if record is None or not record.rejected:
                return {
                    "status": "blocked",
                    "message": (f"Consent was {reason}; durable rejection failed: {response}"),
                    "plan_id": plan_id,
                }
            return {
                "status": "blocked",
                "message": (
                    f"User consent was {reason}; plan {plan_id[:8]} is "
                    "durably rejected and was not executed."
                ),
                "plan_id": plan_id,
            }
        else:
            return {
                "status": "blocked",
                "message": (
                    "Trusted Hades approval consent UI is unavailable; "
                    "the pending plan was not executed."
                ),
                "plan_id": plan_id,
            }

    # 8. Atomically reload and claim the authoritative durable plan before
    # adapter.plan() can produce any side effect.
    claim = cmd.claim_plan_execution(
        plan_id,
        trusted_session_id=input_session_id,
    )
    if not claim.claimed or claim.record is None:
        return {
            "status": "blocked",
            "message": (f"Plan {plan_id[:8]} could not be execution-claimed: {claim.message}"),
            "plan_id": plan_id,
        }
    record = claim.record

    # 9. Execute plan actions via registered adapters
    registry = _get_adapter_registry(context)
    runtime = _get_runtime(context)

    from ariadne.adapters.base import (
        PlannedAction as AdapterPlannedAction,
    )
    from ariadne.store.run_store import Event

    now = datetime.now(UTC)
    actions_executed = 0
    actions_failed = 0
    evidence_artifacts: list[dict[str, Any]] = []

    try:
        execution_contracts = _get_execution_contract_registry(context)
        execution_coordinator = _get_execution_coordinator(context)
    except TypeError:
        return {
            "status": "blocked",
            "message": "Trusted execution boundary is unavailable.",
            "plan_id": plan_id,
            "actions_executed": 0,
            "actions_failed": len(record.plan.actions),
            "evidence_artifacts": [],
        }
    for action_index, action in enumerate(record.plan.actions):
        envelope = ExecutionEnvelope.from_plan(
            record.plan,
            action_index=action_index,
            run_root=run_handle.path,
            policy_digests=execution_policy.source_digests,
        )
        envelope.verify_action(action)
        contract = execution_contracts.get(
            action.adapter,
            action.operation,
        )
        if contract is None:
            actions_failed += 1
            cmd.store.append_event(
                run_handle,
                Event(
                    event_type="process_authorization_blocked",
                    payload={
                        "plan_id": plan_id,
                        "action_index": action_index,
                        "action_digest": envelope.action_digest,
                        "adapter": action.adapter,
                        "operation": action.operation,
                        "target": record.plan.target.host,
                        "policy_source_digests": list(execution_policy.source_digests),
                        "reason_code": AuthorizationReason.CONTRACT_MISSING,
                    },
                    timestamp=datetime.now(UTC),
                ),
            )
            continue

        adapter = registry.get(action.adapter)
        if adapter is None:
            actions_failed += 1
            # Record a failed execution event
            cmd.store.append_event(
                run_handle,
                Event(
                    event_type="plan_executed",
                    payload={
                        "plan_id": plan_id,
                        "playbook_id": record.plan.playbook_id,
                        "action": action.adapter,
                        "operation": action.operation,
                        "status": "failed",
                        "error": f"Adapter {action.adapter!r} not registered",
                        "target": record.plan.target.host,
                    },
                    timestamp=now,
                ),
            )
            continue
        try:
            execution_contracts.verify_adapter(contract, adapter)
        except Exception:
            actions_failed += 1
            cmd.store.append_event(
                run_handle,
                Event(
                    event_type="process_authorization_blocked",
                    payload={
                        "plan_id": plan_id,
                        "action_index": action_index,
                        "action_digest": envelope.action_digest,
                        "adapter": action.adapter,
                        "operation": action.operation,
                        "target": record.plan.target.host,
                        "policy_source_digests": list(execution_policy.source_digests),
                        "reason_code": (AuthorizationReason.IMPLEMENTATION_MISMATCH),
                    },
                    timestamp=datetime.now(UTC),
                ),
            )
            continue

        tool_card_verifier = context.get("tool_card_verifier")
        pending_tool_verification = None

        # Build adapter context and planned action
        adapter_ctx = AdapterContext(
            target=record.plan.target,
            snapshot_hash=record.snapshot_hash,
            engagement_id=engagement_id,
            adapter_name=action.adapter,
            run_root=run_handle.path,
            cwd=run_handle.path,
            limits=record.plan.limits,
            capabilities=record.plan.capabilities,
            action_digest=envelope.action_digest,
        )

        planned_action = AdapterPlannedAction(
            operation=action.operation,
            inputs=deepcopy(action.inputs),
        )

        try:
            # Generate ProcessSpec via adapter.plan() — argv at execution time
            process_spec = adapter.plan(planned_action, adapter_ctx)
            envelope.verify_action(action)
            action_runtime = runtime
            if isinstance(runtime, ProcessRunner):
                executable = process_spec.argv[0]
                runtime_choice = choose_runtime(
                    record.plan.capabilities,
                    local_tool_available=shutil.which(executable) is not None,
                    kali_tool_available=(executable in curated_kali_executables()),
                    requires_compatibility=action.adapter == "nuclei",
                )
                if runtime_choice is RuntimeChoice.BLOCKED:
                    raise KaliRuntimeUnavailableError(
                        f"{executable} is unavailable locally and is not "
                        "declared in the curated Kali manifest."
                    )
                factory = context.get("kali_runtime_factory")
                if action.adapter == "research" and callable(factory):
                    action_runtime = LocalFirstRuntime(
                        local_runtime=runtime,
                        kali_runtime=factory(
                            run_handle.snapshot,
                            run_handle.path,
                        ),
                        kali_executables=curated_kali_executables(),
                    )
                elif runtime_choice is RuntimeChoice.KALI:
                    if not callable(factory):
                        raise KaliRuntimeUnavailableError(
                            "The on-demand Kali runtime is not configured."
                        )
                    action_runtime = factory(
                        run_handle.snapshot,
                        run_handle.path,
                    )

            def audit_block(
                reason: AuthorizationReason,
                blocked_spec: Any,
                attempts: int,
                *,
                _action_index: int = action_index,
                _action_digest: str = envelope.action_digest,
                _adapter: str = action.adapter,
                _operation: str = action.operation,
            ) -> None:
                cmd.store.append_event(
                    run_handle,
                    Event(
                        event_type="process_authorization_blocked",
                        payload={
                            "plan_id": plan_id,
                            "action_index": _action_index,
                            "action_digest": _action_digest,
                            "adapter": _adapter,
                            "operation": _operation,
                            "target": record.plan.target.host,
                            "policy_source_digests": list(execution_policy.source_digests),
                            "reason_code": reason,
                            "attempts_consumed": attempts,
                            "process_spec_digest": (
                                canonical_digest(blocked_spec) if blocked_spec is not None else None
                            ),
                        },
                        timestamp=datetime.now(UTC),
                    ),
                )

            guarded_runtime = GuardedRuntime(
                runtime=action_runtime,
                envelope=envelope,
                contract=contract,
                policy=execution_policy,
                coordinator=execution_coordinator,
                on_block=audit_block,
            )
            guarded_runtime.authorize_initial(process_spec)

            if isinstance(tool_card_verifier, ToolCardVerifier):
                allowed_policy = frozenset(
                    capability
                    for capability, rule in execution_policy.capabilities.items()
                    if rule.allowed
                )
                try:
                    runtime_inspection = None
                    if isinstance(
                        action_runtime,
                        (OnDemandKaliRuntime, LocalFirstRuntime),
                    ):
                        inspect_tool = getattr(
                            action_runtime,
                            "inspect_tool",
                            None,
                        )
                        if not callable(inspect_tool):
                            raise ToolVerificationBlockedError(
                                "Kali runtime cannot inspect the planned tool"
                            )
                        runtime_inspection = await inspect_tool(process_spec.argv[0])
                    pending_tool_verification = _inspect_planned_tool(
                        verifier=tool_card_verifier,
                        process_argv=process_spec.argv,
                        action_inputs=action.inputs,
                        allowed_policy=allowed_policy,
                        required_policy=record.plan.capabilities,
                        inspection=runtime_inspection,
                    )
                except ToolVerificationBlockedError as exc:
                    actions_failed += 1
                    cmd.store.append_event(
                        run_handle,
                        Event(
                            event_type="tool_documentation_blocked",
                            payload={
                                "plan_id": plan_id,
                                "tool_card_id": _tool_id_for_executable(process_spec.argv[0]),
                                "adapter": action.adapter,
                                "reason": str(exc),
                                "next_boundary": "kali_or_tool_availability",
                            },
                            timestamp=datetime.now(UTC),
                        ),
                    )
                    return {
                        "status": "blocked",
                        "boundary": "tool_documentation",
                        "plan_id": plan_id,
                        "tool_card_id": _tool_id_for_executable(process_spec.argv[0]),
                        "message": str(exc),
                        "actions_executed": actions_executed,
                        "actions_failed": actions_failed,
                        "evidence_artifacts": evidence_artifacts,
                    }

            # Execute via runtime
            process_result = await adapter.execute(
                process_spec,
                guarded_runtime,
            )

            # Parse observations from output
            parse_for_spec = getattr(adapter, "parse_for_spec", None)
            parse_for_target = getattr(adapter, "parse_for_target", None)
            parse_for_operation = getattr(
                adapter,
                "parse_for_operation",
                None,
            )
            if callable(parse_for_spec):
                observations = parse_for_spec(
                    process_result,
                    record.plan.target,
                    process_spec,
                )
            elif callable(parse_for_target):
                observations = parse_for_target(
                    process_result,
                    record.plan.target,
                )
            elif callable(parse_for_operation):
                observations = parse_for_operation(
                    process_result,
                    action.operation,
                )
            else:
                observations = adapter.parse(process_result)
            if any(
                _is_simulated_evidence(
                    observation.source,
                    dict(observation.data),
                )
                for observation in observations
            ):
                raise AdapterPolicyError("Simulated observations are forbidden in operational runs")
            candidate_observations = [
                observation
                for observation in observations
                if observation.target != record.plan.target
                and discovered_asset_status(
                    observation.target,
                    record.plan.target,
                )
                is AssetStatus.SCOPE_CANDIDATE
            ]
            if candidate_observations:
                local_transcript = process_result.stdout.encode(
                    "utf-8",
                    errors="replace",
                )
                candidate_artifact = cmd.store.add_bytes(
                    run_handle,
                    local_transcript,
                    ArtifactInput(
                        media_type="text/plain",
                        evidence_type="scope_candidate",
                        source_name=f"{action.adapter}:{action.operation}",
                        maximum_bytes=max(len(local_transcript), 1),
                    ),
                )
                relation = (
                    "route"
                    if action.adapter == "pivot"
                    else "redirect"
                    if action.adapter == "httpx"
                    else "lateral_host"
                )
                for observation in candidate_observations:
                    reason = str(
                        observation.data.get("summary")
                        or observation.data.get("type")
                        or f"{action.adapter} discovered a distinct host"
                    )
                    candidate = create_scope_candidate(
                        target=observation.target,
                        source_target=record.plan.target,
                        reason=reason,
                        evidence_ids=(str(candidate_artifact.artifact_id),),
                        relation=relation,
                    )
                    cmd.store.append_event(
                        run_handle,
                        Event(
                            event_type="scope_candidate_discovered",
                            payload={
                                "candidate_id": str(candidate.candidate_id),
                                "target": candidate.target.host,
                                "source_target": candidate.source_target.host,
                                "reason": candidate.reason,
                                "relation": candidate.relation,
                                "evidence_artifact": (candidate_artifact.path.name),
                                "status": candidate.status.value,
                            },
                            timestamp=datetime.now(UTC),
                        ),
                    )
                candidate_payload = next(
                    event.get("payload", {})
                    for event in reversed(cmd.store.read_events(run_handle))
                    if event.get("event_type") == "scope_candidate_discovered"
                )
                cmd.store.append_event(
                    run_handle,
                    Event(
                        event_type="scope_amendment_required",
                        payload={
                            "plan_id": plan_id,
                            "playbook_id": record.plan.playbook_id,
                            "adapter": action.adapter,
                            "operation": action.operation,
                            "target": candidate_payload.get("target", ""),
                            "candidate_id": candidate_payload.get("candidate_id", ""),
                            "reason": candidate_payload.get("reason", ""),
                        },
                        timestamp=datetime.now(UTC),
                    ),
                )
                return {
                    "status": "blocked",
                    "boundary": "scope_amendment",
                    "plan_id": plan_id,
                    "candidate": candidate_payload,
                    "message": (
                        f"Discovered distinct target "
                        f"{candidate_payload.get('target')} from local evidence. "
                        "A targeted amendment is required before sending traffic."
                    ),
                    "actions_executed": actions_executed,
                    "actions_failed": actions_failed,
                    "evidence_artifacts": evidence_artifacts,
                }

            # Classify the result
            classification = adapter.classify(process_result, observations)
            observations = _typed_progression_observations(
                playbook_id=record.plan.playbook_id,
                adapter=action.adapter,
                operation=action.operation,
                action_inputs=action.inputs,
                target=record.plan.target,
                observations=observations,
                classification_kind=classification.kind,
            )
            if (
                action.adapter == "screenshot"
                and classification.kind == "success"
                and isinstance(action.inputs.get("proof_kind"), str)
                and action.inputs["proof_kind"].strip()
            ):
                observations = tuple(
                    observation.model_copy(
                        update={
                            "data": {
                                **observation.data,
                                "objective_proof": {
                                    "kind": action.inputs["proof_kind"],
                                    "description": str(
                                        action.inputs.get(
                                            "proof_description",
                                            "",
                                        )
                                    ),
                                    "proof": str(observation.data.get("path", "")),
                                },
                            },
                        },
                    )
                    for observation in observations
                )

            # Collect evidence
            evidence_collector = EvidenceCollector(
                snapshot_hash=record.snapshot_hash,
                plan_id=plan_id,
                engagement_id=engagement_id,
            )
            collect_for_spec = getattr(adapter, "collect_for_spec", None)
            if callable(collect_for_spec):
                evidence_results = await collect_for_spec(
                    process_result,
                    process_spec,
                    evidence_collector,
                )
            else:
                evidence_results = await adapter.collect(process_result, evidence_collector)
            transcript = process_result.stdout.encode("utf-8", errors="replace")
            if process_result.stderr:
                transcript += b"\n--- stderr ---\n" + process_result.stderr.encode(
                    "utf-8", errors="replace"
                )
            maximum_bytes = record.plan.limits.max_output_bytes or max(len(transcript), 1)
            stored_transcript = cmd.store.add_bytes(
                run_handle,
                transcript,
                ArtifactInput(
                    media_type="text/plain",
                    evidence_type=action.adapter,
                    source_name=f"{action.adapter}:{action.operation}",
                    maximum_bytes=maximum_bytes,
                ),
            )
            evidence_record = evidence_collector.collect_process(
                process_result,
                {
                    "target": record.plan.target,
                    "engagement_id": engagement_id,
                    "adapter": action.adapter,
                    "argv": process_spec.argv,
                    "source": record.plan.playbook_id,
                    "confidence": classification.confidence,
                },
            )
            if (
                classification.kind == "success"
                and pending_tool_verification is not None
                and isinstance(tool_card_verifier, ToolCardVerifier)
            ):
                verified_tool = tool_card_verifier.promote_after_success(pending_tool_verification)
                cmd.store.append_event(
                    run_handle,
                    Event(
                        event_type="tool_card_runtime_verified",
                        payload={
                            "tool_id": verified_tool.tool_id,
                            "version": verified_tool.version,
                            "card_digest": verified_tool.card_digest,
                            "guidance_source": verified_tool.guidance_source,
                            "verified_at": verified_tool.verified_at,
                        },
                        timestamp=datetime.now(UTC),
                    ),
                )

            # Determine status based on classification
            status = classification.kind
            if classification.kind == "success":
                status = "executed"
                actions_executed += 1
            else:
                actions_failed += 1

            # Record plan_executed event
            cmd.store.append_event(
                run_handle,
                Event(
                    event_type="plan_executed",
                    payload={
                        "plan_id": plan_id,
                        "playbook_id": record.plan.playbook_id,
                        "action": action.adapter,
                        "operation": action.operation,
                        "status": status,
                        "classification": classification.kind,
                        "confidence": classification.confidence,
                        "summary": classification.summary,
                        "target": record.plan.target.host,
                        "exit_code": process_result.exit_code,
                    },
                    timestamp=now,
                ),
            )

            # Record evidence collected events — one per observation
            for obs in observations:
                evidence_artifact = stored_transcript.path.name
                finding_candidate = (
                    _finding_candidate_from_observation(obs)
                    if classification.kind == "success"
                    else None
                )
                evidence_payload: dict[str, Any] = {
                    "artifact": evidence_artifact,
                    "finding": _format_finding(action, obs),
                    "evidence_type": obs.source,
                    "asset": record.plan.target.host,
                    "observation_id": str(obs.observation_id),
                    "adapter": action.adapter,
                    "source": f"{action.adapter}:{action.operation}",
                    "sha256": stored_transcript.sha256,
                    "evidence_id": str(evidence_record.evidence_id),
                    "command_redacted": list(evidence_record.command_redacted),
                    "observation_data": obs.data,
                    "execution_classification": classification.kind,
                }
                if finding_candidate is not None:
                    evidence_payload["finding_id"] = finding_candidate["finding_id"]
                cmd.store.append_event(
                    run_handle,
                    Event(
                        event_type="evidence_collected",
                        payload=evidence_payload,
                        timestamp=now,
                    ),
                )
                if classification.kind == "success":
                    _record_explicit_objective_proof(
                        cmd=cmd,
                        run_handle=run_handle,
                        observation=obs,
                        plan_id=plan_id,
                        playbook_id=record.plan.playbook_id,
                        timestamp=now,
                    )
                if finding_candidate is not None:
                    cmd.store.append_event(
                        run_handle,
                        Event(
                            event_type="finding_candidate",
                            payload={
                                **finding_candidate,
                                "observation_id": str(obs.observation_id),
                                "evidence_artifact": evidence_artifact,
                                "evidence_id": str(evidence_record.evidence_id),
                            },
                            timestamp=now,
                        ),
                    )
                evidence_artifacts.append(
                    {
                        "artifact": evidence_artifact,
                        "observation_id": str(obs.observation_id),
                    }
                )

            # If the adapter produced its own evidence artifacts, record those too
            for ev_result in evidence_results or ():
                artifact_path = run_handle.path / "artifacts" / str(ev_result)
                if ev_result not in ("evidence_collected",) and artifact_path.is_file():
                    cmd.store.append_event(
                        run_handle,
                        Event(
                            event_type="evidence_collected",
                            payload={
                                "artifact": ev_result,
                                "finding": (
                                    f"{action.adapter}:{action.operation} produced {ev_result}"
                                ),
                                "evidence_type": action.adapter,
                                "asset": record.plan.target.host,
                            },
                            timestamp=now,
                        ),
                    )
                    evidence_artifacts.append(
                        {
                            "artifact": ev_result,
                        }
                    )

            if classification.kind == "success":
                playbook = _get_catalog(context).playbooks.get(record.plan.playbook_id)
                if playbook is not None and "cleanup_complete" in playbook.success_emits:
                    cleanup = await adapter.cleanup(adapter_ctx)
                    if cleanup.success:
                        cmd.store.append_event(
                            run_handle,
                            Event(
                                event_type="cleanup_completed",
                                payload={
                                    "plan_id": plan_id,
                                    "playbook_id": playbook.id,
                                    "target": record.plan.target.host,
                                    "description": cleanup.details,
                                },
                                timestamp=now,
                            ),
                        )

        except ScopeAmendmentRequiredError as exc:
            # ``adapter.plan`` raised before a ProcessSpec exists, so no
            # subprocess, traffic, or synthetic evidence was created.
            cmd.store.append_event(
                run_handle,
                Event(
                    event_type="scope_amendment_required",
                    payload={
                        "plan_id": plan_id,
                        "playbook_id": record.plan.playbook_id,
                        "adapter": action.adapter,
                        "operation": action.operation,
                        "target": record.plan.target.host,
                        "reason": str(exc),
                    },
                    timestamp=now,
                ),
            )
            return {
                "status": "blocked",
                "boundary": "scope_amendment",
                "plan_id": plan_id,
                "message": str(exc),
                "actions_executed": actions_executed,
                "actions_failed": actions_failed,
                "evidence_artifacts": evidence_artifacts,
            }
        except KaliRuntimeUnavailableError as exc:
            actions_failed += 1
            cmd.store.append_event(
                run_handle,
                Event(
                    event_type="execution_boundary",
                    payload={
                        "plan_id": plan_id,
                        "playbook_id": record.plan.playbook_id,
                        "adapter": action.adapter,
                        "operation": action.operation,
                        "target": record.plan.target.host,
                        "boundary": "kali_runtime",
                        "reason": str(exc),
                    },
                    timestamp=now,
                ),
            )
            return {
                "status": "blocked",
                "boundary": "kali_runtime",
                "plan_id": plan_id,
                "message": str(exc),
                "actions_executed": actions_executed,
                "actions_failed": actions_failed,
                "evidence_artifacts": evidence_artifacts,
            }
        except AdapterPolicyError as exc:
            boundary = (
                "missing_validated_candidate"
                if action.adapter == "nuclei"
                else "missing_evidence"
                if action.adapter == "research" and action.inputs.get("full_chain")
                else "adapter_policy"
            )
            cmd.store.append_event(
                run_handle,
                Event(
                    event_type="execution_boundary",
                    payload={
                        "plan_id": plan_id,
                        "playbook_id": record.plan.playbook_id,
                        "adapter": action.adapter,
                        "operation": action.operation,
                        "target": record.plan.target.host,
                        "boundary": boundary,
                        "reason": str(exc),
                    },
                    timestamp=now,
                ),
            )
            return {
                "status": "blocked",
                "boundary": boundary,
                "plan_id": plan_id,
                "message": str(exc),
                "actions_executed": actions_executed,
                "actions_failed": actions_failed,
                "evidence_artifacts": evidence_artifacts,
            }
        except Exception as exc:
            actions_failed += 1
            cmd.store.append_event(
                run_handle,
                Event(
                    event_type="plan_executed",
                    payload={
                        "plan_id": plan_id,
                        "playbook_id": record.plan.playbook_id,
                        "action": action.adapter,
                        "operation": action.operation,
                        "status": "error",
                        "error_code": "adapter_execution_error",
                        "error": str(exc),
                        "target": record.plan.target.host,
                    },
                    timestamp=now,
                ),
            )

    # Compute overall status
    overall_status = "executed" if actions_failed == 0 else "partial"
    total_actions = actions_executed + actions_failed

    return {
        "status": overall_status,
        "plan_id": plan_id,
        "next_action": "continue_until_complete_then_render_offline_report",
        "message": (
            f"Plan {plan_id[:8]} executed with {actions_executed}/{total_actions} action(s) "
            f"against target {record.plan.target.host}. "
            f"{actions_failed} action(s) failed. Continue proposing and executing "
            "eligible plans until the objective and cleanup complete, then render "
            "the offline report automatically."
        ),
        "actions_executed": actions_executed,
        "actions_failed": actions_failed,
        "evidence_artifacts": evidence_artifacts,
    }


def _format_finding(
    action: Any,
    observation: Observation,
) -> str:
    """Format a human-readable finding from an action and observation."""
    parts = [f"{action.adapter}:{action.operation}"]
    data = observation.data or {}
    if isinstance(data, dict):
        summary = data.get("summary", "") or data.get("type", "")
        if summary:
            parts.append(str(summary))
    return " — ".join(parts)


def _record_explicit_objective_proof(
    *,
    cmd: AriadneCommand,
    run_handle: RunHandle,
    observation: Observation,
    plan_id: str,
    playbook_id: str,
    timestamp: datetime,
) -> None:
    """Promote only a persisted, objective-shaped observation to completion."""
    proof = observation.data.get("objective_proof")
    if not isinstance(proof, dict):
        return
    proof_map = cast(dict[str, object], proof)
    kind = proof_map.get("kind")
    description = proof_map.get("description", "")
    if not isinstance(kind, str) or not isinstance(description, str):
        return
    objective = next(
        (
            item
            for item in run_handle.snapshot.objectives
            if item.kind == kind and (item.kind != "custom" or item.description == description)
        ),
        None,
    )
    if objective is None:
        return
    existing = cmd.store.read_events(run_handle)
    if any(
        event.get("event_type") == "objective_completed"
        and event.get("payload", {}).get("objective_kind") == objective.kind
        and event.get("payload", {}).get("description", "") == objective.description
        for event in existing
    ):
        return
    cmd.store.append_event(
        run_handle,
        Event(
            event_type="objective_completed",
            payload={
                "plan_id": plan_id,
                "playbook_id": playbook_id,
                "target": observation.target.host,
                "objective_kind": objective.kind,
                "description": objective.description,
                "observation_id": str(observation.observation_id),
                "proof": proof_map.get("proof", ""),
            },
            timestamp=timestamp,
        ),
    )


def _finding_candidate_from_observation(
    observation: Observation,
) -> dict[str, str] | None:
    """Return a reportable candidate only for explicit vulnerability evidence.

    Generic services, open ports, banners, and heuristic output are evidence,
    not validated findings. Nuclei and ZAP expose structured match or alert
    signals, but a single scanner alert remains a candidate until a separate
    validation proof promotes it. This deliberately narrow conversion keeps
    report findings
    tied to one persisted observation and its transcript artifact.
    """
    data = observation.data
    severity = str(data.get("severity") or data.get("risk") or "").casefold()
    if severity not in {"critical", "high", "medium", "low"}:
        return None

    title = ""
    description = ""
    if observation.source == "nuclei":
        template_id = str(data.get("template_id") or "").strip()
        matched_at = str(data.get("matched_at") or "").strip()
        title = str(data.get("name") or "").strip()
        if not template_id or not matched_at or not title:
            return None
        description = f"Nuclei template {template_id} matched {matched_at}"
    elif observation.source == "zap":
        alert = str(data.get("alert") or "").strip()
        alert_ref = str(data.get("alertRef") or data.get("pluginId") or "").strip()
        url = str(data.get("url") or "").strip()
        if not alert or not alert_ref:
            return None
        title = alert
        description = str(data.get("description") or "").strip()
        if not description:
            description = f"ZAP alert {alert_ref}" + (f" at {url}" if url else "")
    else:
        return None

    return {
        "finding_id": f"finding:{observation.observation_id}",
        "title": title,
        "severity": severity,
        "status": "candidate",
        "target": observation.target.host,
        "description": description,
    }


async def handle_render_report(args: dict[str, Any], **context: Any) -> dict[str, Any]:
    """Render a walkthrough or professional report.

    Validates:
    - Active engagement binding exists for this session
    - Style is one of 'walkthrough' or 'professional'
    - Engagement run exists in the store with sufficient events

    Delegates to WalkthroughRenderer or ProfessionalRenderer after
    validation via ReportValidator.
    """
    cmd = _get_command(context)
    if "session_id" in args:
        return {
            "status": "error",
            "message": "session_id must come from trusted Hades context.",
            "path": "",
        }
    session_id = context.get("session_id", "")
    input_session_id = session_id
    style = args.get("style", "walkthrough")
    options = ReportOptions(
        include_flags=bool(args.get("include_flags", False)),
        include_secrets=bool(args.get("include_secrets", False)),
    )

    # 1. Check active engagement
    binding_info = _get_binding(cmd, input_session_id)
    if binding_info is None:
        return {
            "status": "error",
            "message": "No active engagement. Please bind an engagement first.",
            "path": "",
        }

    # 2. Validate style
    if style not in ("walkthrough", "professional"):
        return {
            "status": "error",
            "message": f"Unknown report style: {style!r}. Use 'walkthrough' or 'professional'.",
            "path": "",
        }

    # 3. Get the run handle
    engagement_id = binding_info["engagement_id"]
    if not engagement_id:
        return {
            "status": "error",
            "message": "No engagement id in binding.",
            "path": "",
        }

    run_handle = _get_run_handle(cmd.store, engagement_id)
    if run_handle is None:
        return {
            "status": "error",
            "message": "Engagement snapshot not found in store.",
            "path": "",
        }

    # 4. Validate the run
    validator = ReportValidator()
    validation = validator.validate(run_handle, options)
    if not validation.valid:
        return {
            "status": "error",
            "message": (f"Report validation failed: {'; '.join(validation.errors)}"),
            "path": "",
        }

    # 5. Render the report
    try:
        rendered: RenderedReport
        if style == "walkthrough":
            renderer = WalkthroughRenderer()
            rendered = renderer.render(run_handle, options)
            filename = "walkthrough.md"
        else:
            renderer = ProfessionalRenderer()
            rendered = renderer.render(run_handle, options)
            filename = "professional.html"

        # Write to a file
        report_path = cmd.store.write_output(
            run_handle,
            filename,
            rendered.text.encode("utf-8"),
        )

        return {
            "status": "report_rendered",
            "style": style,
            "path": str(report_path),
            "message": f"{style.title()} report written to {report_path.name}",
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Report rendering failed: {exc}",
            "path": "",
        }


async def handle_run_engagement(
    args: dict[str, Any],
    **context: Any,
) -> dict[str, Any]:
    """Advance deterministically until completion or a true boundary."""
    cmd = _get_command(context)
    session_id = context.get("session_id", "")
    max_steps = args.get("max_steps", 30)
    if not isinstance(max_steps, int) or not 1 <= max_steps <= 100:
        return {"status": "error", "message": "max_steps must be between 1 and 100"}
    for step in range(1, max_steps + 1):
        binding = _get_binding(cmd, session_id)
        if binding is None or binding["engagement_id"] is None:
            return {"status": "error", "message": "No active engagement."}
        run_handle = _get_run_handle(cmd.store, binding["engagement_id"])
        if run_handle is None:
            return {"status": "error", "message": "Engagement run is unavailable."}
        state, _ = _determine_engagement_state(cmd.store, run_handle)
        if state in {EngagementState.REPORTING, EngagementState.COMPLETE}:
            walkthrough = await handle_render_report(
                {"style": "walkthrough"},
                **context,
            )
            professional = await handle_render_report(
                {"style": "professional"},
                **context,
            )
            if (
                walkthrough.get("status") != "report_rendered"
                or professional.get("status") != "report_rendered"
            ):
                return {
                    "status": "blocked",
                    "boundary": "report_quality_gate",
                    "message": (
                        f"Offline report could not complete: "
                        f"{walkthrough.get('message')}; "
                        f"{professional.get('message')}"
                    ),
                }
            return {
                "status": "complete",
                "steps": step - 1,
                "walkthrough_path": walkthrough["path"],
                "professional_path": professional["path"],
                "message": "Objectives, cleanup, and both offline reports completed.",
            }

        proposed = await handle_propose_plan(
            {
                "snapshot_hash": binding["snapshot_hash"],
                "hypothesis": f"Advance engagement from {state.value}",
            },
            **context,
        )
        if proposed.get("status") not in {
            "plan_auto_approved",
            "plan_proposed",
        }:
            return {
                "status": "blocked",
                "boundary": proposed.get("boundary", "no_eligible_plan"),
                "message": proposed.get("message", "No eligible plan."),
                "details": proposed,
            }
        executed = await handle_execute_plan(
            {"plan_id": proposed["plan_id"]},
            **context,
        )
        if executed.get("status") == "blocked":
            return {
                **executed,
                "boundary": executed.get("boundary", "manual_choice"),
                "steps": step,
            }
        if executed.get("status") != "executed":
            events = cmd.store.read_events(run_handle)
            blocked_candidate_ids = {
                event.get("payload", {}).get("candidate_id")
                for event in events
                if event.get("event_type") == "scope_candidate_blocked"
            }
            candidate = next(
                (
                    event.get("payload", {})
                    for event in reversed(events)
                    if event.get("event_type") == "scope_candidate_discovered"
                    and event.get("payload", {}).get("candidate_id") not in blocked_candidate_ids
                ),
                None,
            )
            if candidate is not None:
                return {
                    "status": "blocked",
                    "boundary": "scope_candidate",
                    "candidate": candidate,
                    "steps": step,
                    "message": (
                        f"Discovered distinct target {candidate.get('target')} "
                        f"from local evidence: {candidate.get('reason')}. "
                        "A targeted amendment is required before sending traffic."
                    ),
                }
            return {
                "status": "blocked",
                "boundary": "execution_failure",
                "steps": step,
                "message": executed.get(
                    "message",
                    "A plan could not complete safely.",
                ),
                "details": executed,
            }
    return {
        "status": "blocked",
        "boundary": "safety_step_limit",
        "steps": max_steps,
        "message": "Safety step limit reached; inspect status before continuing.",
    }


# ── Internal helpers ──────────────────────────────────────────────────────


def _get_run_handle(store: RunStore, engagement_id: Any) -> RunHandle | None:
    """Retrieve a RunHandle from the store for the given engagement id.

    Returns None if the engagement has no store entry.
    """
    from uuid import UUID

    if isinstance(engagement_id, str):
        engagement_id = UUID(engagement_id)
    if not store.has_snapshot(engagement_id):
        return None

    # Reconstruct the snapshot from the lock file
    lock_path = store._engagement_path(engagement_id) / "engagement.lock.yaml"
    if not lock_path.is_file():
        return None

    import json

    try:
        data = json.loads(lock_path.read_text())
        snapshot = EngagementSnapshot.model_validate(data)
    except (json.JSONDecodeError, Exception):
        return None

    return RunHandle(
        engagement_id=engagement_id,
        path=store._engagement_path(engagement_id),
        snapshot=snapshot,
    )


def _load_engagement_policy(
    snapshot: EngagementSnapshot,
) -> EffectivePolicy:
    """Rebuild and verify the policy sources frozen into the snapshot."""
    from ariadne.core.policy import build_effective_policy

    effective = build_effective_policy(snapshot.profile, snapshot.constraints)
    if not snapshot.policy_source_digests:
        raise PolicyConfigurationError("snapshot has no policy provenance")
    if effective.source_digests != snapshot.policy_source_digests:
        raise PolicyConfigurationError("policy source digests changed")
    return effective
