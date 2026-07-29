from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from ariadne.adapters import AdapterRegistry
from ariadne.adapters.httpx import HttpxAdapter
from ariadne.adapters.nmap import NmapAdapter
from ariadne.adapters.nuclei import NucleiAdapter
from ariadne.adapters.pivot import PivotAdapter
from ariadne.adapters.research import ResearchAdapter
from ariadne.composition import ServiceContainer
from ariadne.core.engagement import TargetSpec
from ariadne.core.observations import Observation
from ariadne.core.workflow import (
    Playbook,
    PlaybookAction,
    PlaybookLimits,
    Trigger,
    WorkflowCatalog,
)
from ariadne.hades_adapter.commands import CURRENT_DISCLAIMER_VERSION
from ariadne.hades_adapter.consent import ConsentDecision
from ariadne.hades_adapter.handlers import _exclusion_conflict
from ariadne.hades_adapter.registration import _handler_for
from ariadne.knowledge import (
    KnowledgeIndex,
    LocalToolProbe,
    RuntimeVerificationStore,
    ToolCardVerifier,
)
from ariadne.runtime.process import ProcessResult
from ariadne.store.run_store import ArtifactInput, Event, RunStore


class DryRunRuntime:
    calls = 0

    async def run(self, spec) -> ProcessResult:
        self.calls += 1
        return ProcessResult(
            exit_code=0,
            stdout="PING target: dry-run reachable",
            stderr="",
        )


class RedirectRuntime(DryRunRuntime):
    async def run(self, spec) -> ProcessResult:
        self.calls += 1
        return ProcessResult(
            exit_code=0,
            stdout=(
                '{"url":"https://192.0.2.10/","status_code":302,'
                '"redirect":true,"location":"https://192.0.2.11/admin"}\n'
            ),
            stderr="",
        )


class NucleiRuntime(DryRunRuntime):
    async def run(self, spec) -> ProcessResult:
        self.calls += 1
        return ProcessResult(
            exit_code=0,
            stdout=(
                '{"template-id":"CVE-2021-41773","type":"http",'
                '"info":{"name":"Apache path traversal","severity":"high",'
                '"author":"projectdiscovery"},"host":"192.0.2.10",'
                '"matched-at":"https://192.0.2.10/"}\n'
            ),
            stderr="",
        )


class BuiltinProgressionRuntime(DryRunRuntime):
    async def run(self, spec) -> ProcessResult:
        self.calls += 1
        if spec.argv[0] == "ping":
            return ProcessResult(
                exit_code=0,
                stdout="PING target: dry-run reachable",
                stderr="",
            )
        if spec.argv[0] == "nmap":
            return ProcessResult(
                exit_code=0,
                stdout=(
                    '<?xml version="1.0"?><nmaprun><host>'
                    '<address addr="192.0.2.10" addrtype="ipv4"/>'
                    '<ports><port protocol="tcp" portid="80">'
                    '<state state="open"/><service name="http" '
                    'product="Apache httpd" version="2.4.58"/>'
                    "</port></ports></host></nmaprun>"
                ),
                stderr="",
            )
        if spec.argv[0] == "searchsploit":
            return ProcessResult(
                exit_code=0,
                stdout='{"RESULTS_EXPLOIT":[]}',
                stderr="",
            )
        if spec.argv[0] == "curl":
            if (
                "services.nvd.nist.gov" in spec.argv[-1]
                or "known_exploited_vulnerabilities" in spec.argv[-1]
            ):
                body = '{"vulnerabilities":[]}'
            else:
                body = "<html>No matching advisory</html>"
            return ProcessResult(exit_code=0, stdout=body, stderr="")
        if spec.argv[0] == "msfconsole":
            return ProcessResult(
                exit_code=0,
                stdout="No matching modules",
                stderr="",
            )
        raise AssertionError(f"Unexpected executable: {spec.argv[0]}")


class AcceptContract:
    async def request_contract(self, summary: object) -> ConsentDecision:
        del summary
        return ConsentDecision.ACCEPT

    async def request_plan(self, plan: object) -> ConsentDecision:
        del plan
        return ConsentDecision.ACCEPT


class DeterministicDocumentationProbe(LocalToolProbe):
    """Side-effect-free probe for operational-flow tests."""

    def inspect(self, card, official_provider):
        del official_provider
        return (
            f"/fixture/{Path(card.executable).name}",
            f"{Path(card.executable).name} fixture-1.0",
            f"usage: {Path(card.executable).name} [options]",
            "local_help",
        )


def _isolated_tool_verifier(tmp_path: Path) -> ToolCardVerifier:
    knowledge_root = tmp_path / "canonical-knowledge"
    shutil.copytree(Path(__file__).parents[2] / "knowledge", knowledge_root)
    return ToolCardVerifier(
        index=KnowledgeIndex.load(knowledge_root),
        probe=DeterministicDocumentationProbe(),
        store=RuntimeVerificationStore(tmp_path / "tool-runtime"),
    )


def test_explicit_contract_exclusion_blocks_matching_playbook_only() -> None:
    playbook = Playbook(
        id="excluded.v1",
        version=1,
        stage="environment_preflight",
        triggers=(),
        required_evidence_types=frozenset(),
        capabilities=frozenset({"preflight.check"}),
        actions=(
            PlaybookAction(
                adapter="research",
                operation="investigate",
                inputs={},
            ),
        ),
        limits=PlaybookLimits(),
        stop_conditions=(),
        success_emits=(),
        next_playbooks=(),
        report_sections=(),
    )

    assert _exclusion_conflict(playbook, ()) is None
    assert _exclusion_conflict(playbook, ("preflight.check",)) == ("preflight.check")

    async def request_plan(self, plan: object) -> ConsentDecision:
        del plan
        return ConsentDecision.ACCEPT

    async def request_amendment(self, summary: object) -> ConsentDecision:
        del summary
        return ConsentDecision.ACCEPT


@pytest.mark.parametrize(
    ("capability", "adapter", "operation", "exclusion"),
    [
        ("scan.tcp", "nmap", "tcp_discovery", "port scanning"),
        (
            "ad.password_spray",
            "active_directory",
            "password_spray",
            "password spraying",
        ),
    ],
)
def test_common_exclusion_aliases_block_the_matching_workflow_branch(
    capability: str,
    adapter: str,
    operation: str,
    exclusion: str,
) -> None:
    playbook = Playbook(
        id=f"excluded.{operation}.v1",
        version=1,
        stage="enumeration",
        triggers=(),
        required_evidence_types=frozenset(),
        capabilities=frozenset({capability}),
        actions=(PlaybookAction(adapter=adapter, operation=operation, inputs={}),),
        limits=PlaybookLimits(),
        stop_conditions=(),
        success_emits=(),
        next_playbooks=(),
        report_sections=(),
    )

    assert _exclusion_conflict(playbook, (exclusion,)) == exclusion


@pytest.mark.asyncio
async def test_public_dry_run_reaches_both_offline_reports(tmp_path) -> None:
    """One representative wrapper flow needs no target traffic or manual events."""
    playbook = Playbook(
        id="dry-run.complete.v1",
        version=1,
        stage="environment_preflight",
        triggers=(Trigger(kind="engagement_state", types=("snapshot_locked",)),),
        required_evidence_types=frozenset(),
        capabilities=frozenset({"preflight.check"}),
        actions=(
            PlaybookAction(
                adapter="research",
                operation="investigate",
                inputs={
                    "product": "preflight",
                    "tool_card": {
                        "title": "Fixture Ping",
                        "official_source_url": "https://docs.example.com/ping",
                        "source_date": "2026-07-29",
                        "summary": "Fixture-only bounded reachability probe.",
                    },
                },
            ),
        ),
        limits=PlaybookLimits(
            max_rate=1,
            max_concurrency=1,
            max_attempts=1,
            max_duration_seconds=10,
            max_output_bytes=4096,
        ),
        stop_conditions=("policy_blocked",),
        success_emits=("objective_proven", "cleanup_complete"),
        next_playbooks=(),
        report_sections=("scope", "evidence"),
    )
    registry = AdapterRegistry()
    research = ResearchAdapter()
    research.parse_for_target = lambda result, target: (
        Observation(
            observation_id=uuid4(),
            target=TargetSpec(host=target.host),
            source="proof",
            data={
                "type": "objective_proven",
                "objective_proof": {
                    "kind": "proof",
                    "description": "",
                    "proof": "FLAG{dry-run-proof}",
                },
            },
        ),
    )
    registry.register("research", research)
    runtime = DryRunRuntime()
    registry.default_runtime = runtime
    services = ServiceContainer(
        profile_name="dry-run",
        store=RunStore(base_path=tmp_path),
        catalog=WorkflowCatalog(playbooks={playbook.id: playbook}),
        adapter_registry=registry,
        consent_gateway=AcceptContract(),
        tool_card_verifier=_isolated_tool_verifier(tmp_path),
    )
    prepare = _handler_for("ariadne_prepare_engagement", services)
    run = _handler_for("ariadne_run", services)

    created = json.loads(
        await prepare(
            {
                "authorization_attested": True,
                "disclaimer_version": CURRENT_DISCLAIMER_VERSION,
                "profile": "private-lab",
                "target_host": "192.0.2.10",
                "objectives": ["proof"],
                "autonomy": "controlled",
                "intensity": "normal",
                "exclusions": ["dos"],
                "time_window_minutes": 30,
            },
            session_id="dry-run-session",
        )
    )
    result = json.loads(await run({"max_steps": 3}, session_id="dry-run-session"))

    assert created["status"] == "active"
    assert result["status"] == "complete", result
    assert runtime.calls == 1
    assert (tmp_path / "runs").is_dir()
    assert result["walkthrough_path"].endswith("walkthrough.md")
    assert result["professional_path"].endswith("professional.html")
    assert (tmp_path / "canonical-knowledge" / "tools" / "ping.md").is_file()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("adapter", "operation", "inputs", "capability", "boundary"),
    [
        (
            "research",
            "investigate",
            {"full_chain": True},
            "research.vulnerability",
            "missing_evidence",
        ),
        (
            "pivot",
            "add_route",
            {"network": "10.99.99.0/24"},
            "pivot.route",
            "scope_amendment",
        ),
        (
            "nuclei",
            "scan",
            {},
            "exploit.validation",
            "missing_validated_candidate",
        ),
    ],
)
async def test_run_returns_typed_pre_execution_boundaries(
    tmp_path,
    adapter: str,
    operation: str,
    inputs: dict[str, object],
    capability: str,
    boundary: str,
) -> None:
    playbook = Playbook(
        id=f"boundary.{adapter}.v1",
        version=1,
        stage="environment_preflight",
        triggers=(Trigger(kind="engagement_state", types=("snapshot_locked",)),),
        required_evidence_types=frozenset(),
        capabilities=frozenset({capability}),
        actions=(PlaybookAction(adapter=adapter, operation=operation, inputs=inputs),),
        limits=PlaybookLimits(
            max_rate=1,
            max_concurrency=1,
            max_attempts=1,
            max_duration_seconds=10,
            max_output_bytes=4096,
        ),
        stop_conditions=(),
        success_emits=(),
        next_playbooks=(),
        report_sections=(),
    )
    registry = AdapterRegistry()
    registry.register("research", ResearchAdapter())
    registry.register("pivot", PivotAdapter())
    registry.register("nuclei", NucleiAdapter())
    runtime = DryRunRuntime()
    registry.default_runtime = runtime
    services = ServiceContainer(
        profile_name="boundary",
        store=RunStore(base_path=tmp_path),
        catalog=WorkflowCatalog(playbooks={playbook.id: playbook}),
        adapter_registry=registry,
        consent_gateway=AcceptContract(),
    )
    prepare = _handler_for("ariadne_prepare_engagement", services)
    run = _handler_for("ariadne_run", services)

    created = json.loads(
        await prepare(
            {
                "profile": "private-lab",
                "target_host": "192.0.2.10",
                "objectives": ["proof"],
                "autonomy": "controlled",
                "intensity": "normal",
                "exclusions": ["dos"],
                "time_window_minutes": 30,
            },
            session_id=f"boundary-{adapter}",
        )
    )
    result = json.loads(await run({"max_steps": 1}, session_id=f"boundary-{adapter}"))

    assert created["status"] == "active"
    assert result["status"] == "blocked"
    assert result["boundary"] == boundary
    assert runtime.calls == 0


@pytest.mark.asyncio
async def test_post_execution_scope_candidate_persists_amendment_boundary(
    tmp_path,
) -> None:
    playbook = Playbook(
        id="scope.redirect.v1",
        version=1,
        stage="environment_preflight",
        triggers=(Trigger(kind="engagement_state", types=("snapshot_locked",)),),
        required_evidence_types=frozenset(),
        capabilities=frozenset({"web.fingerprint"}),
        actions=(
            PlaybookAction(
                adapter="httpx",
                operation="scan",
                inputs={
                    "ports": [443],
                    "timeout": 10,
                    "max_output": 4096,
                    "tool_card": {
                        "title": "Fixture HTTPX",
                        "official_source_url": "https://docs.example.com/httpx",
                        "source_date": "2026-07-29",
                        "summary": "Fixture-only bounded HTTP probe.",
                    },
                },
            ),
        ),
        limits=PlaybookLimits(
            max_rate=10,
            max_concurrency=1,
            max_attempts=1,
            max_duration_seconds=30,
            max_output_bytes=4096,
        ),
        stop_conditions=(),
        success_emits=(),
        next_playbooks=(),
        report_sections=(),
    )
    registry = AdapterRegistry()
    registry.register("httpx", HttpxAdapter())
    runtime = RedirectRuntime()
    registry.default_runtime = runtime
    services = ServiceContainer(
        profile_name="scope-candidate",
        store=RunStore(base_path=tmp_path),
        catalog=WorkflowCatalog(playbooks={playbook.id: playbook}),
        adapter_registry=registry,
        consent_gateway=AcceptContract(),
        tool_card_verifier=_isolated_tool_verifier(tmp_path),
    )
    prepare = _handler_for("ariadne_prepare_engagement", services)
    run = _handler_for("ariadne_run", services)
    created = json.loads(
        await prepare(
            {
                "profile": "private-lab",
                "target_host": "192.0.2.10",
                "objectives": ["proof"],
                "autonomy": "controlled",
                "intensity": "normal",
                "exclusions": ["dos"],
                "time_window_minutes": 30,
            },
            session_id="scope-candidate-session",
        )
    )

    result = json.loads(await run({"max_steps": 1}, session_id="scope-candidate-session"))

    binding = services.command.get_session_binding("scope-candidate-session")
    assert binding is not None and binding.engagement_id is not None
    handle = services.store.open(binding.engagement_id)
    assert handle is not None
    events = services.store.read_events(handle)
    assert created["status"] == "active"
    assert result["status"] == "blocked"
    assert result["boundary"] == "scope_amendment"
    assert result["candidate"]["target"] == "192.0.2.11"
    assert any(event["event_type"] == "scope_candidate_discovered" for event in events)
    assert any(event["event_type"] == "scope_amendment_required" for event in events)
    assert runtime.calls == 1
    assert (
        tmp_path
        / "canonical-knowledge"
        / "tools"
        / "httpx-toolkit.md"
    ).is_file()


@pytest.mark.asyncio
async def test_persisted_validated_research_injects_target_bound_nuclei_candidate(
    tmp_path,
) -> None:
    playbook = Playbook(
        id="validation.from-research.v1",
        version=1,
        stage="validation",
        triggers=(Trigger(kind="observation_type", types=("research_complete",)),),
        required_evidence_types=frozenset({"research_complete"}),
        capabilities=frozenset({"exploit.validation"}),
        actions=(
            PlaybookAction(
                adapter="nuclei",
                operation="scan",
                inputs={"max_output": 1_000_000},
            ),
        ),
        limits=PlaybookLimits(
            max_rate=10,
            max_concurrency=1,
            max_attempts=1,
            max_duration_seconds=300,
            max_output_bytes=10 * 1024 * 1024,
        ),
        stop_conditions=(),
        success_emits=(),
        next_playbooks=(),
        report_sections=(),
    )
    registry = AdapterRegistry()
    registry.register("nuclei", NucleiAdapter())
    runtime = NucleiRuntime()
    registry.default_runtime = runtime
    services = ServiceContainer(
        profile_name="validated-candidate",
        store=RunStore(base_path=tmp_path),
        catalog=WorkflowCatalog(playbooks={playbook.id: playbook}),
        adapter_registry=registry,
        consent_gateway=AcceptContract(),
    )
    object.__setattr__(services, "tool_card_verifier", None)
    prepare = _handler_for("ariadne_prepare_engagement", services)
    propose = _handler_for("ariadne_propose_plan", services)
    execute = _handler_for("ariadne_execute_plan", services)
    created = json.loads(
        await prepare(
            {
                "profile": "private-lab",
                "target_host": "192.0.2.10",
                "objectives": ["proof"],
                "autonomy": "controlled",
                "intensity": "normal",
                "exclusions": ["dos"],
                "time_window_minutes": 30,
            },
            session_id="validated-candidate-session",
        )
    )
    binding = services.command.get_session_binding("validated-candidate-session")
    assert binding is not None and binding.engagement_id is not None
    handle = services.store.open(binding.engagement_id)
    assert handle is not None
    artifact = services.store.add_bytes(
        handle,
        b'{"candidate":"CVE-2021-41773","version":"2.4.49"}',
        ArtifactInput(
            media_type="text/plain",
            evidence_type="research_complete",
            source_name="research:investigate",
            maximum_bytes=4096,
        ),
    )
    unrelated_artifact = services.store.add_bytes(
        handle,
        b"Unrelated scanner output",
        ArtifactInput(
            media_type="text/plain",
            evidence_type="research_complete",
            source_name="nmap:service_fingerprint",
            maximum_bytes=4096,
        ),
    )
    services.store.append_event(
        handle,
        Event(
            event_type="evidence_collected",
            payload={
                "artifact": unrelated_artifact.path.name,
                "asset": "192.0.2.10",
                "adapter": "nmap",
                "source": "nmap:service_fingerprint",
                "evidence_id": "evidence-unrelated-1",
                "evidence_type": "research_complete",
                "execution_classification": "success",
                "sha256": unrelated_artifact.sha256,
            },
            timestamp=datetime.now(UTC),
        ),
    )
    services.store.append_event(
        handle,
        Event(
            event_type="finding_validated",
            payload={
                "finding_id": "candidate-spoofed-unrelated",
                "template_id": "exposed-panel",
                "target": "192.0.2.10",
                "evidence_id": "evidence-unrelated-1",
                "issuer": "ariadne.evidence.findings.FindingService",
                "validation_source": "FindingService.validate",
                "provenance": (
                    "https://github.com/projectdiscovery/nuclei-templates/tree/main/http/exposures"
                ),
            },
            timestamp=datetime.now(UTC),
        ),
    )
    services.store.append_event(
        handle,
        Event(
            event_type="evidence_collected",
            payload={
                "artifact": artifact.path.name,
                "asset": "192.0.2.10",
                "adapter": "research",
                "source": "research:investigate",
                "evidence_id": "evidence-research-1",
                "evidence_type": "research_complete",
                "execution_classification": "success",
                "sha256": artifact.sha256,
                "observation_data": {
                    "type": "research_complete",
                    "fingerprint": {
                        "product": "Apache HTTP Server",
                        "version": "2.4.49",
                        "protocol": "http",
                        "port": 80,
                    },
                    "candidates": [
                        {
                            "candidate_id": "research-41773",
                            "cve_id": "CVE-2021-41773",
                            "product": "Apache HTTP Server",
                            "version": "2.4.49",
                            "title": "Apache path traversal",
                            "sources": [
                                "local-searchsploit",
                                "nvd",
                            ],
                            "source_urls": [
                                "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
                            ],
                            "exploit_paths": [
                                "exploits/multiple/webapps/50383.sh",
                            ],
                            "metasploit_modules": [],
                            "check_supported": False,
                            "compatible": True,
                            "applicability_evidence": [
                                "nvd-description:version=2.4.49",
                            ],
                            "validation_status": "validated",
                            "evidence": [
                                {
                                    "source": "nvd",
                                    "locator": ("https://nvd.nist.gov/vuln/detail/CVE-2021-41773"),
                                    "sha256": "a" * 64,
                                    "summary": "Version match",
                                },
                            ],
                        },
                    ],
                },
            },
            timestamp=datetime.now(UTC),
        ),
    )

    proposed = json.loads(
        await propose(
            {
                "snapshot_hash": created["snapshot_hash"],
                "hypothesis": "validate curated research candidate",
            },
            session_id="validated-candidate-session",
        )
    )
    record = services.command.get_plan_record(proposed["plan_id"])
    assert record is not None
    candidates = record.plan.actions[0].inputs["validated_candidates"]
    executed = json.loads(
        await execute(
            {"plan_id": proposed["plan_id"]},
            session_id="validated-candidate-session",
        )
    )

    assert candidates[0]["candidate_id"] == "research-41773"
    assert candidates[0]["cve_id"] == "CVE-2021-41773"
    assert candidates[0]["target"] == "192.0.2.10"
    assert candidates[0]["evidence_id"] == "evidence-research-1"
    assert executed["status"] == "executed", (
        executed,
        services.store.read_events(handle)[-1]["payload"].get("error"),
    )
    assert runtime.calls == 1


@pytest.mark.asyncio
async def test_builtin_catalog_reaches_structured_research_boundary(
    tmp_path,
) -> None:
    catalog = WorkflowCatalog.load(Path(__file__).parents[2] / "workflows")
    registry = AdapterRegistry()
    registry.register("research", ResearchAdapter())
    registry.register("nmap", NmapAdapter())
    registry.register("nuclei", NucleiAdapter())
    runtime = BuiltinProgressionRuntime()
    registry.default_runtime = runtime
    services = ServiceContainer(
        profile_name="builtin-progression",
        store=RunStore(base_path=tmp_path),
        catalog=catalog,
        adapter_registry=registry,
        consent_gateway=AcceptContract(),
    )
    object.__setattr__(services, "tool_card_verifier", None)
    prepare = _handler_for("ariadne_prepare_engagement", services)
    run = _handler_for("ariadne_run", services)
    created = json.loads(
        await prepare(
            {
                "profile": "private-lab",
                "target_host": "192.0.2.10",
                "objectives": ["proof"],
                "autonomy": "controlled",
                "intensity": "normal",
                "exclusions": ["dos"],
                "time_window_minutes": 30,
            },
            session_id="builtin-progression-session",
        )
    )

    result = json.loads(
        await run(
            {"max_steps": 10},
            session_id="builtin-progression-session",
        )
    )
    binding = services.command.get_session_binding("builtin-progression-session")
    assert binding is not None and binding.engagement_id is not None
    handle = services.store.open(binding.engagement_id)
    assert handle is not None
    events = services.store.read_events(handle)

    assert created["status"] == "active"
    assert result["status"] == "blocked"
    assert result["boundary"] == "missing_validated_candidate", (
        result,
        [
            event.get("payload", {}).get("error")
            for event in events[-10:]
            if event.get("payload", {}).get("error")
        ],
    )
    assert runtime.calls == 9
    assert [
        event["payload"]["playbook_id"]
        for event in events
        if event["event_type"] == "plan_executed" and event["payload"]["status"] == "executed"
    ] == [
        "engagement.preflight.v1",
        "network.tcp-discovery.v1",
        "network.service-fingerprint.v1",
        "service.protocol-routing.v1",
        "research.service-vulnerability.v1",
    ]
    assert any(
        event["event_type"] == "evidence_collected"
        and event["payload"]["evidence_type"] == "protocol_routed"
        and event["payload"]["execution_classification"] == "success"
        for event in events
    )


@pytest.mark.asyncio
async def test_proposal_follows_declared_next_playbooks(tmp_path) -> None:
    def playbook(identifier: str, next_playbooks: tuple[str, ...] = ()) -> Playbook:
        return Playbook(
            id=identifier,
            version=1,
            stage="environment_preflight",
            triggers=(Trigger(kind="engagement_state", types=("snapshot_locked",)),),
            required_evidence_types=frozenset(),
            capabilities=frozenset({"preflight.check"}),
            actions=(
                PlaybookAction(
                    adapter="research",
                    operation="investigate",
                    inputs={"product": "preflight"},
                ),
            ),
            limits=PlaybookLimits(),
            stop_conditions=(),
            success_emits=(),
            next_playbooks=next_playbooks,
            report_sections=(),
        )

    first = playbook("first.v1", ("second.v1",))
    second = playbook("second.v1")
    unrelated = playbook("unrelated.v1")
    registry = AdapterRegistry()
    registry.register("research", ResearchAdapter())
    services = ServiceContainer(
        profile_name="next-playbook",
        store=RunStore(base_path=tmp_path),
        catalog=WorkflowCatalog(playbooks={item.id: item for item in (first, second, unrelated)}),
        adapter_registry=registry,
        consent_gateway=AcceptContract(),
    )
    prepare = _handler_for("ariadne_prepare_engagement", services)
    propose = _handler_for("ariadne_propose_plan", services)
    created = json.loads(
        await prepare(
            {
                "profile": "private-lab",
                "target_host": "192.0.2.10",
                "objectives": ["proof"],
                "autonomy": "controlled",
                "intensity": "normal",
                "exclusions": ["dos"],
                "time_window_minutes": 30,
            },
            session_id="next-playbook-session",
        )
    )
    first_plan = json.loads(
        await propose(
            {"snapshot_hash": created["snapshot_hash"], "hypothesis": "start"},
            session_id="next-playbook-session",
        )
    )
    binding = services.command.get_session_binding("next-playbook-session")
    assert binding is not None and binding.engagement_id is not None
    handle = services.store.open(binding.engagement_id)
    assert handle is not None
    services.store.append_event(
        handle,
        Event(
            event_type="plan_executed",
            payload={"playbook_id": first.id, "status": "executed"},
            timestamp=datetime.now(UTC),
        ),
    )
    next_plan = json.loads(
        await propose(
            {"snapshot_hash": created["snapshot_hash"], "hypothesis": "continue"},
            session_id="next-playbook-session",
        )
    )

    assert first_plan["playbook_id"] == first.id
    assert next_plan["playbook_id"] == second.id
