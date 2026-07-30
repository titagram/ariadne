from __future__ import annotations

import asyncio
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from ariadne.adapters import AdapterRegistry
from ariadne.adapters.curl import CurlAdapter
from ariadne.adapters.httpx import HttpxAdapter
from ariadne.adapters.katana import KatanaAdapter
from ariadne.adapters.nmap import NmapAdapter
from ariadne.adapters.nuclei import NucleiAdapter
from ariadne.adapters.pcap import PcapAdapter
from ariadne.adapters.pivot import PivotAdapter
from ariadne.adapters.postex import PostExAdapter
from ariadne.adapters.research import ResearchAdapter
from ariadne.adapters.ssh import SshAdapter
from ariadne.adapters.zap import ZapAdapter
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
from ariadne.runtime.process import ProcessResult, ProcessRunner
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
    def __init__(self) -> None:
        self.calls = 0
        self.argv_calls: list[tuple[str, ...]] = []

    async def run(self, spec) -> ProcessResult:
        self.calls += 1
        self.argv_calls.append(tuple(spec.argv))
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
                    '</port><port protocol="tcp" portid="22">'
                    '<state state="open"/><service name="ssh" '
                    'product="OpenSSH" version="9.6"/>'
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
        if spec.argv[0] == "httpx-toolkit":
            return ProcessResult(
                exit_code=0,
                stdout=(
                    '{"url":"http://192.0.2.10:80/","status_code":200,'
                    '"title":"Fixture","tech":["Apache httpd"]}\n'
                ),
                stderr="",
            )
        raise AssertionError(f"Unexpected executable: {spec.argv[0]}")


class ProviderFallbackRuntime(ProcessRunner):
    def __init__(self) -> None:
        self.argv_calls: list[tuple[str, ...]] = []

    async def run(self, spec) -> ProcessResult:
        self.argv_calls.append(tuple(spec.argv))
        if spec.argv[0] == "curl":
            return ProcessResult(
                exit_code=0,
                stdout='<a href="/admin?view=summary">Admin</a>',
                stderr="",
            )
        raise AssertionError(f"Unexpected executable: {spec.argv[0]}")


class CrawlerFallbackRuntime(ProcessRunner):
    def __init__(self) -> None:
        self.argv_calls: list[tuple[str, ...]] = []

    async def run(self, spec) -> ProcessResult:
        self.argv_calls.append(tuple(spec.argv))
        if spec.argv[0] == "katana":
            return ProcessResult(
                exit_code=-1,
                stdout="",
                stderr="",
                timed_out=True,
            )
        if spec.argv[0] == "curl":
            return ProcessResult(
                exit_code=0,
                stdout='<a href="/capture">Capture</a>',
                stderr="",
            )
        raise AssertionError(f"Unexpected executable: {spec.argv[0]}")


class SyntheticGuardedVerticalRuntime:
    """Deterministic tool results behind the production GuardedRuntime."""

    def __init__(self) -> None:
        self.argv_calls: list[tuple[str, ...]] = []

    async def run(self, spec) -> ProcessResult:
        argv = tuple(spec.argv)
        self.argv_calls.append(argv)
        executable = argv[0]
        if executable == "curl" and "--write-out" not in argv:
            return ProcessResult(
                exit_code=0,
                stdout='<a href="/data/3">Download capture</a>',
                stderr="",
            )
        if (
            executable == "curl"
            and "--write-out" in argv
            and argv.count("--url") > 1
        ):
            records = []
            for output, url in zip(argv[14::4], argv[16::4], strict=True):
                downloadable = "/download/" in url and url.endswith("/3")
                body = Path(output)
                if downloadable:
                    body.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 64)
                elif url.endswith("/data/3"):
                    body.write_text(
                        "<button onclick=\"location.href='/download/3'\">"
                        "Download capture</button>"
                    )
                else:
                    body.write_text("<html>No artifact</html>")
                records.append(
                    json.dumps(
                        {
                            "url_effective": url,
                            "response_code": 200,
                            "content_type": (
                                "application/vnd.tcpdump.pcap"
                                if downloadable
                                else "text/html"
                            ),
                            "size_download": 68 if downloadable else 32,
                        },
                        sort_keys=True,
                    )
                )
            return ProcessResult(
                exit_code=0,
                stdout="\n".join(records),
                stderr="",
            )
        if executable == "curl":
            output = Path(argv[argv.index("--output") + 1])
            output.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 64)
            url = argv[argv.index("--url") + 1]
            return ProcessResult(
                exit_code=0,
                stdout=json.dumps(
                    {
                        "url_effective": url,
                        "response_code": 200,
                        "content_type": "application/vnd.tcpdump.pcap",
                        "size_download": output.stat().st_size,
                    }
                ),
                stderr="",
            )
        if executable == "tshark":
            return ProcessResult(
                exit_code=0,
                stdout=(
                    'USER\t"lab-user"\t\n'
                    'PASS\t"synthetic-credential-never-in-evidence"\t\n'
                ),
                stderr="",
            )
        if executable == "ssh":
            remote_command = argv[-1]
            if "user_flag_sha256" in remote_command:
                stdout = json.dumps(
                    {
                        "uid": 1000,
                        "gid": 1000,
                        "username": "lab-user",
                        "user_flag_sha256": "1" * 64,
                    }
                )
            elif remote_command == "id":
                stdout = "uid=1000(lab-user) gid=1000(lab-user) groups=1000(lab-user)"
            elif remote_command.startswith("getcap "):
                stdout = "/usr/bin/python3.8 = cap_setuid+ep"
            elif "root_flag_sha256" in remote_command:
                stdout = json.dumps(
                    {
                        "euid": 0,
                        "root_flag_sha256": "2" * 64,
                    }
                )
            else:
                raise AssertionError(f"Unexpected SSH command: {remote_command}")
            return ProcessResult(exit_code=0, stdout=stdout, stderr="")
        if executable == "nmap":
            return ProcessResult(
                exit_code=0,
                stdout=(
                    '<?xml version="1.0"?><nmaprun><host>'
                    '<address addr="192.0.2.10" addrtype="ipv4"/>'
                    '<ports><port protocol="tcp" portid="22">'
                    '<state state="open"/></port></ports></host></nmaprun>'
                ),
                stderr="",
            )
        raise AssertionError(f"Unexpected executable: {executable}")


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


def test_evidence_driven_foothold_replay_uses_guarded_runtime_end_to_end(
    tmp_path: Path,
) -> None:
    def playbook(
        *,
        identifier: str,
        stage: str,
        evidence: str,
        capability: str,
        adapter: str,
        operation: str,
        inputs: dict[str, object],
        next_playbooks: tuple[str, ...],
        success_emits: tuple[str, ...] = (),
        max_output: int = 10_000_000,
        max_duration: int = 180,
    ) -> Playbook:
        return Playbook(
            id=identifier,
            version=1,
            stage=stage,
            triggers=(
                Trigger(kind="observation_type", types=(evidence,)),
            ),
            required_evidence_types=frozenset({evidence}),
            capabilities=frozenset({capability}),
            actions=(
                PlaybookAction(
                    adapter=adapter,
                    operation=operation,
                    inputs=inputs,
                ),
            ),
            limits=PlaybookLimits(
                max_rate=5,
                max_concurrency=1,
                max_attempts=1,
                max_duration_seconds=max_duration,
                max_output_bytes=max_output,
            ),
            stop_conditions=("bounded_synthetic_replay",),
            success_emits=success_emits,
            next_playbooks=next_playbooks,
            report_sections=("evidence",),
        )

    playbooks = (
        playbook(
            identifier="web.http-fallback.v1",
            stage="enumeration",
            evidence="web_paths",
            capability="web.content_discovery",
            adapter="curl",
            operation="fetch",
            inputs={"timeout": 20, "max_output": 1024 * 1024},
            next_playbooks=("web.object-reference.v1",),
        ),
        playbook(
            identifier="web.object-reference.v1",
            stage="enumeration",
            evidence="web_paths",
            capability="web.object_reference",
            adapter="curl",
            operation="probe_references",
            inputs={"timeout": 20},
            next_playbooks=("web.artifact-download.v1",),
        ),
        playbook(
            identifier="web.artifact-download.v1",
            stage="enumeration",
            evidence="web_object_reference",
            capability="web.object_reference",
            adapter="curl",
            operation="download",
            inputs={"timeout": 30, "max_output": 10_000_000},
            next_playbooks=("artifact.pcap-inspection.v1",),
        ),
        playbook(
            identifier="artifact.pcap-inspection.v1",
            stage="enumeration",
            evidence="web_artifact",
            capability="artifact.packet_inspection",
            adapter="pcap",
            operation="extract_plaintext_credentials",
            inputs={},
            next_playbooks=("foothold.ssh-credentials.v1",),
        ),
        playbook(
            identifier="foothold.ssh-credentials.v1",
            stage="enumeration",
            evidence="credential_material",
            capability="foothold.ssh",
            adapter="ssh",
            operation="authenticate",
            inputs={},
            next_playbooks=("synthetic.linux.identity.v1",),
            max_output=64 * 1024,
            max_duration=60,
        ),
        playbook(
            identifier="synthetic.linux.identity.v1",
            stage="post_exploitation",
            evidence="foothold_established",
            capability="postex.linux.identity",
            adapter="postex",
            operation="identity",
            inputs={},
            next_playbooks=("linux.capabilities.v1",),
        ),
        playbook(
            identifier="linux.capabilities.v1",
            stage="privilege_escalation",
            evidence="linux_host_info",
            capability="privesc.linux.capabilities",
            adapter="postex",
            operation="file_capabilities",
            inputs={},
            next_playbooks=("linux.capability-python-proof.v1",),
        ),
        playbook(
            identifier="linux.capability-python-proof.v1",
            stage="privilege_escalation",
            evidence="privilege_escalation",
            capability="privesc.linux.capabilities",
            adapter="postex",
            operation="capability_python_proof",
            inputs={},
            next_playbooks=("cleanup.verify.v1",),
            max_output=64 * 1024,
            max_duration=60,
        ),
        playbook(
            identifier="cleanup.verify.v1",
            stage="cleanup",
            evidence="objective_proven",
            capability="cleanup.execute",
            adapter="nmap",
            operation="tcp_discovery",
            inputs={"ports": "22"},
            next_playbooks=(),
            success_emits=("cleanup_complete",),
            max_output=2 * 1024 * 1024,
            max_duration=60,
        ),
    )
    registry = AdapterRegistry()
    registry.register("curl", CurlAdapter())
    registry.register("pcap", PcapAdapter())
    registry.register("ssh", SshAdapter())
    registry.register("postex", PostExAdapter())
    registry.register("nmap", NmapAdapter())
    runtime = SyntheticGuardedVerticalRuntime()
    registry.default_runtime = runtime
    services = ServiceContainer(
        profile_name="synthetic-guarded-vertical",
        store=RunStore(base_path=tmp_path),
        catalog=WorkflowCatalog(
            playbooks={item.id: item for item in playbooks},
        ),
        adapter_registry=registry,
        consent_gateway=AcceptContract(),
    )
    object.__setattr__(services, "tool_card_verifier", None)
    prepare = _handler_for("ariadne_prepare_engagement", services)
    run = _handler_for("ariadne_run", services)

    async def replay() -> tuple[dict[str, object], object]:
        created = json.loads(
            await prepare(
                {
                    "profile": "private-lab",
                    "target_host": "192.0.2.10",
                    "objectives": ["user_flag", "root_flag"],
                    "autonomy": "controlled",
                    "intensity": "normal",
                    "exclusions": ["dos"],
                    "time_window_minutes": 30,
                },
                session_id="synthetic-guarded-vertical-session",
            )
        )
        assert created["status"] == "active"
        binding = services.command.get_session_binding(
            "synthetic-guarded-vertical-session"
        )
        assert binding is not None and binding.engagement_id is not None
        handle = services.store.open(binding.engagement_id)
        assert handle is not None
        seed = services.store.add_bytes(
            handle,
            b"synthetic prior web and service evidence",
            ArtifactInput(
                media_type="text/plain",
                evidence_type="seed_observation",
                source_name="synthetic:prior-evidence",
                maximum_bytes=4096,
            ),
        )
        for evidence_type, observation_data in (
            (
                "web_paths",
                {
                    "type": "web_paths",
                    "url": "http://192.0.2.10/capture",
                    "path": "/capture",
                    "method": "GET",
                },
            ),
            (
                "service_fingerprinted",
                {
                    "type": "service_fingerprinted",
                    "service": "ssh",
                    "protocol": "tcp",
                    "port": 22,
                    "state": "open",
                },
            ),
        ):
            services.store.append_event(
                handle,
                Event(
                    event_type="evidence_collected",
                    payload={
                        "artifact": seed.path.name,
                        "asset": "192.0.2.10",
                        "adapter": "synthetic_seed",
                        "source": "synthetic:prior-evidence",
                        "evidence_type": evidence_type,
                        "execution_classification": "success",
                        "sha256": seed.sha256,
                        "observation_data": observation_data,
                    },
                    timestamp=datetime.now(UTC),
                ),
            )
        result = json.loads(
            await run(
                {"max_steps": 11},
                session_id="synthetic-guarded-vertical-session",
            )
        )
        return result, handle

    result, handle = asyncio.run(replay())
    events = services.store.read_events(handle)
    serialized_events = json.dumps(events, sort_keys=True)

    assert result["status"] == "complete", result
    assert [argv[0] for argv in runtime.argv_calls] == [
        "curl",
        "curl",
        "curl",
        "curl",
        "tshark",
        "ssh",
        "ssh",
        "ssh",
        "ssh",
        "nmap",
    ]
    assert not any(
        event["event_type"] == "process_authorization_blocked"
        for event in events
    )
    assert {
        event["payload"]["objective_kind"]
        for event in events
        if event["event_type"] == "objective_completed"
    } == {"user_flag", "root_flag"}
    credential = next(
        event["payload"]["observation_data"]
        for event in events
        if event["event_type"] == "evidence_collected"
        and event["payload"]["evidence_type"] == "credential_material"
    )
    assert credential["secret_persisted"] is True
    assert credential["secret_storage"] == "protected_local_reference"
    assert "synthetic-credential-never-in-evidence" not in serialized_events
    assert (handle.path / credential["credential_ref"]).stat().st_mode & 0o777 == 0o600


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
async def test_builtin_catalog_researches_each_service_without_blind_validation(
    tmp_path,
) -> None:
    catalog = WorkflowCatalog.load(Path(__file__).parents[2] / "workflows")
    registry = AdapterRegistry()
    registry.register("research", ResearchAdapter())
    registry.register("nmap", NmapAdapter())
    registry.register("nuclei", NucleiAdapter())
    registry.register("httpx", HttpxAdapter())
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
            {"max_steps": 8},
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
    assert result["boundary"] == "safety_step_limit", (
        result,
        [
            event.get("payload", {}).get("error")
            for event in events[-10:]
            if event.get("payload", {}).get("error")
        ],
    )
    research_queries = [
        call
        for call in runtime.argv_calls
        if call and call[0] == "searchsploit"
    ]
    assert {call[-2:] for call in research_queries} == {
        ("Apache httpd", "2.4.58"),
        ("OpenSSH", "9.6"),
    }
    assert not any(call and call[0] == "nuclei" for call in runtime.argv_calls)
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
        "research.service-vulnerability.v1",
        "ssh.enumeration.v1",
        "web.fingerprint.v1",
    ]
    routed_ports = {
        event["payload"]["observation_data"]["port"]
        for event in events
        if (
            event["event_type"] == "evidence_collected"
            and event["payload"]["evidence_type"] == "protocol_routed"
            and event["payload"]["execution_classification"] == "success"
        )
    }
    assert routed_ports == {22, 80}
    assert any(
        event["event_type"] == "evidence_collected"
        and event["payload"]["evidence_type"] == "web_technologies"
        and event["payload"]["execution_classification"] == "success"
        for event in events
    )
    httpx_call = next(call for call in runtime.argv_calls if call[0] == "httpx-toolkit")
    assert httpx_call[httpx_call.index("-p") + 1] == "80"


@pytest.mark.asyncio
async def test_unavailable_web_provider_falls_back_without_ending_engagement(
    tmp_path,
    monkeypatch,
) -> None:
    primary = Playbook(
        id="web.primary-zap.v1",
        version=1,
        stage="environment_preflight",
        triggers=(Trigger(kind="engagement_state", types=("snapshot_locked",)),),
        required_evidence_types=frozenset(),
        capabilities=frozenset({"web.passive_scan"}),
        actions=(
            PlaybookAction(
                adapter="zap",
                operation="passive_scan",
                inputs={
                    "scan_type": "passive",
                    "url": "https://192.0.2.10/",
                },
            ),
        ),
        limits=PlaybookLimits(max_attempts=1),
        stop_conditions=("provider_complete",),
        success_emits=("zap_passive_alerts",),
        next_playbooks=("web.http-fallback.v1",),
        report_sections=("web",),
    )
    fallback = Playbook(
        id="web.http-fallback.v1",
        version=1,
        stage="environment_preflight",
        triggers=(Trigger(kind="engagement_state", types=("snapshot_locked",)),),
        required_evidence_types=frozenset(),
        capabilities=frozenset({"web.content_discovery"}),
        actions=(
            PlaybookAction(
                adapter="curl",
                operation="fetch",
                inputs={"url": "http://192.0.2.10/"},
            ),
        ),
        limits=PlaybookLimits(max_attempts=1),
        stop_conditions=("fallback_complete",),
        success_emits=("web_paths",),
        next_playbooks=(),
        report_sections=("web",),
    )
    registry = AdapterRegistry()
    registry.register("zap", ZapAdapter())
    registry.register("curl", CurlAdapter())
    runtime = ProviderFallbackRuntime()
    registry.default_runtime = runtime
    services = ServiceContainer(
        profile_name="provider-fallback",
        store=RunStore(base_path=tmp_path),
        catalog=WorkflowCatalog(
            playbooks={
                primary.id: primary,
                fallback.id: fallback,
            }
        ),
        adapter_registry=registry,
        consent_gateway=AcceptContract(),
    )
    object.__setattr__(services, "tool_card_verifier", None)
    monkeypatch.setattr(
        "ariadne.hades_adapter.handlers.shutil.which",
        lambda executable: (
            None if executable in {"zap.sh", "zaproxy"} else f"/fixture/{executable}"
        ),
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
            session_id="provider-fallback-session",
        )
    )

    result = json.loads(
        await run(
            {"max_steps": 2},
            session_id="provider-fallback-session",
        )
    )
    binding = services.command.get_session_binding("provider-fallback-session")
    assert binding is not None and binding.engagement_id is not None
    handle = services.store.open(binding.engagement_id)
    assert handle is not None
    events = services.store.read_events(handle)

    assert created["status"] == "active"
    assert result["boundary"] == "safety_step_limit", result
    assert any(
        event["event_type"] == "execution_boundary"
        and event["payload"]["playbook_id"] == primary.id
        and event["payload"]["boundary"] == "kali_runtime"
        for event in events
    )
    assert any(
        event["event_type"] == "plan_executed"
        and event["payload"]["playbook_id"] == fallback.id
        and event["payload"]["status"] == "executed"
        for event in events
    )
    assert runtime.argv_calls[0][0] == "curl"


@pytest.mark.asyncio
async def test_failed_crawler_uses_declared_http_fallback_in_same_run(
    tmp_path,
    monkeypatch,
) -> None:
    primary = Playbook(
        id="web.content-discovery.v1",
        version=1,
        stage="environment_preflight",
        triggers=(Trigger(kind="engagement_state", types=("snapshot_locked",)),),
        required_evidence_types=frozenset(),
        capabilities=frozenset({"web.content_discovery"}),
        actions=(
            PlaybookAction(
                adapter="katana",
                operation="crawl",
                inputs={
                    "urls": ["http://192.0.2.10/"],
                    "duration_seconds": 30,
                },
            ),
        ),
        limits=PlaybookLimits(max_attempts=1),
        stop_conditions=("crawler_complete",),
        success_emits=("web_paths",),
        next_playbooks=("web.http-fallback.v1",),
        report_sections=("web",),
    )
    fallback = Playbook(
        id="web.http-fallback.v1",
        version=1,
        stage="environment_preflight",
        triggers=(Trigger(kind="engagement_state", types=("snapshot_locked",)),),
        required_evidence_types=frozenset(),
        capabilities=frozenset({"web.content_discovery"}),
        actions=(
            PlaybookAction(
                adapter="curl",
                operation="fetch",
                inputs={"url": "http://192.0.2.10/"},
            ),
        ),
        limits=PlaybookLimits(max_attempts=1),
        stop_conditions=("fallback_complete",),
        success_emits=("web_paths",),
        next_playbooks=(),
        report_sections=("web",),
    )
    registry = AdapterRegistry()
    registry.register("katana", KatanaAdapter())
    registry.register("curl", CurlAdapter())
    runtime = CrawlerFallbackRuntime()
    registry.default_runtime = runtime
    services = ServiceContainer(
        profile_name="crawler-fallback",
        store=RunStore(base_path=tmp_path),
        catalog=WorkflowCatalog(
            playbooks={
                primary.id: primary,
                fallback.id: fallback,
            }
        ),
        adapter_registry=registry,
        consent_gateway=AcceptContract(),
    )
    object.__setattr__(services, "tool_card_verifier", None)
    monkeypatch.setattr(
        "ariadne.hades_adapter.handlers.shutil.which",
        lambda executable: f"/fixture/{executable}",
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
            session_id="crawler-fallback-session",
        )
    )

    result = json.loads(
        await run(
            {"max_steps": 2},
            session_id="crawler-fallback-session",
        )
    )

    assert created["status"] == "active"
    assert result["boundary"] == "safety_step_limit", result
    assert [call[0] for call in runtime.argv_calls] == ["katana", "curl"]


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


@pytest.mark.asyncio
async def test_failed_playbook_attempt_is_not_reproposed(tmp_path) -> None:
    playbook = Playbook(
        id="fails-once.v1",
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
        limits=PlaybookLimits(max_attempts=1),
        stop_conditions=(),
        success_emits=(),
        next_playbooks=(),
        report_sections=(),
    )
    services = ServiceContainer(
        profile_name="failed-attempt",
        store=RunStore(base_path=tmp_path),
        catalog=WorkflowCatalog(playbooks={playbook.id: playbook}),
        adapter_registry=AdapterRegistry(),
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
            session_id="failed-attempt-session",
        )
    )
    binding = services.command.get_session_binding("failed-attempt-session")
    assert binding is not None and binding.engagement_id is not None
    handle = services.store.open(binding.engagement_id)
    assert handle is not None
    services.store.append_event(
        handle,
        Event(
            event_type="plan_executed",
            payload={"playbook_id": playbook.id, "status": "failure"},
            timestamp=datetime.now(UTC),
        ),
    )

    result = json.loads(
        await propose(
            {
                "snapshot_hash": created["snapshot_hash"],
                "hypothesis": "do not retry failed bounded attempt",
            },
            session_id="failed-attempt-session",
        )
    )

    assert result["status"] == "error"
    assert result["plan_id"] == ""
