from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from uuid import UUID

import pytest
import yaml

from ariadne.adapters.base import AdapterContext
from ariadne.adapters.base import PlannedAction as AdapterPlannedAction
from ariadne.adapters.katana import KatanaAdapter
from ariadne.adapters.nmap import NmapAdapter
from ariadne.adapters.research import ResearchAdapter
from ariadne.adapters.screenshot import ScreenshotAdapter
from ariadne.adapters.zap import ZapAdapter
from ariadne.core.engagement import TargetSpec
from ariadne.core.planner import Plan, PlannedAction
from ariadne.core.policy import CapabilityRule, EffectivePolicy, load_policy
from ariadne.core.workflow import PlaybookLimits, WorkflowCatalog
from ariadne.execution.contracts import (
    ExecutionContractRegistry,
    ExecutionCoordinator,
    ExecutionEnvelope,
    GuardedRuntime,
    ProcessAuthorizationError,
)
from ariadne.runtime.process import ProcessResult, ProcessSpec


class RecordingRuntime:
    def __init__(self, results: list[ProcessResult] | None = None) -> None:
        self.calls: list[ProcessSpec] = []
        self._results = list(results or [ProcessResult(exit_code=0, stdout="", stderr="")])

    async def run(self, spec: ProcessSpec) -> ProcessResult:
        self.calls.append(spec)
        return self._results.pop(0)


class ClockAdvancingRuntime(RecordingRuntime):
    def __init__(self, clock: list[float], advances: list[float]) -> None:
        super().__init__([
            ProcessResult(exit_code=124, stdout="", stderr=""),
            ProcessResult(exit_code=0, stdout="", stderr=""),
        ])
        self._clock = clock
        self._advances = iter(advances)

    async def run(self, spec: ProcessSpec) -> ProcessResult:
        self.calls.append(spec)
        self._clock[0] += next(self._advances)
        return self._results.pop(0)


class ScreenshotRuntime(RecordingRuntime):
    async def run(self, spec: ProcessSpec) -> ProcessResult:
        self.calls.append(spec)
        screenshot_arg = next(item for item in spec.argv if item.startswith("--screenshot="))
        output = Path(screenshot_arg.removeprefix("--screenshot="))
        assert output.parent.is_dir()
        output.write_bytes(b"PNG")
        return ProcessResult(
            exit_code=0,
            stdout=f"321 bytes written to file {output}",
            stderr="",
        )


def _plan(
    *,
    adapter: str = "nmap",
    operation: str = "tcp_discovery",
    capability: str = "scan.tcp",
    inputs: dict[str, object] | None = None,
    limits: PlaybookLimits | None = None,
) -> Plan:
    now = datetime.now(UTC)
    return Plan(
        plan_id="plan-boundary",
        snapshot_hash="a" * 64,
        target=TargetSpec(host="10.10.10.10"),
        hypothesis="bounded execution",
        playbook_id="test.v1",
        capabilities=(capability,),
        actions=(
            PlannedAction(
                adapter=adapter,
                operation=operation,
                inputs=inputs if inputs is not None else {"ports": (22, 80)},
            ),
        ),
        limits=limits
        or PlaybookLimits(
            max_rate=100,
            max_concurrency=1,
            max_attempts=2,
            max_duration_seconds=30,
            max_output_bytes=4096,
        ),
        expected_evidence=(),
        stop_conditions=("timeout",),
        requires_manual_approval=False,
        manual_capabilities=(),
        approval_reasons=(),
        created_at=now,
        expires_at=now + timedelta(minutes=15),
    )


def _policy(
    *,
    capability: str = "scan.tcp",
    tools: frozenset[str] = frozenset({"nmap"}),
) -> EffectivePolicy:
    return EffectivePolicy(
        name="execution-test",
        version=1,
        capabilities={
            capability: CapabilityRule(
                allowed=True,
                max_rate=100,
                max_concurrency=1,
                max_attempts=2,
                max_duration_seconds=30,
                max_output_bytes=4096,
                allowed_tools=tools,
            ),
        },
        source_digests=("policy-a",),
    )


def _envelope(
    tmp_path: Path,
    plan: Plan | None = None,
) -> ExecutionEnvelope:
    return ExecutionEnvelope.from_plan(
        plan or _plan(),
        action_index=0,
        run_root=tmp_path,
        policy_digests=("policy-a",),
    )


def _guard(
    tmp_path: Path,
    runtime: RecordingRuntime,
    *,
    plan: Plan | None = None,
    policy: EffectivePolicy | None = None,
) -> GuardedRuntime:
    envelope = _envelope(tmp_path, plan)
    registry = ExecutionContractRegistry.curated()
    contract = registry.require(envelope.adapter, envelope.operation)
    return GuardedRuntime(
        runtime=runtime,
        envelope=envelope,
        contract=contract,
        policy=policy or _policy(capability=envelope.capabilities[0]),
    )


def _nmap_spec(
    *,
    target: str = "10.10.10.10",
    rate: int = 100,
    timeout: int = 30,
    output: int = 4096,
    cwd: Path | None = None,
    environment: dict[str, str] | None = None,
) -> ProcessSpec:
    return ProcessSpec(
        argv=(
            "nmap",
            "-n",
            "-Pn",
            "-sS",
            "--max-rate",
            str(rate),
            "-p",
            "22,80",
            "-oX",
            "-",
            "--",
            target,
        ),
        timeout_seconds=timeout,
        max_output_bytes=output,
        cwd=cwd,
        environment=environment or {},
    )


def test_registry_contains_the_curated_workflow_operations() -> None:
    registry = ExecutionContractRegistry.curated()

    assert registry.get("research", "investigate") is not None
    for operation in (
        "tcp_discovery",
        "service_fingerprint",
        "udp_targeted",
    ):
        assert registry.get("nmap", operation) is not None
    assert registry.get("nuclei", "scan") is not None
    assert registry.get("nmap", "unknown") is None


def test_builtin_workflow_actions_have_curated_contracts_and_explicit_tools() -> None:
    """A built-in action cannot reach a subprocess through an implicit policy."""
    root = Path(__file__).parents[2]
    catalog = WorkflowCatalog.load(root / "workflows")
    policy = load_policy(root / "policies" / "base.yaml")
    registry = ExecutionContractRegistry.curated()
    boundary_only = {("pivot", "scan_discovered_host")}

    for playbook in catalog.playbooks.values():
        for action in playbook.actions:
            if (action.adapter, action.operation) in boundary_only:
                # The pivot adapter raises ScopeAmendmentRequiredError from
                # plan() before it can return a ProcessSpec or send traffic.
                continue
            contract = registry.get(action.adapter, action.operation)
            assert contract is not None, (
                f"{playbook.id} has no curated contract for {action.adapter}:{action.operation}"
            )
            for capability in playbook.capabilities:
                allowed_tools = policy.capabilities[capability].allowed_tools
                assert allowed_tools, (
                    f"{playbook.id} capability {capability} has no explicit allowed_tools"
                )
                assert contract.executable_ids & allowed_tools, (
                    f"{playbook.id} capability {capability} cannot authorize "
                    f"any executable in {action.adapter}:{action.operation}"
                )


def test_certipy_contract_accepts_the_executable_shipped_by_kali(
    tmp_path: Path,
) -> None:
    plan = _plan(
        adapter="active_directory",
        operation="certipy_find",
        capability="ad.enum",
        inputs={"username": "operator", "password": "secret"},
    )
    guard = _guard(
        tmp_path,
        RecordingRuntime(),
        plan=plan,
        policy=_policy(
            capability="ad.enum",
            tools=frozenset({"certipy-ad"}),
        ),
    )
    spec = ProcessSpec(
        argv=(
            "certipy-ad",
            "find",
            "-u",
            "operator",
            "-p",
            "secret",
            "-dc-ip",
            "10.10.10.10",
            "-target",
            "contoso.local",
        ),
        timeout_seconds=30,
        max_output_bytes=4096,
    )

    guard.authorize_initial(spec)


def test_contract_registry_is_immutable_and_binds_exact_adapter_type() -> None:
    registry = ExecutionContractRegistry.curated()
    contract = registry.require("nmap", "tcp_discovery")

    assert isinstance(registry.contracts, MappingProxyType)
    with pytest.raises(TypeError):
        registry.contracts[("nmap", "tcp_discovery")] = contract  # type: ignore[index]
    registry.verify_adapter(contract, NmapAdapter())
    with pytest.raises(ProcessAuthorizationError, match="implementation"):
        registry.verify_adapter(contract, ResearchAdapter())

    class SubclassedNmap(NmapAdapter):
        pass

    with pytest.raises(ProcessAuthorizationError, match="implementation"):
        registry.verify_adapter(contract, SubclassedNmap())


def test_envelope_is_bound_to_canonical_action_digest(tmp_path: Path) -> None:
    plan = _plan()
    envelope = _envelope(tmp_path, plan)
    mutated = plan.actions[0].model_copy(update={"inputs": {"ports": (443,)}})

    with pytest.raises(ProcessAuthorizationError, match="digest"):
        envelope.verify_action(mutated)


@pytest.mark.asyncio
async def test_malicious_tool_and_other_target_are_denied_before_runtime(
    tmp_path: Path,
) -> None:
    runtime = RecordingRuntime()
    guard = _guard(tmp_path, runtime)
    spec = ProcessSpec(
        argv=("curl", "http://10.10.10.11/"),
        timeout_seconds=10,
        max_output_bytes=4096,
    )

    with pytest.raises(ProcessAuthorizationError):
        guard.authorize_initial(spec)

    assert runtime.calls == []


@pytest.mark.parametrize(
    "argv",
    [
        (
            "nmap",
            "-n",
            "-Pn",
            "-sS",
            "--max-rate",
            "10",
            "-p",
            "22,80",
            "-oX",
            "-",
            "--",
            "10.10.10.11",
        ),
        (
            "nmap",
            "-n",
            "-Pn",
            "-sS",
            "--max-rate",
            "10",
            "-p",
            "22,80",
            "-oX",
            "-",
            "10.10.10.11",
            "--",
            "10.10.10.10",
        ),
    ],
)
def test_nmap_target_swap_or_extra_destination_is_denied(
    tmp_path: Path,
    argv: tuple[str, ...],
) -> None:
    guard = _guard(tmp_path, RecordingRuntime())

    with pytest.raises(ProcessAuthorizationError, match="target|template"):
        guard.authorize_initial(
            ProcessSpec(
                argv=argv,
                timeout_seconds=30,
                max_output_bytes=4096,
            )
        )


@pytest.mark.parametrize(
    "argv",
    [
        (
            "nmap",
            "-n",
            "-Pn",
            "-sT",
            "--max-rate",
            "10",
            "--max-rate",
            "10",
            "-p",
            "22,80",
            "-oX",
            "-",
            "--",
            "10.10.10.10",
        ),
        (
            "nmap",
            "-n",
            "-Pn",
            "-sT",
            "--max-rate",
            "10",
            "-p",
            "22,80",
            "-p",
            "22,80",
            "-oX",
            "-",
            "--",
            "10.10.10.10",
        ),
        (
            "nmap",
            "-n",
            "-Pn",
            "-sT",
            "-sT",
            "--max-rate",
            "10",
            "-p",
            "22,80",
            "-oX",
            "-",
            "--",
            "10.10.10.10",
        ),
        (
            "nmap",
            "-n",
            "-Pn",
            "-sT",
            "--max-rate",
            "10",
            "-p",
            "443",
            "-oX",
            "-",
            "--",
            "10.10.10.10",
        ),
    ],
)
def test_nmap_duplicate_semantic_flags_or_port_mutation_is_denied(
    tmp_path: Path,
    argv: tuple[str, ...],
) -> None:
    guard = _guard(tmp_path, RecordingRuntime())

    with pytest.raises(ProcessAuthorizationError):
        guard.authorize_initial(
            ProcessSpec(
                argv=argv,
                timeout_seconds=30,
                max_output_bytes=4096,
            )
        )


@pytest.mark.parametrize(
    "spec",
    [
        _nmap_spec(timeout=31),
        _nmap_spec(output=8192),
        _nmap_spec(rate=101),
        _nmap_spec(environment={"PATH": "/tmp/evil"}),
    ],
)
def test_declared_bounds_and_environment_are_enforced(
    tmp_path: Path,
    spec: ProcessSpec,
) -> None:
    guard = _guard(tmp_path, RecordingRuntime())

    with pytest.raises(ProcessAuthorizationError):
        guard.authorize_initial(spec)


def test_cwd_must_be_none_or_within_run_root(tmp_path: Path) -> None:
    guard = _guard(tmp_path, RecordingRuntime())
    guard.authorize_initial(_nmap_spec(cwd=tmp_path / "work"))

    with pytest.raises(ProcessAuthorizationError, match="cwd"):
        guard.authorize_initial(_nmap_spec(cwd=tmp_path.parent))


def test_empty_allowed_tools_is_not_unrestricted_at_execution_boundary(
    tmp_path: Path,
) -> None:
    guard = _guard(
        tmp_path,
        RecordingRuntime(),
        policy=_policy(tools=frozenset()),
    )

    with pytest.raises(ProcessAuthorizationError, match="tool"):
        guard.authorize_initial(_nmap_spec())


def test_generic_curated_contract_accepts_target_bound_httpx_and_denies_shell_token(
    tmp_path: Path,
) -> None:
    plan = _plan(adapter="httpx", operation="scan", capability="web.fingerprint")
    guard = _guard(
        tmp_path,
        RecordingRuntime(),
        plan=plan,
        policy=_policy(
            capability="web.fingerprint",
            tools=frozenset({"httpx-toolkit"}),
        ),
    )
    spec = ProcessSpec(
        argv=(
            "httpx-toolkit",
            "-p",
            "80",
            "-json",
            "-no-fallback",
            "-t",
            "10",
            "-timeout",
            "10",
        ),
        stdin=b"https://10.10.10.10\nhttp://10.10.10.10\n",
        timeout_seconds=30,
        max_output_bytes=4096,
    )

    guard.authorize_initial(spec)
    with pytest.raises(ProcessAuthorizationError, match="template|token"):
        guard.authorize_initial(spec.model_copy(update={"argv": spec.argv + ("&&", "curl")}))


@pytest.mark.parametrize(
    ("adapter", "operation", "capability", "tool", "spec", "mutated"),
    [
        (
            "postex",
            "identity",
            "postex.linux.identity",
            "ssh",
            ProcessSpec(
                argv=("ssh", "10.10.10.10", "id"),
                timeout_seconds=30,
                max_output_bytes=4096,
            ),
            ProcessSpec(
                argv=("ssh", "10.10.10.10", "uname -a"),
                timeout_seconds=30,
                max_output_bytes=4096,
            ),
        ),
        (
            "active_directory",
            "ldap_rootdse",
            "ad.enum",
            "ldapsearch",
            ProcessSpec(
                argv=(
                    "ldapsearch",
                    "-H",
                    "ldap://10.10.10.10",
                    "-x",
                    "-s",
                    "base",
                    "-b",
                    "",
                    "objectClass=*",
                ),
                timeout_seconds=30,
                max_output_bytes=4096,
            ),
            ProcessSpec(
                argv=(
                    "ldapsearch",
                    "-H",
                    "ldap://10.10.10.11",
                    "-x",
                    "-s",
                    "base",
                    "-b",
                    "",
                    "objectClass=*",
                ),
                timeout_seconds=30,
                max_output_bytes=4096,
            ),
        ),
    ],
)
def test_remote_operation_contracts_accept_exact_embedded_target_and_reject_mutation(
    tmp_path: Path,
    adapter: str,
    operation: str,
    capability: str,
    tool: str,
    spec: ProcessSpec,
    mutated: ProcessSpec,
) -> None:
    plan = _plan(
        adapter=adapter,
        operation=operation,
        capability=capability,
        inputs={},
    )
    guard = _guard(
        tmp_path,
        RecordingRuntime(),
        plan=plan,
        policy=_policy(capability=capability, tools=frozenset({tool})),
    )

    guard.authorize_initial(spec)
    with pytest.raises(ProcessAuthorizationError, match="target|template"):
        guard.authorize_initial(mutated)


def test_zap_contract_accepts_only_the_exact_operation_yaml_shape(
    tmp_path: Path,
) -> None:
    capability = "web.passive_scan"
    plan = _plan(
        adapter="zap",
        operation="passive_scan",
        capability=capability,
        inputs={
            "url": "http://10.10.10.10:80/",
            "http_host": "orion.test",
        },
    )
    guard = _guard(
        tmp_path,
        RecordingRuntime(),
        plan=plan,
        policy=_policy(capability=capability, tools=frozenset({"zaproxy"})),
    )
    context = AdapterContext(
        target=plan.target,
        snapshot_hash=plan.snapshot_hash,
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name="zap",
    )
    spec = ZapAdapter().plan(
        AdapterPlannedAction(
            operation="passive_scan",
            inputs={
                "url": "http://10.10.10.10:80/",
                "timeout": 30,
                "max_output": 4096,
                "http_host": "orion.test",
            },
        ),
        context,
    )

    guard.authorize_initial(spec)
    with pytest.raises(ProcessAuthorizationError, match="target|environment"):
        guard.authorize_initial(
            spec.model_copy(
                update={
                    "environment": {
                        "ARIADNE_ZAP_HTTP_HOST": "orion.test",
                        "ARIADNE_ZAP_NETWORK_TARGET": "10.10.10.11",
                    }
                }
            )
        )
    automation = yaml.safe_load(spec.stdin)
    automation["env"]["contexts"][0]["urls"].append("https://10.10.10.11")
    automation["jobs"].append({"type": "requestor", "parameters": {}})
    automation["unexpected"] = True
    with pytest.raises(ProcessAuthorizationError, match="target|template"):
        guard.authorize_initial(
            spec.model_copy(update={"stdin": yaml.safe_dump(automation).encode()})
        )


def test_metasploit_contract_allows_target_bound_vhost(tmp_path: Path) -> None:
    capability = "exploit.metasploit"
    plan = _plan(
        adapter="metasploit",
        operation="check",
        capability=capability,
        inputs={},
        limits=PlaybookLimits(
            max_rate=1,
            max_concurrency=1,
            max_attempts=1,
            max_duration_seconds=30,
            max_output_bytes=4096,
        ),
    )
    guard = _guard(
        tmp_path,
        RecordingRuntime(),
        plan=plan,
        policy=_policy(capability=capability, tools=frozenset({"msfconsole"})),
    )
    spec = ProcessSpec(
        argv=(
            "msfconsole",
            "-q",
            "-x",
            "use exploit/linux/http/example; set RHOSTS 10.10.10.10; "
            "set RPORT 80; set VHOST orion.test; check; exit",
        ),
        timeout_seconds=30,
        max_output_bytes=4096,
    )
    guard.authorize_initial(spec)


def test_katana_contract_rejects_a_seed_outside_the_exact_target(
    tmp_path: Path,
) -> None:
    capability = "web.content_discovery"
    plan = _plan(
        adapter="katana",
        operation="crawl",
        capability=capability,
        inputs={},
        limits=PlaybookLimits(
            max_rate=20,
            max_concurrency=1,
            max_attempts=1,
            max_duration_seconds=30,
            max_output_bytes=4096,
        ),
    )
    guard = _guard(
        tmp_path,
        RecordingRuntime(),
        plan=plan,
        policy=_policy(capability=capability, tools=frozenset({"katana"})),
    )
    context = AdapterContext(
        target=plan.target,
        snapshot_hash=plan.snapshot_hash,
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name="katana",
        limits=plan.limits,
        capabilities=plan.capabilities,
    )
    spec = KatanaAdapter().plan(
        AdapterPlannedAction(
            operation="crawl",
            inputs={
                "urls": ["http://10.10.10.10/"],
                "duration_seconds": 5,
            },
        ),
        context,
    )

    guard.authorize_initial(spec)
    mutated = spec.model_copy(
        update={
            "argv": tuple(
                "http://10.10.10.11/" if item == "http://10.10.10.10/" else item
                for item in spec.argv
            )
        }
    )
    with pytest.raises(ProcessAuthorizationError, match="target"):
        guard.authorize_initial(mutated)


@pytest.mark.asyncio
async def test_screenshot_workspace_is_created_only_after_authorization(
    tmp_path: Path,
) -> None:
    capability = "web.screenshot"
    plan = _plan(
        adapter="screenshot",
        operation="capture",
        capability=capability,
        inputs={},
    )
    runtime = ScreenshotRuntime()
    guard = _guard(
        tmp_path,
        runtime,
        plan=plan,
        policy=_policy(capability=capability, tools=frozenset({"chromium"})),
    )
    context = AdapterContext(
        target=plan.target,
        snapshot_hash=plan.snapshot_hash,
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name="screenshot",
        run_root=tmp_path,
    )
    adapter = ScreenshotAdapter()
    spec = adapter.plan(
        AdapterPlannedAction(
            operation="capture",
            inputs={"timeout": 30, "max_output": 4096},
        ),
        context,
    )
    screenshots = tmp_path / "artifacts" / "screenshots"

    assert not screenshots.exists()
    guard.authorize_initial(spec)
    assert not screenshots.exists()
    await adapter.execute(spec, guard)
    assert screenshots.is_dir()


@pytest.mark.asyncio
async def test_nmap_fallback_consumes_second_attempt_and_honours_budget(
    tmp_path: Path,
) -> None:
    plan = _plan(
        limits=PlaybookLimits(
            max_rate=100,
            max_concurrency=1,
            max_attempts=1,
            max_duration_seconds=30,
            max_output_bytes=4096,
        )
    )
    runtime = RecordingRuntime(
        [
            ProcessResult(
                exit_code=1,
                stdout="",
                stderr="TCP/IP fingerprinting requires root privileges",
            ),
            ProcessResult(exit_code=0, stdout="", stderr=""),
        ]
    )
    guard = _guard(tmp_path, runtime, plan=plan)
    spec = _nmap_spec()
    guard.authorize_initial(spec)

    with pytest.raises(ProcessAuthorizationError, match="attempt"):
        await NmapAdapter().execute(spec, guard)

    assert len(runtime.calls) == 1


@pytest.mark.asyncio
async def test_nested_results_consume_combined_output_budget(
    tmp_path: Path,
) -> None:
    runtime = RecordingRuntime(
        [
            ProcessResult(exit_code=0, stdout="a" * 3000, stderr="b" * 500),
            ProcessResult(
                exit_code=0,
                stdout="c" * 700,
                stderr="",
            ),
        ]
    )
    guard = _guard(tmp_path, runtime)
    spec = _nmap_spec()
    guard.authorize_initial(spec)

    await guard.run(spec)
    with pytest.raises(ProcessAuthorizationError, match="output"):
        await guard.run(
            spec.model_copy(
                update={"argv": tuple("-sT" if value == "-sS" else value for value in spec.argv)}
            )
        )

    assert len(runtime.calls) == 1


@pytest.mark.asyncio
async def test_setup_overhead_caps_nested_timeout_instead_of_blocking(
    tmp_path: Path,
) -> None:
    now = [0.0]
    runtime = RecordingRuntime(
        [
            ProcessResult(exit_code=0, stdout="", stderr=""),
        ]
    )
    envelope = _envelope(tmp_path)
    contract = ExecutionContractRegistry.curated().require(
        envelope.adapter,
        envelope.operation,
    )
    guard = GuardedRuntime(
        runtime=runtime,
        envelope=envelope,
        contract=contract,
        policy=_policy(),
        clock=lambda: now[0],
    )
    spec = _nmap_spec()
    guard.authorize_initial(spec)
    now[0] = 5.0

    await guard.run(spec)

    assert len(runtime.calls) == 1
    assert runtime.calls[0].timeout_seconds == 25


@pytest.mark.asyncio
async def test_tool_timeout_starts_a_fresh_local_timer_for_fallback(
    tmp_path: Path,
) -> None:
    clock = [0.0]
    runtime = ClockAdvancingRuntime(clock, [20.0, 5.0])
    envelope = _envelope(tmp_path)
    contract = ExecutionContractRegistry.curated().require(
        envelope.adapter,
        envelope.operation,
    )
    guard = GuardedRuntime(
        runtime=runtime,
        envelope=envelope,
        contract=contract,
        policy=_policy(),
        clock=lambda: clock[0],
    )
    spec = _nmap_spec()
    guard.authorize_initial(spec)

    first = await guard.run(spec)
    second = await guard.run(spec)

    assert first.exit_code == 124
    assert second.exit_code == 0
    assert [call.timeout_seconds for call in runtime.calls] == [30, 10]
    assert guard.attempts == 2
    assert guard.attempt_elapsed_seconds == 0.0


@pytest.mark.asyncio
async def test_execution_coordinator_never_exceeds_shared_concurrency() -> None:
    import asyncio

    coordinator = ExecutionCoordinator(max_concurrency=1)
    entered = 0
    peak = 0
    release = asyncio.Event()

    async def worker() -> None:
        nonlocal entered, peak
        async with coordinator.slot():
            entered += 1
            peak = max(peak, entered)
            await release.wait()
            entered -= 1

    first = asyncio.create_task(worker())
    await asyncio.sleep(0)
    second = asyncio.create_task(worker())
    await asyncio.sleep(0)
    assert peak == 1
    release.set()
    await first
    await second


def test_process_spec_rejects_absolute_shell_invocation() -> None:
    with pytest.raises(ValueError, match="Shell invocation"):
        ProcessSpec(
            argv=("/bin/sh", "-c", "nmap 10.10.10.10"),
            timeout_seconds=10,
            max_output_bytes=4096,
        )
