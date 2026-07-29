from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ariadne.adapters.nmap import NmapAdapter
from ariadne.core.engagement import TargetSpec
from ariadne.core.planner import Plan, PlannedAction
from ariadne.core.policy import CapabilityRule, EffectivePolicy
from ariadne.core.workflow import PlaybookLimits
from ariadne.execution.contracts import (
    ExecutionContractRegistry,
    ExecutionEnvelope,
    GuardedRuntime,
    ProcessAuthorizationError,
)
from ariadne.runtime.process import ProcessResult, ProcessSpec


class RecordingRuntime:
    def __init__(self, results: list[ProcessResult] | None = None) -> None:
        self.calls: list[ProcessSpec] = []
        self._results = list(results or [
            ProcessResult(exit_code=0, stdout="", stderr="")
        ])

    async def run(self, spec: ProcessSpec) -> ProcessResult:
        self.calls.append(spec)
        return self._results.pop(0)


def _plan(
    *,
    adapter: str = "nmap",
    operation: str = "tcp_discovery",
    capability: str = "scan.tcp",
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
                inputs={"ports": (22, 80)},
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


def test_registry_contains_only_current_live_slice() -> None:
    registry = ExecutionContractRegistry.curated()

    assert registry.get("research", "investigate") is not None
    for operation in (
        "tcp_discovery",
        "service_fingerprint",
        "udp_targeted",
    ):
        assert registry.get("nmap", operation) is not None
    assert registry.get("nuclei", "scan") is None
    assert registry.get("nmap", "unknown") is None


def test_envelope_is_bound_to_canonical_action_digest(tmp_path: Path) -> None:
    plan = _plan()
    envelope = _envelope(tmp_path, plan)
    mutated = plan.actions[0].model_copy(
        update={"inputs": {"ports": (443,)}}
    )

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
            "nmap", "-n", "-Pn", "-sS", "--max-rate", "10",
            "-p", "22", "-oX", "-", "--", "10.10.10.11",
        ),
        (
            "nmap", "-n", "-Pn", "-sS", "--max-rate", "10",
            "-p", "22", "-oX", "-", "10.10.10.11", "--", "10.10.10.10",
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
    runtime = RecordingRuntime([
        ProcessResult(
            exit_code=1,
            stdout="",
            stderr="TCP/IP fingerprinting requires root privileges",
        ),
        ProcessResult(exit_code=0, stdout="", stderr=""),
    ])
    guard = _guard(tmp_path, runtime, plan=plan)
    spec = _nmap_spec()
    guard.authorize_initial(spec)

    with pytest.raises(ProcessAuthorizationError, match="attempt"):
        await NmapAdapter().execute(spec, guard)

    assert len(runtime.calls) == 1


def test_process_spec_rejects_absolute_shell_invocation() -> None:
    with pytest.raises(ValueError, match="Shell invocation"):
        ProcessSpec(
            argv=("/bin/sh", "-c", "nmap 10.10.10.10"),
            timeout_seconds=10,
            max_output_bytes=4096,
        )
