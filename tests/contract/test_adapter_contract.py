"""Contract tests for the ToolAdapter protocol and adapter base types.

Verifies structural invariants of the adapter SDK without executing
any real tool: protocol shape, factory helpers, and error types.
"""

from __future__ import annotations

from uuid import UUID

import pytest
from pydantic import ValidationError

from ariadne.adapters.base import (
    AdapterContext,
    AdapterError,
    CleanupResult,
    ExecutionClassification,
    PlannedAction,
    Runtime,
    ToolAdapter,
    ToolProbe,
)
from ariadne.core.engagement import TargetSpec
from ariadne.core.observations import Observation
from ariadne.runtime.process import ProcessResult, ProcessSpec

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def sample_target() -> TargetSpec:
    return TargetSpec(host="10.10.10.10")


@pytest.fixture
def adapter_context(sample_target: TargetSpec) -> AdapterContext:
    return AdapterContext(
        target=sample_target,
        snapshot_hash="abc123",
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name="test_adapter",
    )


@pytest.fixture
def planned_action() -> PlannedAction:
    return PlannedAction(operation="scan", inputs={"ports": [22, 80, 443]})


@pytest.fixture
def sample_result() -> ProcessResult:
    return ProcessResult(
        exit_code=0,
        stdout="open 22/tcp\nopen 80/tcp",
        stderr="",
        timed_out=False,
        output_truncated=False,
    )


# ── Type shape ────────────────────────────────────────────────────────────────


class TestToolProbe:
    def test_available_tool(self) -> None:
        probe = ToolProbe(available=True, version="7.95", path="/usr/bin/nmap")
        assert probe.available is True
        assert probe.version == "7.95"
        assert probe.path == "/usr/bin/nmap"

    def test_unavailable_tool(self) -> None:
        probe = ToolProbe(available=False)
        assert probe.available is False
        assert probe.version is None

    def test_rejects_extra_field(self) -> None:
        with pytest.raises(ValidationError):
            ToolProbe(available=True, bogus=True)  # type: ignore[call-arg]


class TestPlannedAction:
    def test_basic_action(self, planned_action: PlannedAction) -> None:
        assert planned_action.operation == "scan"
        assert planned_action.inputs == {"ports": [22, 80, 443]}

    def test_rejects_extra_field(self) -> None:
        with pytest.raises(ValidationError):
            PlannedAction(operation="scan", inputs={}, extra=True)  # type: ignore[call-arg]


class TestAdapterContext:
    def test_basic_context(self, adapter_context: AdapterContext) -> None:
        assert str(adapter_context.target.host) == "10.10.10.10"
        assert adapter_context.snapshot_hash == "abc123"

    def test_rejects_extra_field(self) -> None:
        with pytest.raises(ValidationError):
            AdapterContext(
                target=TargetSpec(host="10.10.10.10"),
                snapshot_hash="x",
                engagement_id=UUID(int=0),
                adapter_name="t",
                bogus=True,  # type: ignore[call-arg]
            )


class TestExecutionClassification:
    def test_success(self) -> None:
        c = ExecutionClassification(kind="success", confidence=0.9, summary="Ports discovered")
        assert c.kind == "success"
        assert c.confidence == 0.9

    def test_rejects_high_confidence(self) -> None:
        with pytest.raises(ValidationError):
            ExecutionClassification(kind="success", confidence=1.5, summary="bad")

    def test_rejects_low_confidence(self) -> None:
        with pytest.raises(ValidationError):
            ExecutionClassification(kind="success", confidence=-0.1, summary="bad")


class TestCleanupResult:
    def test_success(self) -> None:
        r = CleanupResult(success=True, details="Removed temp files")
        assert r.success is True

    def test_failure(self) -> None:
        r = CleanupResult(success=False, details="Could not remove /tmp/foo")
        assert r.success is False


# ── Protocol contract ─────────────────────────────────────────────────────────

# These tests verify that any ToolAdapter implementation conforms to
# the expected structural interface.


class _ConcreteAdapter:
    """Minimal ToolAdapter implementation for protocol conformance checks."""

    name: str = "test_adapter"

    async def probe(self, runtime: Runtime) -> ToolProbe:
        return ToolProbe(available=True)

    def plan(self, action: PlannedAction, context: AdapterContext) -> ProcessSpec:
        return ProcessSpec(
            argv=("echo", action.operation),
            timeout_seconds=30,
            max_output_bytes=4096,
        )

    async def execute(
        self, spec: ProcessSpec, runtime: Runtime
    ) -> ProcessResult:
        return ProcessResult(
            exit_code=0, stdout="", stderr="", timed_out=False, output_truncated=False
        )

    def parse(self, result: ProcessResult) -> tuple[Observation, ...]:
        return ()

    def classify(
        self,
        result: ProcessResult,
        observations: tuple[Observation, ...],
    ) -> ExecutionClassification:
        return ExecutionClassification(kind="unknown", confidence=0.0, summary="No classification")

    async def collect(
        self, result: ProcessResult, collector: object
    ) -> tuple[str, ...]:
        return ()

    async def cleanup(self, context: AdapterContext) -> CleanupResult:
        return CleanupResult(success=True, details="Cleaned up")


class TestToolAdapterProtocol:
    def test_concrete_adapter_satisfies_protocol(self) -> None:
        """Verify isinstance check against the structural protocol."""
        adapter = _ConcreteAdapter()
        assert isinstance(adapter, ToolAdapter)

    def test_minimal_adapter_has_name(self) -> None:
        adapter = _ConcreteAdapter()
        assert hasattr(adapter, "name")
        assert isinstance(adapter.name, str)

    def test_plan_returns_process_spec(
        self, planned_action: PlannedAction, adapter_context: AdapterContext
    ) -> None:
        adapter = _ConcreteAdapter()
        spec = adapter.plan(planned_action, adapter_context)
        assert isinstance(spec, ProcessSpec)

    def test_parse_returns_observations_tuple(self, sample_result: ProcessResult) -> None:
        adapter = _ConcreteAdapter()
        obs = adapter.parse(sample_result)
        assert isinstance(obs, tuple)
        for o in obs:
            assert isinstance(o, Observation)


# ── Runtime protocol ──────────────────────────────────────────────────────────


class TestRuntimeProtocol:
    def test_runtime_is_a_protocol(self) -> None:
        """Runtime should be a typing.Protocol, not a concrete class."""
        assert isinstance(Runtime, type) and getattr(Runtime, "_is_protocol", False)

    def test_runtime_cannot_be_instantiated(self) -> None:
        with pytest.raises(TypeError):
            Runtime()  # type: ignore[abstract]


# ── Error types ───────────────────────────────────────────────────────────────


class TestAdapterError:
    def test_is_exception(self) -> None:
        err = AdapterError("something went wrong")
        assert isinstance(err, Exception)
        assert str(err) == "something went wrong"

    def test_catch_by_base(self) -> None:
        err = AdapterError("test")
        assert isinstance(err, Exception)
