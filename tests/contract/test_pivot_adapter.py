"""Contract tests for the PivotAdapter tunnel lifecycle operations.

Verifies operation dispatch, command construction, output parsing, and
classification for pivot operations: start_tunnel, add_route, remove_route,
and stop_tunnel. Ligolo-ng is primary; Chisel and SSH are explicit fallbacks.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from ariadne.adapters.base import AdapterContext, PlannedAction
from ariadne.adapters.pivot import PivotAdapter
from ariadne.core.engagement import TargetSpec
from ariadne.core.errors import AdapterError
from ariadne.runtime.process import ProcessResult, ProcessStatus

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def adapter() -> PivotAdapter:
    return PivotAdapter()


def _pivot_context(
    host: str = "10.10.10.10",
    extra_env: dict[str, str] | None = None,
) -> AdapterContext:
    env: dict[str, str] = {}
    if extra_env:
        env.update(extra_env)
    return AdapterContext(
        target=TargetSpec(host=host),
        snapshot_hash="abc123",
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name="pivot",
        environment=env,
    )


@pytest.fixture
def pivot_context() -> AdapterContext:
    return _pivot_context()


def action(operation: str, **inputs: object) -> PlannedAction:
    return PlannedAction(operation=operation, inputs=inputs)


def load_fixture(name: str) -> str:
    """Load a fixture file from tests/fixtures/pivot/."""
    path = Path(__file__).parent.parent / "fixtures" / "pivot" / name
    return path.read_text()


# ── Plan (command building) ───────────────────────────────────────────────────


class TestPivotPlan:
    """Verify that PivotAdapter.plan() builds correct ProcessSpec args."""

    def test_start_tunnel_plan(
        self, adapter: PivotAdapter, pivot_context: AdapterContext
    ) -> None:
        spec = adapter.plan(action("start_tunnel"), pivot_context)
        argv_str = " ".join(spec.argv).lower()
        assert "ligolo" in argv_str or "proxy" in argv_str
        assert spec.timeout_seconds >= 1

    def test_start_tunnel_uses_ligolo_by_default(
        self, adapter: PivotAdapter, pivot_context: AdapterContext
    ) -> None:
        spec = adapter.plan(action("start_tunnel"), pivot_context)
        argv_str = " ".join(spec.argv).lower()
        assert "ligolo" in argv_str
        assert "proxy" in argv_str

    def test_add_route_plan(
        self, adapter: PivotAdapter, pivot_context: AdapterContext
    ) -> None:
        spec = adapter.plan(
            action("add_route", network="192.168.1.0/24"), pivot_context
        )
        argv_str = " ".join(spec.argv).lower()
        assert "route" in argv_str
        assert spec.timeout_seconds <= 60

    def test_add_route_with_explicit_network(
        self, adapter: PivotAdapter, pivot_context: AdapterContext
    ) -> None:
        """Verify that add_route includes the target network."""
        spec = adapter.plan(
            action("add_route", network="10.10.10.0/24"), pivot_context
        )
        argv_str = " ".join(spec.argv).lower()
        assert "10.10.10.0/24" in argv_str or "10.10.10" in argv_str

    def test_remove_route_plan(
        self, adapter: PivotAdapter, pivot_context: AdapterContext
    ) -> None:
        spec = adapter.plan(
            action("remove_route", network="172.16.5.0/24"), pivot_context
        )
        argv_str = " ".join(spec.argv).lower()
        assert "route" in argv_str
        assert "remove" in argv_str or "del" in argv_str or "delete" in argv_str

    def test_stop_tunnel_plan(
        self, adapter: PivotAdapter, pivot_context: AdapterContext
    ) -> None:
        spec = adapter.plan(action("stop_tunnel"), pivot_context)
        argv_str = " ".join(spec.argv).lower()
        assert "stop" in argv_str or "kill" in argv_str or "cleanup" in argv_str

    def test_unknown_operation_raises(
        self, adapter: PivotAdapter, pivot_context: AdapterContext
    ) -> None:
        with pytest.raises(AdapterError, match="unknown|invalid|supported"):
            adapter.plan(action("invalid_operation"), pivot_context)

    def test_all_operations_set_bounded_limits(
        self, adapter: PivotAdapter, pivot_context: AdapterContext
    ) -> None:
        for op in ("start_tunnel", "add_route", "remove_route", "stop_tunnel"):
            kwargs = {}
            if op in ("add_route", "remove_route"):
                kwargs["network"] = "192.168.1.0/24"
            spec = adapter.plan(action(op, **kwargs), pivot_context)
            assert 1 <= spec.timeout_seconds <= 3600
            assert spec.max_output_bytes >= 1024


# ── Parse ─────────────────────────────────────────────────────────────────────


class TestPivotParse:
    """Verify that PivotAdapter.parse() extracts structured observations."""

    def test_parse_empty_output(self, adapter: PivotAdapter) -> None:
        result = ProcessResult(exit_code=0, stdout="", stderr="")
        obs = adapter.parse(result)
        assert obs == ()

    def test_parse_tunnel_started(self, adapter: PivotAdapter) -> None:
        result = ProcessResult(
            exit_code=0, stdout=load_fixture("tunnel_started.json"), stderr=""
        )
        obs = adapter.parse(result)
        assert len(obs) >= 1
        assert obs[0].source == "pivot"

    def test_parse_discovered_host(self, adapter: PivotAdapter) -> None:
        result = ProcessResult(
            exit_code=0, stdout=load_fixture("discovered-host.json"), stderr=""
        )
        obs = adapter.parse(result)
        assert len(obs) >= 1
        assert obs[0].source == "pivot"

    def test_parse_route_added(self, adapter: PivotAdapter) -> None:
        result = ProcessResult(
            exit_code=0, stdout=load_fixture("route_added.txt"), stderr=""
        )
        obs = adapter.parse(result)
        assert len(obs) >= 1

    def test_parse_tunnel_stopped(self, adapter: PivotAdapter) -> None:
        result = ProcessResult(
            exit_code=0, stdout=load_fixture("tunnel_stopped.txt"), stderr=""
        )
        obs = adapter.parse(result)
        assert len(obs) >= 1


# ── Classify ──────────────────────────────────────────────────────────────────


class TestPivotClassify:
    """Verify PivotAdapter.classify() returns appropriate classifications."""

    def test_completed_classification(self, adapter: PivotAdapter) -> None:
        result = ProcessResult(exit_code=0, stdout="tunnel ready\n", stderr="")
        obs = adapter.parse(result)
        classification = adapter.classify(result, obs)
        assert classification.kind in ("success", "unknown")

    def test_timeout_classification(self, adapter: PivotAdapter) -> None:
        result = ProcessResult(
            exit_code=-1,
            stdout="",
            stderr="",
            status=ProcessStatus.TIMED_OUT,
            timed_out=True,
        )
        classification = adapter.classify(result, ())
        assert classification.kind == "partial"

    def test_failed_execution(self, adapter: PivotAdapter) -> None:
        result = ProcessResult(exit_code=1, stdout="", stderr="connection refused")
        classification = adapter.classify(result, ())
        assert classification.kind == "failure"


# ── State management ──────────────────────────────────────────────────────────


class TestPivotState:
    """Verify PivotAdapter tracks tunnel state across operations."""

    def test_start_tunnel_records_session_id(
        self, adapter: PivotAdapter, pivot_context: AdapterContext
    ) -> None:
        adapter.plan(action("start_tunnel"), pivot_context)
        assert len(adapter._tunnels) >= 1
        tunnel_id = list(adapter._tunnels.keys())[0]
        assert tunnel_id.startswith("tun_")
        assert adapter._tunnels[tunnel_id]["target"] == str(pivot_context.target.host)

    def test_stop_tunnel_cleans_up_session(
        self, adapter: PivotAdapter, pivot_context: AdapterContext
    ) -> None:
        adapter.plan(action("start_tunnel"), pivot_context)
        assert len(adapter._tunnels) >= 1
        tunnel_id = list(adapter._tunnels.keys())[0]
        adapter.plan(action("stop_tunnel", tunnel_id=tunnel_id), pivot_context)
        assert tunnel_id not in adapter._tunnels

    def test_cleanup_removes_all_tunnels(
        self, adapter: PivotAdapter, pivot_context: AdapterContext
    ) -> None:
        import asyncio

        adapter.plan(action("start_tunnel"), pivot_context)
        assert len(adapter._tunnels) >= 1
        result = asyncio.run(adapter.cleanup(pivot_context))
        assert result.success
        assert len(adapter._tunnels) == 0


# ── Protocol shape ────────────────────────────────────────────────────────────


class TestPivotProtocol:
    """Verify PivotAdapter satisfies the ToolAdapter protocol."""

    def test_has_name(self, adapter: PivotAdapter) -> None:
        assert PivotAdapter.name == "pivot"

    def test_is_tool_adapter(self, adapter: PivotAdapter) -> None:
        from ariadne.adapters.base import ToolAdapter

        assert isinstance(adapter, ToolAdapter)

    def test_probe_returns_available(self, adapter: PivotAdapter) -> None:
        from ariadne.adapters.base import Runtime

        class _MinimalRuntime(Runtime):
            async def run(self, spec: object) -> ProcessResult:
                return ProcessResult(exit_code=0, stdout="", stderr="")

        import asyncio

        result = asyncio.run(adapter.probe(_MinimalRuntime()))
        assert result.available

    def test_cleanup_returns_success(self, adapter: PivotAdapter) -> None:
        import asyncio

        ctx = _pivot_context()
        cleanup = asyncio.run(adapter.cleanup(ctx))
        assert cleanup.success
