"""Contract tests for the PostExAdapter Windows post-exploitation operations.

Verifies operation dispatch, command construction, output parsing, and
classification for Windows-specific post-exploitation actions:
identity, token_privileges, services, scheduled_tasks, registry,
winpeas_standard, privesccheck, and seatbelt_selected.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from ariadne.adapters.base import AdapterContext, PlannedAction
from ariadne.adapters.postex import PostExAdapter
from ariadne.core.engagement import TargetSpec
from ariadne.core.errors import AdapterError, AdapterPolicyError
from ariadne.runtime.process import ProcessResult, ProcessStatus

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def adapter() -> PostExAdapter:
    return PostExAdapter()


def _windows_context(
    host: str = "10.10.10.10",
    extra_env: dict[str, str] | None = None,
) -> AdapterContext:
    env = {"TARGET_OS": "windows"}
    if extra_env:
        env.update(extra_env)
    return AdapterContext(
        target=TargetSpec(host=host),
        snapshot_hash="abc123",
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name="postex_windows",
        environment=env,
    )


@pytest.fixture
def windows_context() -> AdapterContext:
    return _windows_context()


@pytest.fixture
def windows_context_with_capability() -> AdapterContext:
    return _windows_context(
        extra_env={"CAPABILITY_exploit_payload_upload": "allow"}
    )


def action(operation: str, **inputs: object) -> PlannedAction:
    return PlannedAction(operation=operation, inputs=inputs)


def winpeas_output() -> str:
    """Load fixture WinPEAS output."""
    path = Path(__file__).parent.parent / "fixtures" / "postex" / "winpeas_output.txt"
    return path.read_text()


def privesccheck_output() -> str:
    """Load fixture PrivescCheck output."""
    path = (
        Path(__file__).parent.parent / "fixtures" / "postex" / "privesccheck_output.txt"
    )
    return path.read_text()


def seatbelt_output() -> str:
    """Load fixture Seatbelt output."""
    path = Path(__file__).parent.parent / "fixtures" / "postex" / "seatbelt_output.txt"
    return path.read_text()


# ── Plan (command building) ───────────────────────────────────────────────────


class TestWindowsPostexPlan:
    """Verify that PostExAdapter.plan() builds correct ProcessSpec args for
    Windows operations."""

    def test_identity_plan(
        self, adapter: PostExAdapter, windows_context: AdapterContext
    ) -> None:
        spec = adapter.plan(action("identity"), windows_context)
        argv_str = " ".join(spec.argv).lower()
        assert "whoami" in argv_str
        assert spec.timeout_seconds <= 60

    def test_token_privileges_plan(
        self, adapter: PostExAdapter, windows_context: AdapterContext
    ) -> None:
        spec = adapter.plan(action("token_privileges"), windows_context)
        argv_str = " ".join(spec.argv).lower()
        assert "whoami" in argv_str and "priv" in argv_str
        assert spec.timeout_seconds <= 60

    def test_services_plan(
        self, adapter: PostExAdapter, windows_context: AdapterContext
    ) -> None:
        spec = adapter.plan(action("services"), windows_context)
        argv_str = " ".join(spec.argv).lower()
        assert "sc" in argv_str or "wmic" in argv_str or "powershell" in argv_str
        assert spec.timeout_seconds <= 120

    def test_scheduled_tasks_plan(
        self, adapter: PostExAdapter, windows_context: AdapterContext
    ) -> None:
        spec = adapter.plan(action("scheduled_tasks"), windows_context)
        argv_str = " ".join(spec.argv).lower()
        assert "schtasks" in argv_str or "powershell" in argv_str or "wmic" in argv_str
        assert spec.timeout_seconds <= 120

    def test_registry_plan(
        self, adapter: PostExAdapter, windows_context: AdapterContext
    ) -> None:
        spec = adapter.plan(action("registry"), windows_context)
        argv_str = " ".join(spec.argv).lower()
        assert "reg" in argv_str or "powershell" in argv_str
        assert spec.timeout_seconds <= 120

    def test_winpeas_requires_capability(
        self, adapter: PostExAdapter, windows_context: AdapterContext
    ) -> None:
        """Windows tool upload requires the exploit.payload_upload capability."""
        with pytest.raises(AdapterPolicyError, match="payload_upload|capability"):
            adapter.plan(action("winpeas"), windows_context)

    def test_winpeas_with_capability(
        self, adapter: PostExAdapter, windows_context_with_capability: AdapterContext
    ) -> None:
        """WinPEAS plan succeeds when the payload_upload capability is present."""
        spec = adapter.plan(action("winpeas"), windows_context_with_capability)
        assert spec.timeout_seconds <= 900
        assert spec.max_output_bytes >= 1024

    def test_privesccheck_requires_capability(
        self, adapter: PostExAdapter, windows_context: AdapterContext
    ) -> None:
        """PrivescCheck upload requires the exploit.payload_upload capability."""
        with pytest.raises(AdapterPolicyError, match="payload_upload|capability"):
            adapter.plan(action("privesccheck"), windows_context)

    def test_privesccheck_with_capability(
        self, adapter: PostExAdapter, windows_context_with_capability: AdapterContext
    ) -> None:
        spec = adapter.plan(action("privesccheck"), windows_context_with_capability)
        assert spec.timeout_seconds <= 900

    def test_seatbelt_requires_capability(
        self, adapter: PostExAdapter, windows_context: AdapterContext
    ) -> None:
        """Seatbelt upload requires the exploit.payload_upload capability."""
        with pytest.raises(AdapterPolicyError, match="payload_upload|capability"):
            adapter.plan(action("seatbelt"), windows_context)

    def test_seatbelt_with_capability(
        self, adapter: PostExAdapter, windows_context_with_capability: AdapterContext
    ) -> None:
        spec = adapter.plan(action("seatbelt"), windows_context_with_capability)
        assert spec.timeout_seconds <= 900

    def test_unknown_operation_raises(
        self, adapter: PostExAdapter, windows_context: AdapterContext
    ) -> None:
        with pytest.raises(AdapterError, match="unknown|invalid|supported"):
            adapter.plan(action("invalid_operation"), windows_context)

    def test_all_operations_set_bounded_limits(
        self, adapter: PostExAdapter, windows_context: AdapterContext
    ) -> None:
        for op in ("identity", "token_privileges", "services", "registry"):
            spec = adapter.plan(action(op), windows_context)
            assert 1 <= spec.timeout_seconds <= 3600
            assert spec.max_output_bytes >= 1024


# ── Parse ─────────────────────────────────────────────────────────────────────


class TestWindowsPostexParse:
    """Verify that PostExAdapter.parse() extracts typed observations from
    Windows post-exploitation tool output."""

    def test_parse_empty_output(self, adapter: PostExAdapter) -> None:
        result = ProcessResult(exit_code=0, stdout="", stderr="")
        obs = adapter.parse(result)
        assert obs == ()

    def test_parse_winpeas_output(self, adapter: PostExAdapter) -> None:
        result = ProcessResult(exit_code=0, stdout=winpeas_output(), stderr="")
        obs = adapter.parse(result)
        assert len(obs) >= 1
        assert obs[0].source == "postex"

    def test_parse_privesccheck_output(self, adapter: PostExAdapter) -> None:
        result = ProcessResult(exit_code=0, stdout=privesccheck_output(), stderr="")
        obs = adapter.parse(result)
        assert len(obs) >= 1

    def test_parse_seatbelt_output(self, adapter: PostExAdapter) -> None:
        result = ProcessResult(exit_code=0, stdout=seatbelt_output(), stderr="")
        obs = adapter.parse(result)
        assert len(obs) >= 1


# ── Classify ──────────────────────────────────────────────────────────────────


class TestWindowsPostexClassify:
    """Verify PostExAdapter.classify() returns appropriate classifications."""

    def test_completed_classification(self, adapter: PostExAdapter) -> None:
        result = ProcessResult(exit_code=0, stdout="whoami output\n", stderr="")
        obs = adapter.parse(result)
        classification = adapter.classify(result, obs)
        assert classification.kind in ("success", "unknown")

    def test_timeout_classification(self, adapter: PostExAdapter) -> None:
        result = ProcessResult(
            exit_code=-1,
            stdout="",
            stderr="",
            status=ProcessStatus.TIMED_OUT,
            timed_out=True,
        )
        classification = adapter.classify(result, ())
        assert classification.kind == "partial"

    def test_failed_execution(self, adapter: PostExAdapter) -> None:
        result = ProcessResult(exit_code=1, stdout="", stderr="access denied")
        classification = adapter.classify(result, ())
        assert classification.kind == "failure"


# ── Protocol shape ────────────────────────────────────────────────────────────


class TestPostExProtocol:
    """Verify PostExAdapter satisfies the ToolAdapter protocol."""

    def test_has_name(self, adapter: PostExAdapter) -> None:
        assert PostExAdapter.name == "postex"

    def test_is_tool_adapter(self, adapter: PostExAdapter) -> None:
        from ariadne.adapters.base import ToolAdapter

        assert isinstance(adapter, ToolAdapter)

    def test_probe_returns_available(self, adapter: PostExAdapter) -> None:
        from ariadne.adapters.base import Runtime

        class _MinimalRuntime(Runtime):
            async def run(self, spec: object) -> ProcessResult:
                return ProcessResult(exit_code=0, stdout="", stderr="")

        import asyncio

        result = asyncio.run(adapter.probe(_MinimalRuntime()))
        assert result.available

    def test_cleanup_returns_success(self, adapter: PostExAdapter) -> None:
        import asyncio

        ctx = _windows_context()
        cleanup = asyncio.run(adapter.cleanup(ctx))
        assert cleanup.success
