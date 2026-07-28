"""Contract tests for the PostExAdapter Linux post-exploitation operations.

Verifies operation dispatch, command construction, output parsing, and
classification for Linux-specific post-exploitation actions:
identity, sudo_rules, suid_files, file_capabilities, scheduled_jobs,
services, linpeas_standard, and pspy_bounded.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from ariadne.adapters.base import AdapterContext, PlannedAction
from ariadne.adapters.postex import PostExAdapter
from ariadne.core.engagement import TargetSpec
from ariadne.core.errors import AdapterError
from ariadne.runtime.process import ProcessResult, ProcessStatus

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def adapter() -> PostExAdapter:
    return PostExAdapter()


@pytest.fixture
def linux_context() -> AdapterContext:
    return AdapterContext(
        target=TargetSpec(host="10.10.10.10"),
        snapshot_hash="abc123",
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name="postex_linux",
    )


def action(operation: str, **inputs: object) -> PlannedAction:
    return PlannedAction(operation=operation, inputs=inputs)


def linpeas_output() -> str:
    """Load fixture LinPEAS output."""
    path = Path(__file__).parent.parent / "fixtures" / "postex" / "linpeas_output.txt"
    return path.read_text()


def pspy_output() -> str:
    """Load fixture pspy output."""
    path = Path(__file__).parent.parent / "fixtures" / "postex" / "pspy_output.txt"
    return path.read_text()


# ── Plan (command building) ───────────────────────────────────────────────────


class TestLinuxPostexPlan:
    """Verify that PostExAdapter.plan() builds correct ProcessSpec args for
    Linux operations."""

    def test_identity_plan(self, adapter: PostExAdapter, linux_context: AdapterContext) -> None:
        spec = adapter.plan(action("identity"), linux_context)
        assert "id" in spec.argv
        assert spec.timeout_seconds <= 60

    def test_sudo_rules_plan(self, adapter: PostExAdapter, linux_context: AdapterContext) -> None:
        spec = adapter.plan(action("sudo_rules"), linux_context)
        argv_str = " ".join(spec.argv)
        assert "sudo" in argv_str
        assert spec.timeout_seconds <= 60

    def test_suid_files_plan(self, adapter: PostExAdapter, linux_context: AdapterContext) -> None:
        spec = adapter.plan(action("suid_files"), linux_context)
        argv_str = " ".join(spec.argv)
        assert "find" in argv_str
        assert spec.timeout_seconds <= 120

    def test_file_capabilities_plan(
        self, adapter: PostExAdapter, linux_context: AdapterContext
    ) -> None:
        spec = adapter.plan(action("file_capabilities"), linux_context)
        argv_str = " ".join(spec.argv)
        assert "getcap" in argv_str or "capsh" in argv_str
        assert spec.timeout_seconds <= 120

    def test_scheduled_jobs_plan(
        self, adapter: PostExAdapter, linux_context: AdapterContext
    ) -> None:
        spec = adapter.plan(action("scheduled_jobs"), linux_context)
        argv_str = " ".join(spec.argv).lower()
        assert "cron" in argv_str or "systemctl" in argv_str or "at" in argv_str
        assert spec.timeout_seconds <= 120

    def test_services_plan(self, adapter: PostExAdapter, linux_context: AdapterContext) -> None:
        spec = adapter.plan(action("services"), linux_context)
        argv_str = " ".join(spec.argv).lower()
        assert "systemctl" in argv_str or "service" in argv_str
        assert spec.timeout_seconds <= 120

    def test_linpeas_default_plan_is_not_aggressive(
        self, adapter: PostExAdapter, linux_context: AdapterContext
    ) -> None:
        spec = adapter.plan(action("linpeas"), linux_context)
        assert "-a" not in spec.argv
        assert spec.timeout_seconds <= 900

    def test_pspy_bounded_timeout(
        self, adapter: PostExAdapter, linux_context: AdapterContext
    ) -> None:
        spec = adapter.plan(action("pspy_bounded"), linux_context)
        assert spec.timeout_seconds <= 120
        # pspy should run for a bounded duration, not indefinitely

    def test_unknown_operation_raises(
        self, adapter: PostExAdapter, linux_context: AdapterContext
    ) -> None:
        with pytest.raises(AdapterError, match="unknown|invalid|supported"):
            adapter.plan(action("invalid_operation"), linux_context)

    def test_all_operations_set_bounded_limits(
        self, adapter: PostExAdapter, linux_context: AdapterContext
    ) -> None:
        for op in ("identity", "sudo_rules", "suid_files", "services"):
            spec = adapter.plan(action(op), linux_context)
            assert 1 <= spec.timeout_seconds <= 3600
            assert spec.max_output_bytes >= 1024


# ── Parse ─────────────────────────────────────────────────────────────────────


class TestLinuxPostexParse:
    """Verify that PostExAdapter.parse() extracts typed observations from
    Linux post-exploitation tool output."""

    def test_parse_empty_output(self, adapter: PostExAdapter) -> None:
        result = ProcessResult(exit_code=0, stdout="", stderr="")
        obs = adapter.parse(result)
        assert obs == ()

    def test_parse_linpeas_output(self, adapter: PostExAdapter) -> None:
        result = ProcessResult(exit_code=0, stdout=linpeas_output(), stderr="")
        obs = adapter.parse(result)
        assert len(obs) >= 1
        assert obs[0].source == "postex"

    def test_parse_pspy_output(self, adapter: PostExAdapter) -> None:
        result = ProcessResult(exit_code=0, stdout=pspy_output(), stderr="")
        obs = adapter.parse(result)
        assert len(obs) >= 1

    def test_parse_malformed_output_skips_gracefully(
        self, adapter: PostExAdapter
    ) -> None:
        result = ProcessResult(exit_code=0, stdout="not useful at all\n", stderr="")
        obs = adapter.parse(result)
        assert isinstance(obs, tuple)

    def test_parse_identity_output(self, adapter: PostExAdapter) -> None:
        result = ProcessResult(
            exit_code=0,
            stdout="uid=1001(www-data) gid=1001(www-data) groups=1001(www-data)\n",
            stderr="",
        )
        obs = adapter.parse(result)
        assert len(obs) >= 1


# ── Classify ──────────────────────────────────────────────────────────────────


class TestLinuxPostexClassify:
    """Verify PostExAdapter.classify() returns appropriate classifications."""

    def test_completed_classification(self, adapter: PostExAdapter) -> None:
        result = ProcessResult(exit_code=0, stdout="uid=1000(user)\n", stderr="")
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
        result = ProcessResult(exit_code=1, stdout="", stderr="error: not found")
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

    def test_collect_returns_empty(self, adapter: PostExAdapter) -> None:
        import asyncio

        result = ProcessResult(exit_code=0, stdout="data", stderr="")
        artifacts = asyncio.run(adapter.collect(result, object()))
        assert isinstance(artifacts, tuple)

    def test_cleanup_returns_success(self, adapter: PostExAdapter) -> None:
        import asyncio

        ctx = AdapterContext(
            target=TargetSpec(host="10.10.10.10"),
            snapshot_hash="abc123",
            engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
            adapter_name="postex_linux",
        )
        cleanup = asyncio.run(adapter.cleanup(ctx))
        assert cleanup.success
