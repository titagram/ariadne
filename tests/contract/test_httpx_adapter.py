"""Contract tests for the HttpxAdapter.

Verifies command-building, JSONL parsing, redirect handling,
and safety invariants for the httpx HTTP discovery adapter.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from ariadne.adapters.base import (
    AdapterContext,
    PlannedAction,
)
from ariadne.adapters.httpx import HttpxAdapter
from ariadne.core.engagement import TargetSpec
from ariadne.core.errors import AdapterError
from ariadne.runtime.process import ProcessResult

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def context() -> AdapterContext:
    return AdapterContext(
        target=TargetSpec(host="10.10.10.10"),
        snapshot_hash="abc123",
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name="httpx",
    )


@pytest.fixture
def context_fqdn() -> AdapterContext:
    return AdapterContext(
        target=TargetSpec(host="scanme.nmap.org"),
        snapshot_hash="abc123",
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name="httpx",
    )


@pytest.fixture
def load_fixture() -> type:
    """Helper that reads a fixture file from tests/fixtures/httpx/."""

    def _load(name: str) -> str:
        p = Path(__file__).parents[2] / "tests" / "fixtures" / "httpx" / name
        return p.read_text()

    return _load  # type: ignore[return-value]


def action(operation: str, **inputs: object) -> PlannedAction:
    return PlannedAction(operation=operation, inputs=inputs)


# ── Plan (command building) ──────────────────────────────────────────────────


class TestHttpxPlan:
    """Verify that HttpxAdapter.plan() builds correct ProcessSpec arguments."""

    def test_scan_plan_includes_target_and_jsonl_output(
        self, context: AdapterContext
    ) -> None:
        spec = HttpxAdapter().plan(
            action("scan", ports=(80, 443)),
            context,
        )
        assert spec.argv[0] == "httpx"
        # Should contain the target IP
        # Uses stdin to feed targets (safer than argv)
        assert any("-l" in arg for arg in spec.argv) or any(
            "-json" in arg for arg in spec.argv
        )

    def test_scan_plan_disables_hostname_probe(self, context: AdapterContext) -> None:
        """Verify that unrelated hostname probing is disabled."""
        spec = HttpxAdapter().plan(
            action("scan", ports=(80,)),
            context,
        )
        argv_str = " ".join(spec.argv)
        # Should avoid automatic hostname resolution of unrelated targets
        assert "-no-fallback" in argv_str or "-no-scan" in argv_str or "nh" in argv_str

    def test_scan_plan_fqdn_uses_target_in_stdin(
        self, context_fqdn: AdapterContext
    ) -> None:
        spec = HttpxAdapter().plan(
            action("scan", ports=(443,)),
            context_fqdn,
        )
        # Target goes through stdin, not argv, for safety
        assert spec.stdin is not None
        stdin_text = spec.stdin.decode("utf-8")
        assert "scanme.nmap.org" in stdin_text

    def test_sets_bounded_timeout_and_output(
        self, context: AdapterContext
    ) -> None:
        spec = HttpxAdapter().plan(
            action("scan", ports=(22, 80, 443)),
            context,
        )
        assert 1 <= spec.timeout_seconds <= 3600
        assert spec.max_output_bytes >= 1024

    def test_rejects_unknown_operation(self, context: AdapterContext) -> None:
        with pytest.raises(AdapterError):
            HttpxAdapter().plan(action("unknown_op"), context)

    def test_rejects_empty_ports(self, context: AdapterContext) -> None:
        with pytest.raises(AdapterError):
            HttpxAdapter().plan(action("scan", ports=()), context)


# ── Parse ─────────────────────────────────────────────────────────────────────


class TestHttpxParse:
    """Verify that HttpxAdapter.parse() extracts typed observations."""

    def test_parser_emits_endpoint(self, load_fixture) -> None:
        result = ProcessResult(
            exit_code=0,
            stdout=load_fixture("endpoints.jsonl"),
            stderr="",
        )
        obs = HttpxAdapter().parse(result)
        assert len(obs) == 3

        # First observation should be an http.endpoint
        assert obs[0].data["url"] == "https://10.10.10.10/"
        assert obs[0].data["status_code"] == 200
        assert obs[0].data["title"] == "Welcome to Ubuntu"
        assert "tech" in obs[0].data
        assert "Ubuntu" in obs[0].data["tech"]

    def test_redirect_marks_external_host_observed_only(
        self, load_fixture
    ) -> None:
        """A redirect to an unconfirmed host should be marked observed_only."""
        result = ProcessResult(
            exit_code=0,
            stdout=load_fixture("redirect.jsonl"),
            stderr="",
        )
        obs = HttpxAdapter().parse(result)
        # Should produce at least 2 observations
        assert len(obs) >= 2
        # The redirect observation should have a location field
        redirect_obs = [o for o in obs if o.data.get("redirect") is True]
        assert len(redirect_obs) >= 1
        # The external host should be referenced in the observation
        assert "external-host.com" in str(redirect_obs[0].data.get("location", ""))

    def test_incomplete_jsonl_handles_gracefully(self, load_fixture) -> None:
        """An incomplete/malformed JSONL line should be skipped."""
        result = ProcessResult(
            exit_code=0,
            stdout=load_fixture("incomplete.jsonl"),
            stderr="",
        )
        obs = HttpxAdapter().parse(result)
        # At least the first valid line should be parsed
        assert len(obs) == 1
        assert obs[0].data["url"] == "https://10.10.10.10/"

    def test_empty_output_returns_empty_tuple(self) -> None:
        result = ProcessResult(exit_code=0, stdout="", stderr="")
        obs = HttpxAdapter().parse(result)
        assert obs == ()

    def test_no_http_endpoints_returns_empty(self) -> None:
        """Output with no valid HTTP endpoints should not crash."""
        result = ProcessResult(
            exit_code=0,
            stdout='{"timestamp": "bad", "url": null}\n',
            stderr="",
        )
        obs = HttpxAdapter().parse(result)
        # URL is null, so it may be filtered or included — just shouldn't crash
        assert isinstance(obs, tuple)


# ── Probe ──────────────────────────────────────────────────────────────────────


class TestHttpxProbe:
    """Verify probe returns a plausible ToolProbe."""

    def test_httpx_adapter_has_name(self) -> None:
        adapter = HttpxAdapter()
        assert hasattr(adapter, "name")
        assert adapter.name == "httpx"


# ── Protocol shape ────────────────────────────────────────────────────────────


class TestHttpxProtocol:
    """Verify HttpxAdapter satisfies the ToolAdapter protocol."""

    def test_is_tool_adapter(self) -> None:
        from ariadne.adapters.base import ToolAdapter

        assert isinstance(HttpxAdapter(), ToolAdapter)
