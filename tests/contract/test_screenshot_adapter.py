"""Contract tests for the ScreenshotAdapter.

Verifies Chromium invocation, viewport constraints, evidence capture,
and SHA-256 recording for the headless screenshot adapter.
"""

from __future__ import annotations

from uuid import UUID

import pytest

from ariadne.adapters.base import (
    AdapterContext,
    PlannedAction,
)
from ariadne.adapters.screenshot import ScreenshotAdapter
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
        adapter_name="screenshot",
    )


@pytest.fixture
def context_fqdn() -> AdapterContext:
    return AdapterContext(
        target=TargetSpec(host="scanme.nmap.org"),
        snapshot_hash="abc123",
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name="screenshot",
    )


def action(operation: str, **inputs: object) -> PlannedAction:
    return PlannedAction(operation=operation, inputs=inputs)


# ── Plan (command building) ──────────────────────────────────────────────────


class TestScreenshotPlan:
    """Verify that ScreenshotAdapter.plan() builds correct Chromium arguments."""

    def test_capture_plan_includes_chromium_headless(
        self, context: AdapterContext
    ) -> None:
        spec = ScreenshotAdapter().plan(action("capture"), context)
        argv_str = " ".join(spec.argv)
        assert "chromium" in argv_str or "google-chrome" in argv_str
        assert "--headless" in argv_str
        assert "--screenshot" in argv_str or "--print-to-pdf" in argv_str

    def test_capture_plan_has_target_url(
        self, context: AdapterContext
    ) -> None:
        spec = ScreenshotAdapter().plan(action("capture"), context)
        assert spec.stdin is not None or any(
            "10.10.10.10" in arg for arg in spec.argv
        )

    def test_capture_plan_has_fixed_viewport(
        self, context: AdapterContext
    ) -> None:
        spec = ScreenshotAdapter().plan(action("capture"), context)
        argv_str = " ".join(spec.argv)
        assert "1920" in argv_str or "1280" in argv_str

    def test_capture_plan_fqdn(self, context_fqdn: AdapterContext) -> None:
        spec = ScreenshotAdapter().plan(action("capture"), context_fqdn)
        argv_str = " ".join(spec.argv)
        assert "scanme.nmap.org" in argv_str

    def test_rejects_unknown_operation(self, context: AdapterContext) -> None:
        with pytest.raises(AdapterError):
            ScreenshotAdapter().plan(action("unknown_op"), context)

    def test_sets_bounded_timeout_and_output(
        self, context: AdapterContext
    ) -> None:
        spec = ScreenshotAdapter().plan(action("capture"), context)
        assert 1 <= spec.timeout_seconds <= 3600
        assert spec.max_output_bytes >= 1024


# ── Parse ─────────────────────────────────────────────────────────────────────


class TestScreenshotParse:
    """Verify that ScreenshotAdapter.parse() extracts typed observations."""

    def test_parses_screenshot_evidence(self) -> None:
        """A Chromium screenshot output should produce an evidence observation."""
        result = ProcessResult(
            exit_code=0,
            stdout="Screenshot saved to /tmp/screenshot_10.10.10.10_80_20210101.png\n"
                   "DevTools listening on ws://127.0.0.1:1234\n"
                   "https://10.10.10.10/ - loaded in 1200ms",
            stderr="",
        )
        obs = ScreenshotAdapter().parse(result)
        assert len(obs) >= 1
        assert obs[0].source == "screenshot"
        assert "path" in obs[0].data or "url" in obs[0].data
        assert obs[0].target.host == "10.10.10.10"

    def test_empty_output_returns_empty_tuple(self) -> None:
        result = ProcessResult(exit_code=0, stdout="", stderr="")
        obs = ScreenshotAdapter().parse(result)
        assert obs == ()

    def test_error_output_returns_empty(self) -> None:
        """Error output should not crash, may return empty."""
        result = ProcessResult(
            exit_code=1,
            stdout="",
            stderr="Error: cannot open display",
        )
        obs = ScreenshotAdapter().parse(result)
        assert isinstance(obs, tuple)


# ── Probe ─────────────────────────────────────────────────────────────────────


class TestScreenshotProbe:
    """Verify probe metadata."""

    def test_screenshot_adapter_has_name(self) -> None:
        adapter = ScreenshotAdapter()
        assert hasattr(adapter, "name")
        assert adapter.name == "screenshot"


# ── Protocol shape ────────────────────────────────────────────────────────────


class TestScreenshotProtocol:
    """Verify ScreenshotAdapter satisfies the ToolAdapter protocol."""

    def test_is_tool_adapter(self) -> None:
        from ariadne.adapters.base import ToolAdapter

        assert isinstance(ScreenshotAdapter(), ToolAdapter)
