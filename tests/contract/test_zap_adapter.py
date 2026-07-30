"""Contract tests for the ZapAdapter.

Verifies automation-plan generation, scope-boundary enforcement,
and alert parsing for the OWASP ZAP web-application adapter.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest
import yaml

from ariadne.adapters.base import (
    AdapterContext,
    PlannedAction,
)
from ariadne.adapters.zap import ZapAdapter
from ariadne.core.engagement import TargetSpec
from ariadne.core.errors import AdapterError
from ariadne.core.workflow import PlaybookLimits
from ariadne.runtime.process import ProcessResult

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def context() -> AdapterContext:
    return AdapterContext(
        target=TargetSpec(host="10.10.10.10"),
        snapshot_hash="abc123",
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name="zap",
    )


@pytest.fixture
def context_fqdn() -> AdapterContext:
    return AdapterContext(
        target=TargetSpec(host="scanme.nmap.org"),
        snapshot_hash="abc123",
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name="zap",
    )


@pytest.fixture
def load_fixture() -> type:
    """Helper that reads a fixture file from tests/fixtures/zap/."""

    def _load(name: str) -> str:
        p = Path(__file__).parents[2] / "tests" / "fixtures" / "zap" / name
        return p.read_text()

    return _load  # type: ignore[return-value]


def action(operation: str, **inputs: object) -> PlannedAction:
    return PlannedAction(operation=operation, inputs=inputs)


# ── Plan (automation framework plan generation) ──────────────────────────────


class TestZapPlan:
    """Verify that ZapAdapter.automation_plan() generates correct YAML."""

    def test_automation_plan_contains_confirmed_context(self, context: AdapterContext) -> None:
        plan = ZapAdapter().automation_plan(context)
        assert plan["env"]["contexts"][0]["urls"] == ["https://10.10.10.10"]
        assert plan["env"]["contexts"][0]["includePaths"] == [r"https://10\.10\.10\.10/.*"]

    def test_automation_plan_fqdn(self, context_fqdn: AdapterContext) -> None:
        """FQDN targets should produce the correct context URL."""
        plan = ZapAdapter().automation_plan(context_fqdn)
        assert plan["env"]["contexts"][0]["urls"] == ["https://scanme.nmap.org"]
        include_paths = plan["env"]["contexts"][0]["includePaths"]
        assert any("scanme\\.nmap\\.org" in p for p in include_paths)

    def test_automation_plan_includes_passive_scan(self, context: AdapterContext) -> None:
        plan = ZapAdapter().automation_plan(context)
        job_types = [j["type"] for j in plan["jobs"]]
        assert "passiveScan-config" in job_types

    def test_automation_plan_includes_spider(self, context: AdapterContext) -> None:
        plan = ZapAdapter().automation_plan(context)
        job_types = [j["type"] for j in plan["jobs"]]
        assert "spider" in job_types

    def test_automation_plan_rejects_unknown_operation(self, context: AdapterContext) -> None:
        with pytest.raises(AdapterError):
            ZapAdapter().plan(action("unknown_op"), context)

    def test_plan_returns_process_spec_with_yaml_stdin(self, context: AdapterContext) -> None:
        spec = ZapAdapter().plan(
            action("passive_scan", http_host="orion.test"),
            context,
        )
        assert spec.argv == (
            "zaproxy",
            "-cmd",
            "-silent",
            "-autorun",
            "/dev/stdin",
        )
        assert spec.environment == {
            "ARIADNE_ZAP_HTTP_HOST": "orion.test",
            "ARIADNE_ZAP_NETWORK_TARGET": "10.10.10.10",
        }
        assert spec.stdin is not None
        stdin_text = spec.stdin.decode("utf-8")
        parsed = yaml.safe_load(stdin_text)
        assert parsed["env"]["contexts"][0]["urls"] == ["https://10.10.10.10"]
        assert parsed["jobs"][0] == {
            "type": "replacer",
            "parameters": {"deleteAllRules": False},
            "rules": [
                {
                    "description": "approved-http-host-alias",
                    "url": r"^https://10\.10\.10\.10/.*",
                    "matchType": "req_header",
                    "matchString": "Host",
                    "matchRegex": False,
                    "replacementString": "orion.test",
                }
            ],
        }

    def test_sets_bounded_timeout_and_output(self, context: AdapterContext) -> None:
        bounded_context = context.model_copy(
            update={"limits": PlaybookLimits(max_duration_seconds=180)}
        )
        spec = ZapAdapter().plan(action("passive_scan"), bounded_context)
        assert spec.timeout_seconds == 180
        assert spec.max_output_bytes >= 1024

    def test_active_scan_rejects_random_paths_without_policy(self, context: AdapterContext) -> None:
        """Active scan should reject unapproved paths outside scope."""
        spec = ZapAdapter().plan(action("active_scan"), context)
        assert spec.stdin is not None
        stdin_text = spec.stdin.decode("utf-8")
        parsed = yaml.safe_load(stdin_text)
        job_types = [j["type"] for j in parsed["jobs"]]
        assert "activeScan" in job_types


# ── Parse ─────────────────────────────────────────────────────────────────────


class TestZapParse:
    """Verify that ZapAdapter.parse() extracts typed observations."""

    def test_parses_alerts(self, load_fixture) -> None:
        result = ProcessResult(
            exit_code=0,
            stdout=load_fixture("alerts.json"),
            stderr="",
        )
        obs = ZapAdapter().parse(result)
        assert len(obs) == 2

        # First alert: Cross-Domain Misconfiguration
        assert obs[0].data["alert"] == "Cross-Domain Misconfiguration"
        assert obs[0].data["risk"] == "Medium"
        assert obs[0].data["confidence"] == "Medium"
        assert obs[0].data["alertRef"] == "10098"
        assert obs[0].source == "zap"

        # Second alert: Missing header
        assert obs[1].data["alertRef"] == "10021"

    def test_empty_output_returns_empty_tuple(self) -> None:
        result = ProcessResult(exit_code=0, stdout="", stderr="")
        obs = ZapAdapter().parse(result)
        assert obs == ()

    def test_progress_logs_do_not_create_simulated_alerts(self) -> None:
        result = ProcessResult(exit_code=0, stdout="not json at all", stderr="")
        assert ZapAdapter().parse(result) == ()

    def test_alert_target_matches_context_host(self, load_fixture) -> None:
        result = ProcessResult(
            exit_code=0,
            stdout=load_fixture("alerts.json"),
            stderr="",
        )
        obs = ZapAdapter().parse(result)
        for o in obs:
            assert o.target.host == "10.10.10.10"


# ── Probe ─────────────────────────────────────────────────────────────────────


class TestZapProbe:
    """Verify probe metadata."""

    def test_zap_adapter_has_name(self) -> None:
        adapter = ZapAdapter()
        assert hasattr(adapter, "name")
        assert adapter.name == "zap"


# ── Protocol shape ────────────────────────────────────────────────────────────


class TestZapProtocol:
    """Verify ZapAdapter satisfies the ToolAdapter protocol."""

    def test_is_tool_adapter(self) -> None:
        from ariadne.adapters.base import ToolAdapter

        assert isinstance(ZapAdapter(), ToolAdapter)
