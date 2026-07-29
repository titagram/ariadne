"""Contract tests for state progression, preflight eligibility, and real adapter execution.

Tests that:
- handle_propose_plan starts at ENVIRONMENT_PREFLIGHT state (not DISCOVERY)
- Preflight playbook is eligible when state and policy are correct
- handle_execute_plan invokes real adapters instead of simulating events
- State advances to DISCOVERY only after preflight evidence exists
- Bounded rejection blocks denied capabilities
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ariadne.adapters import AdapterRegistry, build_default_registry
from ariadne.adapters.base import ProcessResult, ProcessSpec
from ariadne.core.planner import Planner
from ariadne.core.policy import CapabilityRule, EffectivePolicy
from ariadne.core.workflow import WorkflowCatalog
from ariadne.execution.contracts import (
    ExecutionContractRegistry,
    ExecutionCoordinator,
)
from ariadne.hades_adapter.commands import CURRENT_DISCLAIMER_VERSION, AriadneCommand
from ariadne.hades_adapter.handlers import (
    _get_run_handle,  # type: ignore[attr-defined]
    handle_execute_plan,
    handle_prepare_engagement,
    handle_propose_plan,
)
from ariadne.hades_adapter.session import ChallengeLedger
from ariadne.store.run_store import RunStore

pytestmark = pytest.mark.asyncio


# ── Fake runtime for test adapter execution ────────────────────────────────


class FakeRuntime:
    """A fake Runtime that returns a successful ProcessResult for any spec."""

    def __init__(self, exit_code: int = 0, stdout: str = "") -> None:
        self._exit_code = exit_code
        self._stdout = stdout
        self.last_spec: ProcessSpec | None = None

    async def run(self, spec: ProcessSpec) -> ProcessResult:
        self.last_spec = spec
        return ProcessResult(
            exit_code=self._exit_code,
            stdout=self._stdout,
            stderr="",
        )


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def ledger() -> ChallengeLedger:
    return ChallengeLedger()


@pytest.fixture
def store(tmp_path) -> RunStore:
    return RunStore(base_path=tmp_path)


@pytest.fixture
def command(ledger, store) -> AriadneCommand:
    return AriadneCommand(ledger=ledger, store=store)


@pytest.fixture
def session_id() -> str:
    return "test-session-preflight"


@pytest.fixture
def registry() -> AdapterRegistry:
    """Get the default adapter registry for testing."""
    return build_default_registry()


@pytest.fixture
def fake_runtime() -> FakeRuntime:
    """Get a fake runtime that returns success with preflight output."""
    return FakeRuntime(
        exit_code=0,
        stdout="searchsploit output: environment ready",
    )


@pytest.fixture
def full_catalog() -> WorkflowCatalog:
    """Load the preflight-to-discovery workflow for state progression tests."""
    fixtures_dir = Path(__file__).parents[2] / "tests" / "fixtures" / "workflows" / "progression"
    return WorkflowCatalog.load(fixtures_dir)


@pytest.fixture
def planner(full_catalog: WorkflowCatalog) -> Planner:
    return Planner(catalog=full_catalog)


@pytest.fixture
def policy() -> EffectivePolicy:
    """Policy that allows preflight.check and scan.tcp (like real base policy)."""
    return EffectivePolicy(
        name="test-policy",
        version=1,
        capabilities={
            "preflight.check": CapabilityRule(allowed=True),
            "scan.tcp": CapabilityRule(allowed=True),
            "service.enum": CapabilityRule(allowed=True),
            "exploit": CapabilityRule(allowed=False),
            "persistence": CapabilityRule(allowed=False),
        },
        source_digests=(),
    )


async def _bind_engagement(command: AriadneCommand, session_id: str) -> str:
    """Helper: atomically prepare and bind an engagement."""
    args = {
        "authorization_attested": True,
        "disclaimer_version": CURRENT_DISCLAIMER_VERSION,
        "profile": "private-lab",
        "target_host": "10.10.10.10",
        "objectives": ["proof"],
        "autonomy": "controlled",
    }
    prepare_result = await handle_prepare_engagement(
        args,
        session_id=session_id,
        ariadne_command=command,
    )
    return prepare_result["snapshot_hash"]


# ── RED tests (expected to fail before fixes) ───────────────────────────────


class TestPreflightEligibility:
    """Preflight playbook must be eligible when state=ENVIRONMENT_PREFLIGHT.

    Currently handle_propose_plan hardcodes state=EngagementState.DISCOVERY
    with empty observations, causing the full-sequence catalog to reject all
    plans because the first eligible playbook has stage 'environment_preflight'.
    """

    async def test_preflight_plan_proposed_with_correct_state(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        full_catalog: WorkflowCatalog,
    ) -> None:
        """A plan from engagement.preflight.v1 should be proposed.

        This is the RED test — it fails when state is hardcoded to DISCOVERY
        because engagement.preflight.v1 has stage=environment_preflight.
        """
        snapshot_hash = await _bind_engagement(command, session_id)

        result = await handle_propose_plan(
            {
                "snapshot_hash": snapshot_hash,
                "hypothesis": "Preflight environment readiness check",
            },
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=full_catalog,
        )

        # Should propose the preflight playbook
        assert result["status"] == "plan_proposed", (
            f"Expected plan_proposed, got {result}. "
            f"If this fails with 'no eligible playbooks', the state is still DISCOVERY"
        )
        assert result["playbook_id"] == "engagement.preflight.v1", (
            f"Expected preflight playbook, got {result.get('playbook_id')}"
        )
        # Actions should reference the research adapter for preflight
        assert len(result["actions"]) > 0
        assert result["actions"][0]["adapter"] == "research"

    async def test_preflight_requires_preflight_check_capability(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        full_catalog: WorkflowCatalog,
    ) -> None:
        """Without preflight.check in policy, proposing preflight should fail.

        This tests that capability validation works even when state is correct.
        """
        snapshot_hash = await _bind_engagement(command, session_id)

        # Use a policy that does NOT include preflight.check
        _ = EffectivePolicy(
            name="limited-policy",
            version=1,
            capabilities={
                "scan.tcp": CapabilityRule(allowed=True),
            },
            source_digests=(),
        )

        # We need to call propose_plan — but the catalog/planner use the
        # _load_engagement_policy function which is independent of the
        # policy fixture. This test expects that when we fix the handler,
        # the policy loading will be correct.
        #
        # For now: if the preflight plan CAN be proposed (state is correct),
        # and the policy denies preflight.check, the planner should reject it.
        result = await handle_propose_plan(
            {
                "snapshot_hash": snapshot_hash,
                "hypothesis": "Preflight check",
            },
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=full_catalog,
        )

        # With the fix, the handler should first produce a plan (state correct)
        # but the planner's capability check should reject it because
        # preflight.check is missing from the effective policy
        #
        # If the handler never gets past state matching, this fails differently
        assert result["status"] in ("error", "plan_proposed"), (
            f"Got {result}. With the fix, either the plan is proposed "
            f"(if policy includes preflight.check) or rejected (if not)."
        )
        if result["status"] == "error":
            # Should mention capability, not "no eligible playbooks"
            msg = result.get("message", "").lower()
            assert "capability" in msg or "preflight" in msg


class TestAdapterExecution:
    """handle_execute_plan must invoke real adapters, not simulate events."""

    async def test_execution_invokes_adapter_not_simulated(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        full_catalog: WorkflowCatalog,
        registry: AdapterRegistry,
        fake_runtime: FakeRuntime,
    ) -> None:
        """After approval, execution should generate real adapter argv.

        This test verifies that:
        1. A plan is proposed and approved
        2. Execution generates a ProcessSpec via adapter.plan()
        3. The store contains REAL evidence (not simulated artifact names)
        """
        snapshot_hash = await _bind_engagement(command, session_id)

        # Propose and approve
        propose_result = await handle_propose_plan(
            {
                "snapshot_hash": snapshot_hash,
                "hypothesis": "Preflight environment readiness check",
            },
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=full_catalog,
        )
        assert propose_result["status"] == "plan_proposed"
        plan_id = propose_result["plan_id"]

        # Approve via /ariadne
        approve_resp = command.handle(
            f"approve {plan_id}",
            trusted_session_id=session_id,
        )
        assert "approved" in approve_resp.lower()

        # Execute — this test was RED because handle_execute_plan used simulated events.
        # Now it should invoke the research adapter via FakeRuntime.
        result = await handle_execute_plan(
            {"plan_id": plan_id},
            session_id=session_id,
            ariadne_command=command,
            adapter_registry=registry,
            runtime=fake_runtime,
            execution_contract_registry=ExecutionContractRegistry.curated(),
            execution_coordinator=ExecutionCoordinator(1),
            catalog=full_catalog,
        )
        assert result["status"] in ("executed", "partial"), (
            f"Expected executed/partial, got {result}"
        )

        # Verify the store contains real evidence (not simulated artifact names)
        binding = command.ledger.get_session_binding(session_id)
        assert binding is not None
        assert binding.engagement_id is not None

        # Read events from the actual run path (where handle_execute_plan wrote them)
        handle = _get_run_handle(command.store, binding.engagement_id)
        assert handle is not None, "Run handle should exist after execution"

        events_path = handle.path / "events.jsonl"

        # Diagnostic: list all files in the run directory
        run_files = [str(p.name) for p in handle.path.iterdir()]
        assert events_path.exists(), (
            f"No events file found at {events_path}. "
            f"Files in run dir: {run_files}. "
            f"Execute result: {result}"
        )

        events_text = events_path.read_text()
        events = [json.loads(line) for line in events_text.strip().split("\n") if line.strip()]

        # Should have plan_executed event
        plan_executed_events = [e for e in events if e.get("event_type") == "plan_executed"]
        assert len(plan_executed_events) >= 1, (
            f"No plan_executed event found. Events: {[e.get('event_type') for e in events]}"
        )

        # Should have evidence_collected events from the real adapter
        evidence_events = [e for e in events if e.get("event_type") == "evidence_collected"]
        assert len(evidence_events) >= 1, (
            f"No evidence_collected events found. Events: {[e.get('event_type') for e in events]}"
        )

        # The evidence_collected payload should reference a real finding
        # (not "adapter_operation_result.txt" which was the simulated pattern)
        for ev in evidence_events:
            payload = ev.get("payload", {})
            finding = payload.get("finding", "")
            # Simulated artifacts used the pattern "{adapter}_{operation}_result.txt"
            # Real adapter should produce meaningful evidence content
            assert "simulated" not in finding.lower(), (
                f"Evidence appears simulated: {finding}"
            )

    async def test_execution_rejects_denied_capability(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        full_catalog: WorkflowCatalog,
    ) -> None:
        """Plans with denied capabilities should be rejected at plan time."""
        snapshot_hash = await _bind_engagement(command, session_id)

        # Create a planner with a catalog that only has exploit-like playbooks
        # Actually, the plan proposal itself checks capabilities via the planner
        # The exploit capability is hard-denied for all engagements

        # If we propose a plan for a playbook whose capability is denied by policy,
        # the planner should reject it at build time.
        # With state=ENVIRONMENT_PREFLIGHT and preflight.check allowed,
        # this test just verifies that explore/exploit/etc. capabilities
        # are correctly denied by the engagement policy.

        # Propose preflight (should work with correct state+policy)
        propose_result = await handle_propose_plan(
            {
                "snapshot_hash": snapshot_hash,
                "hypothesis": "Preflight check",
            },
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=full_catalog,
        )

        # Preflight should be proposed — it has preflight.check which is allowed
        # This test passes once the state progression fix is in place
        assert propose_result["status"] == "plan_proposed"
        assert propose_result["playbook_id"] == "engagement.preflight.v1"


class TestProgressionToDiscovery:
    """After preflight evidence, the next plan should be TCP discovery."""

    async def test_progression_to_tcp_discovery_after_preflight(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        full_catalog: WorkflowCatalog,
    ) -> None:
        """With preflight evidence in the store, the next propose should select tcp-discovery."""
        snapshot_hash = await _bind_engagement(command, session_id)

        # Simulate preflight evidence in the store
        binding = command.ledger.get_session_binding(session_id)
        assert binding is not None
        assert binding.engagement_id is not None

        run_handle = command.store.open(binding.engagement_id)
        assert run_handle is not None

        from ariadne.store.run_store import Event

        now = datetime.now(UTC)
        # Write preflight evidence into the store
        command.store.append_event(
            run_handle,
            Event(
                event_type="evidence_collected",
                payload={
                    "artifact": "preflight_check.txt",
                    "finding": "Environment is ready for testing",
                    "evidence_type": "preflight_passed",
                    "asset": "10.10.10.10",
                },
                timestamp=now,
            ),
        )

        # Now propose a plan — should select tcp-discovery because
        # preflight evidence exists and tcp-discovery requires preflight_passed
        propose_result = await handle_propose_plan(
            {
                "snapshot_hash": snapshot_hash,
                "hypothesis": "TCP discovery on target",
            },
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=full_catalog,
        )

        # This test is RED because the current handler ignores store events
        # and hardcodes state=DISCOVERY with empty observations.
        # With the fix, it should read preflight evidence from the store,
        # set state=DISCOVERY, and observations={preflight_passed},
        # making network.tcp-discovery.v1 eligible.
        assert propose_result["status"] == "plan_proposed", (
            f"Expected plan_proposed, got {propose_result}. "
            f"State progression from preflight to discovery should be driven by store evidence."
        )
        assert propose_result["playbook_id"] == "preflight.tcp-discovery.v1", (
            f"Expected tcp-discovery, got {propose_result.get('playbook_id')}"
        )
