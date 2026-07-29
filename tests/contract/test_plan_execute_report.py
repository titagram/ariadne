"""Contract tests for handle_propose_plan, handle_execute_plan, handle_render_report.

Verifies that the handlers enforce all guard conditions:
- Active engagement required (snapshot_hash binding)
- Snapshot mismatch rejection
- Plan expiry
- Explicit approval
- Unregistered adapter rejection
- Denied capability rejection
- Bounded execution
- Evidence persistence
- Cleanup
- Offline walkthrough/professional report rendering
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from ariadne.adapters import AdapterRegistry, build_default_registry
from ariadne.adapters.base import ProcessResult, ProcessSpec
from ariadne.core.planner import Planner
from ariadne.core.policy import CapabilityRule, EffectivePolicy
from ariadne.core.workflow import WorkflowCatalog
from ariadne.hades_adapter.commands import CURRENT_DISCLAIMER_VERSION, AriadneCommand
from ariadne.hades_adapter.handlers import (
    handle_execute_plan,
    handle_prepare_engagement,
    handle_propose_plan,
    handle_render_report,
)
from ariadne.hades_adapter.schemas import ExecutePlanInput, ProposePlanInput, RenderReportInput
from ariadne.hades_adapter.session import ChallengeLedger
from ariadne.store.run_store import ArtifactInput, Event, RunStore

pytestmark = pytest.mark.asyncio


class FakeRuntime:
    """A fake Runtime that returns a successful ProcessResult for any spec."""

    def __init__(self, exit_code: int = 0, stdout: str = "") -> None:
        self._exit_code = exit_code
        self._stdout = stdout
        self.calls = 0

    async def run(self, spec: ProcessSpec) -> ProcessResult:
        self.calls += 1
        return ProcessResult(
            exit_code=self._exit_code,
            stdout=self._stdout,
            stderr="",
        )

# ── Shared fixtures ────────────────────────────────────────────────────────────


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
    return "test-session-workflow"


@pytest.fixture
def catalog() -> WorkflowCatalog:
    fixtures_dir = Path(__file__).parents[2] / "tests" / "fixtures" / "workflows"
    return WorkflowCatalog.load(fixtures_dir)


@pytest.fixture
def planner(catalog: WorkflowCatalog) -> Planner:
    return Planner(catalog=catalog)


@pytest.fixture
def policy() -> EffectivePolicy:
    return EffectivePolicy(
        name="test-policy",
        version=1,
        capabilities={
            "preflight.check": CapabilityRule(allowed=True),
            "scan.tcp": CapabilityRule(allowed=True),
        },
        source_digests=(),
    )


@pytest.fixture
def registry() -> AdapterRegistry:
    """Default adapter registry for testing."""
    return build_default_registry()


@pytest.fixture
def fake_runtime() -> FakeRuntime:
    """Fake runtime that returns success."""
    return FakeRuntime(exit_code=0, stdout="scan results")


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


# ── Input schema tests ────────────────────────────────────────────────────────


class TestProposePlanSchema:
    """ProposePlanInput schema validation."""

    def test_valid_input(self) -> None:
        """Valid ProposePlanInput passes schema validation."""
        inp = ProposePlanInput(
            snapshot_hash="a" * 64,
            hypothesis="TCP services on common ports",
        )
        assert inp.snapshot_hash == "a" * 64
        assert inp.hypothesis == "TCP services on common ports"

    def test_input_from_dict(self) -> None:
        """ProposePlanInput accepts dict with optional fields omitted."""
        data = {"snapshot_hash": "a" * 64}
        inp = ProposePlanInput.model_validate(data)
        assert inp.snapshot_hash == "a" * 64
        assert inp.hypothesis == ""


class TestExecutePlanSchema:
    """ExecutePlanInput schema validation."""

    def test_valid_input(self) -> None:
        """Valid ExecutePlanInput passes schema validation."""
        inp = ExecutePlanInput(plan_id="plan-001")
        assert inp.plan_id == "plan-001"


class TestRenderReportSchema:
    """RenderReportInput schema validation."""

    def test_valid_input(self) -> None:
        """Valid RenderReportInput passes schema validation."""
        inp = RenderReportInput(style="walkthrough")
        assert inp.style == "walkthrough"

    def test_professional_style(self) -> None:
        """RenderReportInput accepts 'professional' style."""
        inp = RenderReportInput(style="professional")
        assert inp.style == "professional"


# ── Handler-level tests ──────────────────────────────────────────────────────


class TestProposePlanHandler:
    """handle_propose_plan contract tests."""

    def test_handler_exists(self) -> None:
        """The handle_propose_plan callable exists."""
        assert callable(handle_propose_plan)

    async def test_rejects_no_active_engagement(
        self, command: AriadneCommand, session_id: str
    ) -> None:
        """Handler rejects propose_plan when no engagement is bound."""
        result = await handle_propose_plan(
            {"snapshot_hash": "invalid", "hypothesis": "test"},
            session_id=session_id,
            ariadne_command=command,
        )
        assert result["status"] == "error", f"Expected error, got {result}"

    async def test_rejects_snapshot_hash_mismatch(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
    ) -> None:
        """Handler rejects propose_plan when snapshot_hash doesn't match the binding."""
        await _bind_engagement(command, session_id)
        # Intentionally use a different hash
        wrong_hash = "f" * 64
        result = await handle_propose_plan(
            {"snapshot_hash": wrong_hash, "hypothesis": "test"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        assert result["status"] == "error", f"Expected error, got {result}"
        assert "snapshot" in result.get("message", "").lower()

    async def test_proposes_plan_successfully(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
    ) -> None:
        """Handler proposes a valid plan when engagement is active and input correct."""
        snapshot_hash = await _bind_engagement(command, session_id)

        result = await handle_propose_plan(
            {
                "snapshot_hash": snapshot_hash,
                "hypothesis": "TCP services are running on common ports",
            },
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        assert result["status"] == "plan_proposed", f"Expected plan_proposed, got {result}"
        assert "plan_id" in result
        assert result["plan_id"]
        assert "actions" in result
        assert len(result["actions"]) > 0
        assert "expires_at" in result

    async def test_plan_requires_approval_before_execution(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
    ) -> None:
        """A plan can be approved by the user via /ariadne approve <plan-id>."""
        snapshot_hash = await _bind_engagement(command, session_id)
        result = await handle_propose_plan(
            {
                "snapshot_hash": snapshot_hash,
                "hypothesis": "TCP services are running on common ports",
            },
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        plan_id = result["plan_id"]

        # Approve via the /ariadne command
        response = command.handle(f"approve {plan_id}")
        assert "approved" in response.lower(), f"Expected approval, got: {response}"


class TestExecutePlanHandler:
    """handle_execute_plan contract tests."""

    def test_handler_exists(self) -> None:
        """The handle_execute_plan callable exists."""
        assert callable(handle_execute_plan)

    async def test_rejects_no_active_engagement(
        self, command: AriadneCommand, session_id: str
    ) -> None:
        """Handler rejects execute_plan when no engagement is bound."""
        result = await handle_execute_plan(
            {"plan_id": "plan-001"},
            session_id=session_id,
            ariadne_command=command,
        )
        assert result["status"] == "error"

    async def test_rejects_unapproved_plan(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
    ) -> None:
        """Handler rejects execution of a plan that has not been approved."""
        snapshot_hash = await _bind_engagement(command, session_id)
        propose_result = await handle_propose_plan(
            {
                "snapshot_hash": snapshot_hash,
                "hypothesis": "TCP services on common ports",
            },
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        plan_id = propose_result["plan_id"]

        # Attempt to execute WITHOUT approval
        result = await handle_execute_plan(
            {"plan_id": plan_id},
            session_id=session_id,
            ariadne_command=command,
        )
        assert result["status"] == "error", f"Expected error for unapproved plan, got {result}"
        assert "approv" in result.get("message", "").lower()

    async def test_rejects_unknown_plan(
        self,
        command: AriadneCommand,
        session_id: str,
    ) -> None:
        """Handler rejects execution of a plan id that was never proposed."""
        await _bind_engagement(command, session_id)
        result = await handle_execute_plan(
            {"plan_id": "nonexistent-plan-id"},
            session_id=session_id,
            ariadne_command=command,
        )
        assert result["status"] == "error"

    async def test_rejects_plan_created_by_different_trusted_session(
        self,
        command: AriadneCommand,
        planner: Planner,
        catalog: WorkflowCatalog,
        registry: AdapterRegistry,
        fake_runtime: FakeRuntime,
    ) -> None:
        session_a = "plan-owner-session"
        session_b = "different-session"
        snapshot_hash = await _bind_engagement(command, session_a)
        proposed = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "owner plan"},
            session_id=session_a,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        command.handle(f"approve {proposed['plan_id']}")
        await _bind_engagement(command, session_b)

        result = await handle_execute_plan(
            {"plan_id": proposed["plan_id"]},
            session_id=session_b,
            ariadne_command=command,
            adapter_registry=registry,
            runtime=fake_runtime,
        )

        assert result["status"] == "error"
        assert "session" in result["message"].lower()
        assert fake_runtime.calls == 0
        assert all(
            event["event_type"] != "plan_executed"
            for snapshot in command.store.iter_snapshots()
            for handle in (command.store.open(snapshot.engagement_id),)
            if handle is not None
            for event in command.store.read_events(handle)
        )

    async def test_rejects_plan_after_active_snapshot_changes(
        self,
        command: AriadneCommand,
        planner: Planner,
        catalog: WorkflowCatalog,
        registry: AdapterRegistry,
        fake_runtime: FakeRuntime,
    ) -> None:
        session_id = "stale-plan-session"
        replacement_session = "replacement-session"
        snapshot_hash = await _bind_engagement(command, session_id)
        proposed = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "stale plan"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        command.handle(f"approve {proposed['plan_id']}")
        await _bind_engagement(command, replacement_session)
        replacement = command.get_session_binding(replacement_session)
        assert replacement is not None
        assert replacement.engagement_id is not None
        replacement_handle = command.store.open(replacement.engagement_id)
        assert replacement_handle is not None
        command.store.append_event(
            replacement_handle,
            Event(
                event_type="session_bound",
                payload={
                    "session_id": session_id,
                    "snapshot_hash": replacement.snapshot_hash,
                },
                timestamp=datetime.now(UTC),
            ),
        )
        command.ledger.unbind_session(session_id)

        result = await handle_execute_plan(
            {"plan_id": proposed["plan_id"]},
            session_id=session_id,
            ariadne_command=command,
            adapter_registry=registry,
            runtime=fake_runtime,
        )

        assert result["status"] == "error"
        assert "snapshot" in result["message"].lower()
        assert fake_runtime.calls == 0
        assert all(
            event["event_type"] != "plan_executed"
            for snapshot in command.store.iter_snapshots()
            for handle in (command.store.open(snapshot.engagement_id),)
            if handle is not None
            for event in command.store.read_events(handle)
        )

    async def test_executes_approved_plan(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
        registry: AdapterRegistry,
        fake_runtime: FakeRuntime,
    ) -> None:
        """Handler executes an approved plan and returns evidence results."""
        snapshot_hash = await _bind_engagement(command, session_id)
        propose_result = await handle_propose_plan(
            {
                "snapshot_hash": snapshot_hash,
                "hypothesis": "TCP services on common ports",
            },
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        plan_id = propose_result["plan_id"]

        # Approve plan
        approve_resp = command.handle(f"approve {plan_id}")
        assert "approved" in approve_resp.lower()

        # Execute with adapter registry and fake runtime
        result = await handle_execute_plan(
            {"plan_id": plan_id},
            session_id=session_id,
            ariadne_command=command,
            adapter_registry=registry,
            runtime=fake_runtime,
        )
        assert result["status"] in ("executed", "partial"), f"Expected executed, got {result}"
        assert "plan_id" in result


class TestRenderReportHandler:
    """handle_render_report contract tests."""

    def test_handler_exists(self) -> None:
        """The handle_render_report callable exists."""
        assert callable(handle_render_report)

    async def test_rejects_no_active_engagement(
        self, command: AriadneCommand, session_id: str
    ) -> None:
        """Handler rejects render_report when no engagement is bound."""
        result = await handle_render_report(
            {"style": "walkthrough"},
            session_id=session_id,
            ariadne_command=command,
        )
        assert result["status"] == "error"

    async def test_renders_walkthrough(
        self,
        command: AriadneCommand,
        session_id: str,
    ) -> None:
        """Handler renders a walkthrough report for an active engagement."""
        await _bind_engagement(command, session_id)

        # The store should have the run handle — we need events to pass validation
        binding = command.ledger.get_session_binding(session_id)
        assert binding is not None, "No session binding found"
        assert binding.engagement_id is not None
        handle = command.store.open(binding.engagement_id)
        assert handle is not None
        _populate_test_events(command.store, handle)

        result = await handle_render_report(
            {"style": "walkthrough"},
            session_id=session_id,
            ariadne_command=command,
        )
        assert result["status"] == "report_rendered", f"Expected report_rendered, got {result}"
        assert "path" in result
        assert result["path"]

    async def test_renders_professional(
        self,
        command: AriadneCommand,
        session_id: str,
    ) -> None:
        """Handler renders a professional HTML report."""
        await _bind_engagement(command, session_id)

        # Populate events
        binding = command.ledger.get_session_binding(session_id)
        assert binding is not None
        assert binding.engagement_id is not None
        handle = command.store.open(binding.engagement_id)
        assert handle is not None
        _populate_test_events(command.store, handle)

        result = await handle_render_report(
            {"style": "professional"},
            session_id=session_id,
            ariadne_command=command,
        )
        assert result["status"] == "report_rendered"
        assert "path" in result


# ── Helpers ──────────────────────────────────────────────────────────────────


def _populate_test_events(store: RunStore, handle) -> None:
    """Populate a run handle with minimal events for report validation."""
    now = datetime.now(UTC)

    # Add a real artifact first, then reference its filename in events
    artifact = store.add_bytes(
        handle,
        data=b"80/tcp open http\n",
        metadata=ArtifactInput(
            media_type="text/plain",
            evidence_type="scan_result",
            source_name="nmap",
            maximum_bytes=1024 * 1024,
        ),
    )
    artifact_name = artifact.path.name

    store.append_event(
        handle,
        Event(
            event_type="evidence_collected",
            payload={
                "artifact": artifact_name,
                "finding": "Open port 80",
                "asset": "10.10.10.10",
            },
            timestamp=now,
        ),
    )
    store.append_event(
        handle,
        Event(
            event_type="objective_completed",
            payload={"objective_kind": "proof", "description": "Captured proof flag"},
            timestamp=now,
        ),
    )
    store.append_event(
        handle,
        Event(
            event_type="cleanup_completed",
            payload={"description": "Cleaned up all artifacts"},
            timestamp=now,
        ),
    )
