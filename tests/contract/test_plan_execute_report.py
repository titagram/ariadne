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
from threading import Barrier
from threading import Event as ThreadEvent

import pytest

from ariadne.adapters import AdapterRegistry, build_default_registry
from ariadne.adapters.base import ProcessResult, ProcessSpec
from ariadne.adapters.nmap import NmapAdapter
from ariadne.composition import ServiceContainer
from ariadne.core.errors import PolicyConfigurationError
from ariadne.core.planner import Planner
from ariadne.core.policy import CapabilityRule, EffectivePolicy
from ariadne.core.workflow import WorkflowCatalog
from ariadne.hades_adapter.commands import CURRENT_DISCLAIMER_VERSION, AriadneCommand
from ariadne.hades_adapter.consent import (
    ConsentDecision,
    HadesConsentGateway,
    UnavailableConsentGateway,
)
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


class FakeConsent:
    """Deterministic stand-in for Hades trusted elicitation UI."""

    def __init__(self, result: str) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    async def __call__(self, **kwargs: object) -> str:
        self.calls.append(kwargs)
        return self.result


class FakeConsentGateway:
    def __init__(self, decision: object) -> None:
        self.decision = decision
        self.calls = 0

    async def request_plan(self, plan: object) -> object:
        self.calls += 1
        return self.decision


class CallbackConsentGateway(FakeConsentGateway):
    def __init__(self, decision: object, callback) -> None:
        super().__init__(decision)
        self.callback = callback

    async def request_plan(self, plan: object) -> object:
        self.callback()
        return await super().request_plan(plan)


class PausingConsentGateway(FakeConsentGateway):
    def __init__(self, decision: object) -> None:
        super().__init__(decision)
        self.started = ThreadEvent()
        self.release = ThreadEvent()

    async def request_plan(self, plan: object) -> object:
        import asyncio

        self.started.set()
        await asyncio.to_thread(self.release.wait, 5)
        return await super().request_plan(plan)


class BlockingNmapAdapter(NmapAdapter):
    """Fixture adapter that accepts the catalog's synthetic tcp_scan op."""

    def __init__(self) -> None:
        super().__init__()
        self.plan_calls = 0
        self.execute_started = ThreadEvent()
        self.release_execute = ThreadEvent()

    def plan(self, action, context):
        del action, context
        self.plan_calls += 1
        return ProcessSpec(
            argv=("nmap", "--version"),
            timeout_seconds=10,
            max_output_bytes=4096,
        )

    async def execute(self, spec, runtime):
        import asyncio

        self.execute_started.set()
        await asyncio.to_thread(self.release_execute.wait, 5)
        return await runtime.run(spec)

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


async def _bind_engagement(
    command: AriadneCommand,
    session_id: str,
    *,
    autonomy: str = "controlled",
) -> str:
    """Helper: atomically prepare and bind an engagement."""
    args = {
        "authorization_attested": True,
        "disclaimer_version": CURRENT_DISCLAIMER_VERSION,
        "profile": "private-lab",
        "target_host": "10.10.10.10",
        "objectives": ["proof"],
        "autonomy": autonomy,
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


class TestCompositionOwnership:
    def test_service_container_reuses_one_command_instance(
        self,
        store: RunStore,
        ledger: ChallengeLedger,
        catalog: WorkflowCatalog,
        registry: AdapterRegistry,
    ) -> None:
        services = ServiceContainer(
            profile_name="test",
            store=store,
            ledger=ledger,
            catalog=catalog,
            adapter_registry=registry,
            consent_gateway=UnavailableConsentGateway(),
        )
        assert services.command is services.command

    async def test_reserved_malicious_consent_context_cannot_override_composition(
        self,
        store: RunStore,
        ledger: ChallengeLedger,
        catalog: WorkflowCatalog,
        registry: AdapterRegistry,
        fake_runtime: FakeRuntime,
        session_id: str,
    ) -> None:
        import json

        from ariadne.hades_adapter.registration import _handler_for

        composed_gateway = FakeConsentGateway(ConsentDecision.DECLINE)
        malicious_gateway = FakeConsentGateway(ConsentDecision.ACCEPT)
        registry.default_runtime = fake_runtime
        services = ServiceContainer(
            profile_name="test",
            store=store,
            ledger=ledger,
            catalog=catalog,
            adapter_registry=registry,
            consent_gateway=composed_gateway,
        )
        snapshot_hash = await _bind_engagement(services.command, session_id)
        proposed = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "reserved context"},
            session_id=session_id,
            ariadne_command=services.command,
            planner=services.planner,
            catalog=services.catalog,
        )
        wrapped = _handler_for("ariadne_execute_plan", services)

        raw = await wrapped(  # type: ignore[operator]
            {"plan_id": proposed["plan_id"]},
            session_id=session_id,
            consent_gateway=malicious_gateway,
        )
        result = json.loads(raw)

        assert result["status"] == "blocked"
        assert composed_gateway.calls == 1
        assert malicious_gateway.calls == 0
        assert fake_runtime.calls == 0


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
        assert result["approval_status"] == "awaiting_user_approval"
        assert command.get_plan_record(result["plan_id"]).approved is False

    async def test_full_mode_auto_approves_curated_in_policy_plan(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
    ) -> None:
        """Forcing /ariadne approve in full mode would break continuous execution."""
        snapshot_hash = await _bind_engagement(
            command,
            session_id,
            autonomy="full",
        )

        result = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "bounded discovery"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )

        record = command.get_plan_record(result["plan_id"])
        assert result["status"] == "plan_auto_approved"
        assert result["approval_status"] == "auto_approved"
        assert "call ariadne_execute_plan now" in result["message"].lower()
        assert record is not None
        assert record.approved is True
        assert record.approval_source == "full_autonomy_policy"

        binding = command.get_session_binding(session_id)
        assert binding is not None
        assert binding.engagement_id is not None
        handle = command.store.open(binding.engagement_id)
        assert handle is not None
        events = command.store.read_events(handle)
        proposed = [e for e in events if e["event_type"] == "plan_proposed"]
        auto = [e for e in events if e["event_type"] == "plan_auto_approved"]
        assert proposed[-1]["payload"]["plan_id"] == result["plan_id"]
        assert proposed[-1]["payload"]["snapshot_hash"] == snapshot_hash
        assert proposed[-1]["payload"]["session_id"] == session_id
        assert proposed[-1]["payload"]["autonomy"] == "full"
        assert auto[-1]["payload"]["capabilities"] == ["preflight.check"]
        assert auto[-1]["payload"]["reason"] == "full_autonomy_curated_in_policy"

    async def test_full_mode_does_not_auto_approve_always_manual_capability(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Ignoring effective-policy always_manual would bypass a hard approval boundary."""
        from ariadne.hades_adapter import handlers

        snapshot_hash = await _bind_engagement(
            command,
            session_id,
            autonomy="full",
        )
        guarded = EffectivePolicy(
            name="guarded",
            version=1,
            capabilities={
                "preflight.check": CapabilityRule(
                    allowed=True,
                    always_manual=True,
                ),
            },
            source_digests=(),
        )
        monkeypatch.setattr(handlers, "_load_engagement_policy", lambda snapshot: guarded)

        result = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "guarded preflight"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )

        record = command.get_plan_record(result["plan_id"])
        assert result["status"] == "plan_proposed"
        assert result["approval_status"] == "awaiting_user_approval"
        assert result["manual_capabilities"] == ["preflight.check"]
        assert record is not None
        assert record.approved is False

    async def test_auto_approval_event_failure_leaves_plan_unapproved(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An event-chain write failure must fail closed instead of approving in memory."""
        snapshot_hash = await _bind_engagement(
            command,
            session_id,
            autonomy="full",
        )
        real_append = command.store.append_event

        def fail_auto_approval(handle, event) -> None:
            if event.event_type == "plan_auto_approved":
                raise RuntimeError("simulated durable event failure")
            real_append(handle, event)

        monkeypatch.setattr(command.store, "append_event", fail_auto_approval)

        result = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "fail closed"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )

        assert result["status"] == "error"
        record = command.get_plan_record(result["plan_id"])
        assert record is not None
        assert record.approved is False
        assert "persist" in result["message"].lower()

    async def test_policy_provenance_drift_blocks_plan_proposal(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Changed policy files must require a new immutable snapshot."""
        from ariadne.hades_adapter import handlers

        snapshot_hash = await _bind_engagement(command, session_id, autonomy="full")

        def reject_drift(snapshot):
            raise PolicyConfigurationError("policy source digests changed")

        monkeypatch.setattr(handlers, "_load_engagement_policy", reject_drift)
        result = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "must stop"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )

        assert result["status"] == "error"
        assert "new snapshot" in result["message"].lower()

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
        response = command.handle(
            f"approve {plan_id}",
            trusted_session_id=session_id,
        )
        assert "approved" in response.lower(), f"Expected approval, got: {response}"


class TestExecutePlanHandler:
    """handle_execute_plan contract tests."""

    def test_handler_exists(self) -> None:
        """The handle_execute_plan callable exists."""
        assert callable(handle_execute_plan)

    @pytest.mark.parametrize(
        ("outcome", "expected"),
        [
            ("accept", (True, "accepted")),
            ("decline", (False, "declined")),
            ("cancel", (None, "cancelled")),
            ("unexpected", (None, "invalid_response")),
        ],
    )
    async def test_hades_consent_outcomes_are_normalized_fail_closed(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
        outcome: str,
        expected: tuple[bool | None, str],
    ) -> None:
        snapshot_hash = await _bind_engagement(command, session_id)
        proposed = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "consent mapping"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        record = command.get_plan_record(proposed["plan_id"])
        assert record is not None

        decision = await HadesConsentGateway(
            FakeConsent(outcome)
        ).request_plan(record.plan)
        mapping = {
            ConsentDecision.ACCEPT: (True, "accepted"),
            ConsentDecision.DECLINE: (False, "declined"),
            ConsentDecision.CANCEL: (None, "cancelled"),
            ConsentDecision.UNAVAILABLE: (None, "invalid_response"),
        }
        assert mapping[decision] == expected

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
        assert result["status"] == "blocked", (
            f"Expected blocked for unapproved plan, got {result}"
        )
        assert "approv" in result.get("message", "").lower()

    async def test_trusted_elicitation_accept_persists_and_executes_without_slash(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
        registry: AdapterRegistry,
        fake_runtime: FakeRuntime,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A manual boundary is resolved inside the model-tool turn."""
        from ariadne.hades_adapter import handlers

        snapshot_hash = await _bind_engagement(command, session_id, autonomy="full")
        real_policy = handlers._load_engagement_policy

        def manual_policy(snapshot):
            policy = real_policy(snapshot)
            capabilities = dict(policy.capabilities)
            capabilities["preflight.check"] = capabilities[
                "preflight.check"
            ].model_copy(update={"always_manual": True})
            return policy.model_copy(update={"capabilities": capabilities})

        monkeypatch.setattr(handlers, "_load_engagement_policy", manual_policy)
        proposed = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "manual boundary"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        consent = FakeConsentGateway(ConsentDecision.ACCEPT)

        result = await handle_execute_plan(
            {"plan_id": proposed["plan_id"]},
            session_id=session_id,
            ariadne_command=command,
            adapter_registry=registry,
            runtime=fake_runtime,
            catalog=catalog,
            consent_gateway=consent,
        )

        assert proposed["requires_manual_approval"] is True
        assert result["status"] in ("executed", "partial")
        assert consent.calls == 1
        record = command.get_plan_record(proposed["plan_id"])
        assert record is not None and record.approved and not record.rejected

    @pytest.mark.parametrize(
        ("decision", "label"),
        [("decline", "declined"), ("cancel", "cancelled")],
    )
    async def test_elicitation_decline_or_cancel_is_durable_and_never_executes(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
        registry: AdapterRegistry,
        fake_runtime: FakeRuntime,
        decision: str,
        label: str,
    ) -> None:
        snapshot_hash = await _bind_engagement(command, session_id)
        proposed = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": label},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        consent = FakeConsentGateway(ConsentDecision(decision))

        result = await handle_execute_plan(
            {"plan_id": proposed["plan_id"]},
            session_id=session_id,
            ariadne_command=command,
            adapter_registry=registry,
            runtime=fake_runtime,
            catalog=catalog,
            consent_gateway=consent,
        )

        assert result["status"] == "blocked"
        assert label in result["message"].lower()
        assert fake_runtime.calls == 0
        restarted = AriadneCommand(ChallengeLedger(), command.store)
        record = restarted.get_plan_record(
            proposed["plan_id"],
            trusted_session_id=session_id,
        )
        assert record is not None and record.rejected and not record.approved

    async def test_accepted_decision_is_recovered_without_second_elicitation(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
        registry: AdapterRegistry,
        fake_runtime: FakeRuntime,
    ) -> None:
        snapshot_hash = await _bind_engagement(command, session_id)
        proposed = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "remember consent"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        accepted = FakeConsentGateway(ConsentDecision.ACCEPT)
        first = await handle_execute_plan(
            {"plan_id": proposed["plan_id"]},
            session_id=session_id,
            ariadne_command=command,
            adapter_registry=registry,
            runtime=fake_runtime,
            catalog=catalog,
            consent_gateway=accepted,
        )
        restarted = AriadneCommand(ChallengeLedger(), command.store)
        must_not_run = FakeConsentGateway(ConsentDecision.DECLINE)
        second = await handle_execute_plan(
            {"plan_id": proposed["plan_id"]},
            session_id=session_id,
            ariadne_command=restarted,
            adapter_registry=registry,
            runtime=fake_runtime,
            catalog=catalog,
            consent_gateway=must_not_run,
        )

        assert first["status"] in ("executed", "partial")
        assert second["status"] == "blocked"
        assert "claimed" in second["message"].lower()
        assert must_not_run.calls == 0

    async def test_approved_then_explicit_reject_is_irreversible_and_blocks(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
        registry: AdapterRegistry,
        fake_runtime: FakeRuntime,
    ) -> None:
        snapshot_hash = await _bind_engagement(command, session_id)
        proposed = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "revoke"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        assert "approved" in command.handle(
            f"approve {proposed['plan_id']}",
            trusted_session_id=session_id,
        ).lower()
        assert "rejected" in command.handle(
            f"reject {proposed['plan_id']}",
            trusted_session_id=session_id,
        ).lower()
        assert "rejected" in command.handle(
            f"approve {proposed['plan_id']}",
            trusted_session_id=session_id,
        ).lower()

        restarted = AriadneCommand(ChallengeLedger(), command.store)
        result = await handle_execute_plan(
            {"plan_id": proposed["plan_id"]},
            session_id=session_id,
            ariadne_command=restarted,
            adapter_registry=registry,
            runtime=fake_runtime,
            catalog=catalog,
        )
        assert result["status"] == "blocked"
        assert fake_runtime.calls == 0

    async def test_cross_session_reject_is_denied(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
    ) -> None:
        snapshot_hash = await _bind_engagement(command, session_id)
        proposed = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "owned"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        response = command.handle(
            f"reject {proposed['plan_id']}",
            trusted_session_id="other-session",
        )
        assert "unknown" in response.lower() or "different" in response.lower()
        record = command.get_plan_record(proposed["plan_id"])
        assert record is not None and not record.rejected

    async def test_missing_elicitation_api_fails_closed_even_with_yolo_context(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
        registry: AdapterRegistry,
        fake_runtime: FakeRuntime,
    ) -> None:
        snapshot_hash = await _bind_engagement(command, session_id)
        proposed = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "no api"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        result = await handle_execute_plan(
            {"plan_id": proposed["plan_id"]},
            session_id=session_id,
            ariadne_command=command,
            adapter_registry=registry,
            runtime=fake_runtime,
            catalog=catalog,
            consent_gateway=UnavailableConsentGateway(),
            yolo=True,
        )

        assert result["status"] == "blocked"
        assert "consent" in result["message"].lower()
        assert fake_runtime.calls == 0

    async def test_yolo_context_still_calls_trusted_consent(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
        registry: AdapterRegistry,
        fake_runtime: FakeRuntime,
    ) -> None:
        snapshot_hash = await _bind_engagement(command, session_id)
        proposed = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "yolo is irrelevant"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        requester = FakeConsent("unexpected")
        consent = HadesConsentGateway(requester)
        result = await handle_execute_plan(
            {"plan_id": proposed["plan_id"]},
            session_id=session_id,
            ariadne_command=command,
            adapter_registry=registry,
            runtime=fake_runtime,
            catalog=catalog,
            consent_gateway=consent,
            yolo=True,
        )
        assert result["status"] == "blocked"
        assert "unavailable" in result["message"].lower()
        assert len(requester.calls) == 1
        assert fake_runtime.calls == 0

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
        command.handle(
            f"approve {proposed['plan_id']}",
            trusted_session_id=session_a,
        )
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
        command.handle(
            f"approve {proposed['plan_id']}",
            trusted_session_id=session_id,
        )
        await _bind_engagement(command, replacement_session)
        replacement = command.get_session_binding(replacement_session)
        assert replacement is not None
        assert replacement.engagement_id is not None
        replacement_handle = command.store.open(replacement.engagement_id)
        assert replacement_handle is not None
        transaction_id = "replacement-transaction"
        command.store.append_event(
            replacement_handle,
            Event(
                event_type="engagement_locked",
                payload={
                    "snapshot_hash": replacement.snapshot_hash,
                    "authorization_attested": True,
                    "disclaimer_version": CURRENT_DISCLAIMER_VERSION,
                    "transaction_id": transaction_id,
                },
                timestamp=datetime.now(UTC),
            ),
        )
        command.store.append_event(
            replacement_handle,
            Event(
                event_type="session_bound",
                payload={
                    "session_id": session_id,
                    "snapshot_hash": replacement.snapshot_hash,
                    "transaction_id": transaction_id,
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
        approve_resp = command.handle(
            f"approve {plan_id}",
            trusted_session_id=session_id,
        )
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

    async def test_full_mode_executes_auto_approved_plan_without_slash_approve(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
        registry: AdapterRegistry,
        fake_runtime: FakeRuntime,
    ) -> None:
        """Requiring a slash approval after auto-approval would stall continuous mode."""
        snapshot_hash = await _bind_engagement(
            command,
            session_id,
            autonomy="full",
        )
        proposed = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "continuous preflight"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )

        result = await handle_execute_plan(
            {"plan_id": proposed["plan_id"]},
            session_id=session_id,
            ariadne_command=command,
            adapter_registry=registry,
            runtime=fake_runtime,
        )

        assert proposed["status"] == "plan_auto_approved"
        assert result["status"] in ("executed", "partial")
        assert "not been approved" not in result["message"].lower()
        assert result["next_action"] == "continue_until_complete_then_render_offline_report"
        assert "offline report" in result["message"].lower()

    async def test_policy_provenance_drift_blocks_approved_plan_execution(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
        registry: AdapterRegistry,
        fake_runtime: FakeRuntime,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An approved plan cannot outlive the policy sources frozen at lock."""
        from ariadne.hades_adapter import handlers

        snapshot_hash = await _bind_engagement(command, session_id)
        proposed = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "policy-bound plan"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        command.handle(
            f"approve {proposed['plan_id']}",
            trusted_session_id=session_id,
        )

        def reject_drift(snapshot):
            raise PolicyConfigurationError("policy source digests changed")

        monkeypatch.setattr(handlers, "_load_engagement_policy", reject_drift)
        result = await handle_execute_plan(
            {"plan_id": proposed["plan_id"]},
            session_id=session_id,
            ariadne_command=command,
            adapter_registry=registry,
            runtime=fake_runtime,
        )

        assert result["status"] == "error"
        assert "new snapshot" in result["message"].lower()
        assert fake_runtime.calls == 0

    async def test_restart_recovers_and_executes_durable_auto_approval(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
        registry: AdapterRegistry,
        fake_runtime: FakeRuntime,
    ) -> None:
        snapshot_hash = await _bind_engagement(
            command,
            session_id,
            autonomy="full",
        )
        proposed = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "restart-safe"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )

        restarted = AriadneCommand(
            ledger=ChallengeLedger(),
            store=command.store,
        )
        result = await handle_execute_plan(
            {"plan_id": proposed["plan_id"]},
            session_id=session_id,
            ariadne_command=restarted,
            adapter_registry=registry,
            runtime=fake_runtime,
            catalog=catalog,
        )

        assert proposed["status"] == "plan_auto_approved"
        assert result["status"] in ("executed", "partial")
        recovered = restarted.get_plan_record(
            proposed["plan_id"],
            trusted_session_id=session_id,
        )
        assert recovered is not None
        assert recovered.approved is True
        assert recovered.approval_source == "full_autonomy_policy"

    async def test_restart_manual_approval_is_durable_and_session_bound(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
        registry: AdapterRegistry,
        fake_runtime: FakeRuntime,
    ) -> None:
        snapshot_hash = await _bind_engagement(command, session_id)
        proposed = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "manual restart"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )

        restarted = AriadneCommand(
            ledger=ChallengeLedger(),
            store=command.store,
        )
        missing = restarted.handle(f"approve {proposed['plan_id']}")
        cross_session = restarted.handle(
            f"approve {proposed['plan_id']}",
            trusted_session_id="another-session",
        )
        approved = restarted.handle(
            f"approve {proposed['plan_id']}",
            trusted_session_id=session_id,
        )

        assert "trusted hades session" in missing.lower()
        assert "different" in cross_session.lower() or "unknown" in cross_session.lower()
        assert "approved" in approved.lower()

        after_second_restart = AriadneCommand(
            ledger=ChallengeLedger(),
            store=command.store,
        )
        result = await handle_execute_plan(
            {"plan_id": proposed["plan_id"]},
            session_id=session_id,
            ariadne_command=after_second_restart,
            adapter_registry=registry,
            runtime=fake_runtime,
            catalog=catalog,
        )
        assert result["status"] in ("executed", "partial")
        recovered = after_second_restart.get_plan_record(
            proposed["plan_id"],
            trusted_session_id=session_id,
        )
        assert recovered is not None
        assert recovered.approval_source == "user"

    async def test_tampered_durable_plan_fails_closed_after_restart(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
        registry: AdapterRegistry,
        fake_runtime: FakeRuntime,
    ) -> None:
        snapshot_hash = await _bind_engagement(
            command,
            session_id,
            autonomy="full",
        )
        proposed = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "immutable"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        binding = command.get_session_binding(session_id)
        assert binding is not None and binding.engagement_id is not None
        handle = command.store.open(binding.engagement_id)
        assert handle is not None
        events_path = handle.path / "events.jsonl"
        events_path.write_text(
            events_path.read_text().replace("immutable", "tampered"),
            encoding="utf-8",
        )

        restarted = AriadneCommand(
            ledger=ChallengeLedger(),
            store=command.store,
        )
        result = await handle_execute_plan(
            {"plan_id": proposed["plan_id"]},
            session_id=session_id,
            ariadne_command=restarted,
            adapter_registry=registry,
            runtime=fake_runtime,
            catalog=catalog,
        )

        assert result["status"] == "error"
        assert fake_runtime.calls == 0

    async def test_plan_proposal_event_contains_complete_recoverable_record(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
    ) -> None:
        snapshot_hash = await _bind_engagement(
            command,
            session_id,
            autonomy="full",
        )
        proposed = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "durable record"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        binding = command.get_session_binding(session_id)
        assert binding is not None and binding.engagement_id is not None
        handle = command.store.open(binding.engagement_id)
        assert handle is not None
        payload = next(
            event["payload"]
            for event in command.store.read_events(handle)
            if event["event_type"] == "plan_proposed"
            and event["payload"]["plan_id"] == proposed["plan_id"]
        )

        assert payload["plan"]["plan_id"] == proposed["plan_id"]
        assert payload["trusted_session_id"] == session_id
        assert payload["snapshot_hash"] == snapshot_hash
        assert payload["expires_at"] == proposed["expires_at"]
        assert payload["approval_state"] == "pending"
        assert payload["approval_correlation_id"]

    async def test_restart_after_execution_claim_cannot_execute_again(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
        registry: AdapterRegistry,
        fake_runtime: FakeRuntime,
    ) -> None:
        snapshot_hash = await _bind_engagement(command, session_id)
        proposed = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "single claim"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        assert "approved" in command.handle(
            f"approve {proposed['plan_id']}",
            trusted_session_id=session_id,
        ).lower()
        claimed = command.claim_plan_execution(
            proposed["plan_id"],
            trusted_session_id=session_id,
        )
        assert claimed.claimed is True

        counting = BlockingNmapAdapter()
        counting.release_execute.set()
        registry.register("nmap", counting)
        restarted = AriadneCommand(ChallengeLedger(), command.store)
        result = await handle_execute_plan(
            {"plan_id": proposed["plan_id"]},
            session_id=session_id,
            ariadne_command=restarted,
            adapter_registry=registry,
            runtime=fake_runtime,
            catalog=catalog,
            consent_gateway=FakeConsentGateway(ConsentDecision.ACCEPT),
        )

        assert result["status"] == "blocked"
        assert "claimed" in result["message"].lower()
        assert counting.plan_calls == 0
        assert fake_runtime.calls == 0

    @pytest.mark.parametrize("failure_mode", ["policy_drift", "tamper"])
    async def test_change_between_consent_and_claim_has_no_side_effect(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
        registry: AdapterRegistry,
        fake_runtime: FakeRuntime,
        monkeypatch: pytest.MonkeyPatch,
        failure_mode: str,
    ) -> None:
        from ariadne.hades_adapter import commands

        snapshot_hash = await _bind_engagement(command, session_id)
        proposed = await handle_propose_plan(
            {
                "snapshot_hash": snapshot_hash,
                "hypothesis": f"claim {failure_mode}",
            },
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        binding = command.get_session_binding(session_id)
        assert binding is not None and binding.engagement_id is not None
        handle = command.store.open(binding.engagement_id)
        assert handle is not None

        if failure_mode == "policy_drift":
            real_build = commands.build_effective_policy

            def break_after_consent() -> None:
                def drift(profile, constraints):
                    policy = real_build(profile, constraints)
                    return policy.model_copy(
                        update={"source_digests": ("drifted",)}
                    )

                monkeypatch.setattr(commands, "build_effective_policy", drift)

        else:
            def break_after_consent() -> None:
                events_path = handle.path / "events.jsonl"
                events_path.write_text(
                    events_path.read_text().replace(
                        f"claim {failure_mode}",
                        "claim modified",
                    ),
                    encoding="utf-8",
                )

        counting = BlockingNmapAdapter()
        counting.release_execute.set()
        registry.register("nmap", counting)
        gateway = CallbackConsentGateway(
            ConsentDecision.ACCEPT,
            break_after_consent,
        )
        result = await handle_execute_plan(
            {"plan_id": proposed["plan_id"]},
            session_id=session_id,
            ariadne_command=command,
            adapter_registry=registry,
            runtime=fake_runtime,
            catalog=catalog,
            consent_gateway=gateway,
        )

        assert result["status"] == "blocked"
        assert counting.plan_calls == 0
        assert fake_runtime.calls == 0
        assert not any(
            event["event_type"] == "plan_execution_claimed"
            for event in command.store.read_events(handle)
        )

    async def test_concurrent_reject_wins_before_claim_with_zero_side_effect(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
        registry: AdapterRegistry,
        fake_runtime: FakeRuntime,
    ) -> None:
        import asyncio

        snapshot_hash = await _bind_engagement(command, session_id)
        proposed = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "reject race"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        counting = BlockingNmapAdapter()
        counting.release_execute.set()
        registry.register("nmap", counting)
        gateway = PausingConsentGateway(ConsentDecision.ACCEPT)
        execution = asyncio.create_task(handle_execute_plan(
            {"plan_id": proposed["plan_id"]},
            session_id=session_id,
            ariadne_command=command,
            adapter_registry=registry,
            runtime=fake_runtime,
            catalog=catalog,
            consent_gateway=gateway,
        ))
        await asyncio.to_thread(gateway.started.wait, 5)

        rejected = command.handle(
            f"reject {proposed['plan_id']}",
            trusted_session_id=session_id,
        )
        gateway.release.set()
        result = await execution

        assert "rejected" in rejected.lower()
        assert result["status"] == "blocked"
        assert counting.plan_calls == 0
        assert fake_runtime.calls == 0

    async def test_execution_claim_wins_and_reject_is_denied(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
        registry: AdapterRegistry,
        fake_runtime: FakeRuntime,
    ) -> None:
        import asyncio

        snapshot_hash = await _bind_engagement(command, session_id)
        proposed = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "claim wins"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        assert "approved" in command.handle(
            f"approve {proposed['plan_id']}",
            trusted_session_id=session_id,
        ).lower()
        blocking = BlockingNmapAdapter()
        registry.register("nmap", blocking)
        execution = asyncio.create_task(handle_execute_plan(
            {"plan_id": proposed["plan_id"]},
            session_id=session_id,
            ariadne_command=command,
            adapter_registry=registry,
            runtime=fake_runtime,
            catalog=catalog,
            consent_gateway=UnavailableConsentGateway(),
        ))
        await asyncio.to_thread(blocking.execute_started.wait, 5)

        rejected = command.handle(
            f"reject {proposed['plan_id']}",
            trusted_session_id=session_id,
        )
        second = await handle_execute_plan(
            {"plan_id": proposed["plan_id"]},
            session_id=session_id,
            ariadne_command=command,
            adapter_registry=registry,
            runtime=fake_runtime,
            catalog=catalog,
            consent_gateway=UnavailableConsentGateway(),
        )
        blocking.release_execute.set()
        first = await execution

        assert "claimed" in rejected.lower()
        assert second["status"] == "blocked"
        assert "claimed" in second["message"].lower()
        assert first["status"] in ("executed", "partial")
        assert blocking.plan_calls == 1

    async def test_claim_and_reject_share_one_serialized_transition(
        self,
        command: AriadneCommand,
        session_id: str,
        planner: Planner,
        catalog: WorkflowCatalog,
    ) -> None:
        import asyncio
        from concurrent.futures import ThreadPoolExecutor

        snapshot_hash = await _bind_engagement(command, session_id)
        proposed = await handle_propose_plan(
            {"snapshot_hash": snapshot_hash, "hypothesis": "lock contention"},
            session_id=session_id,
            ariadne_command=command,
            planner=planner,
            catalog=catalog,
        )
        assert "approved" in command.handle(
            f"approve {proposed['plan_id']}",
            trusted_session_id=session_id,
        ).lower()
        barrier = Barrier(3)

        def claim():
            barrier.wait()
            return command.claim_plan_execution(
                proposed["plan_id"],
                trusted_session_id=session_id,
            )

        def reject():
            barrier.wait()
            return command.reject_plan(
                proposed["plan_id"],
                trusted_session_id=session_id,
                decision_channel="slash_command",
                reason="explicit_user_rejection",
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            claim_future = pool.submit(claim)
            reject_future = pool.submit(reject)
            barrier.wait()
            claimed, rejected = await asyncio.gather(
                asyncio.wrap_future(claim_future),
                asyncio.wrap_future(reject_future),
            )

        reject_won = "rejected." in rejected.lower()
        assert claimed.claimed is not reject_won
        if claimed.claimed:
            assert "claimed" in rejected.lower()
        else:
            assert "rejected" in claimed.message.lower()


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
