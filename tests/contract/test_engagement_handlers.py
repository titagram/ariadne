"""Contract tests for Ariadne's atomic engagement lock."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ariadne.core.engagement import (
    EngagementDraft,
    Objective,
    TargetSpec,
    lock_attested_engagement,
)
from ariadne.core.enums import AutonomyMode, EnvironmentProfile
from ariadne.core.errors import PolicyConfigurationError
from ariadne.hades_adapter.commands import CURRENT_DISCLAIMER_VERSION, AriadneCommand
from ariadne.hades_adapter.consent import ConsentDecision
from ariadne.hades_adapter.handlers import (
    handle_amend_engagement,
    handle_prepare_engagement,
    handle_status,
)
from ariadne.hades_adapter.schemas import (
    ARIADNE_TOOLS,
    ExecutePlanInput,
    PrepareEngagementInput,
    ProposePlanInput,
    RenderReportInput,
    StatusInput,
)
from ariadne.hades_adapter.session import ChallengeLedger
from ariadne.store.run_store import Event, RunStore


@pytest.fixture
def store(tmp_path) -> RunStore:
    return RunStore(base_path=tmp_path)


@pytest.fixture
def command(store) -> AriadneCommand:
    return AriadneCommand(ledger=ChallengeLedger(), store=store)


class ContractConsent:
    def __init__(self, decision: ConsentDecision = ConsentDecision.ACCEPT) -> None:
        self.decision = decision

    async def request_contract(self, summary: object) -> ConsentDecision:
        del summary
        return self.decision

    async def request_amendment(self, summary: object) -> ConsentDecision:
        del summary
        return self.decision


@pytest.fixture
def valid_answers() -> dict:
    return {
        "authorization_attested": True,
        "disclaimer_version": CURRENT_DISCLAIMER_VERSION,
        "profile": "private-lab",
        "target_host": "192.168.2.148",
        "objectives": ["proof"],
        "autonomy": "full",
        "time_window_minutes": 30,
        "notes": "Single-target private lab.",
    }


def test_public_registry_has_no_bind_tool() -> None:
    assert "ariadne_bind_engagement" not in ARIADNE_TOOLS


def test_prepare_schema_never_accepts_model_supplied_consent() -> None:
    properties = ARIADNE_TOOLS["ariadne_prepare_engagement"].schema[
        "parameters"
    ]["properties"]

    assert "authorization_attested" not in properties
    assert "disclaimer_version" not in properties


def test_prepare_schema_accepts_an_explicit_custom_objective() -> None:
    parsed = PrepareEngagementInput.model_validate(
        {
            "profile": "private-lab",
            "target_host": "lab.test",
            "objectives": [
                {
                    "kind": "custom",
                    "description": "Prove access to the test application",
                }
            ],
        }
    )

    assert parsed.objectives[0]["kind"] == "custom"


def test_render_schema_exposes_explicit_sensitive_report_options() -> None:
    parsed = RenderReportInput.model_validate(
        {"style": "professional", "include_flags": True, "include_secrets": True}
    )

    assert parsed.include_flags is True
    assert parsed.include_secrets is True


@pytest.mark.parametrize(
    "schema,payload",
    [
        (PrepareEngagementInput, {
            "authorization_attested": True,
            "disclaimer_version": CURRENT_DISCLAIMER_VERSION,
            "profile": "private-lab",
            "target_host": "192.168.2.148",
            "objectives": ["proof"],
            "session_id": "attacker-selected",
        }),
        (StatusInput, {"session_id": "attacker-selected"}),
        (ProposePlanInput, {
            "snapshot_hash": "a" * 64,
            "session_id": "attacker-selected",
        }),
        (ExecutePlanInput, {
            "plan_id": "plan",
            "session_id": "attacker-selected",
        }),
        (RenderReportInput, {"session_id": "attacker-selected"}),
    ],
)
def test_model_callable_schemas_reject_session_id(schema, payload) -> None:
    with pytest.raises(ValidationError):
        schema.model_validate(payload)


@pytest.mark.asyncio
async def test_prepare_atomically_locks_and_binds_trusted_session(
    command: AriadneCommand,
    valid_answers: dict,
) -> None:
    result = await handle_prepare_engagement(
        valid_answers,
        session_id="trusted-hades-session",
        ariadne_command=command,
        consent_gateway=ContractConsent(),
    )

    assert result["status"] == "active"
    assert result["engagement_id"]
    assert len(result["snapshot_hash"]) == 64
    assert "challenge_id" not in result
    binding = command.get_session_binding("trusted-hades-session")
    assert binding is not None
    assert binding.snapshot_hash == result["snapshot_hash"]
    assert binding.engagement_id is not None
    snapshot = command.store.open(binding.engagement_id).snapshot
    assert len(snapshot.policy_source_digests) == 3
    assert all(snapshot.policy_source_digests)
    assert snapshot.intensity == "normal"
    assert snapshot.constraints.max_requests_per_second == 10
    assert snapshot.constraints.max_concurrent_checks == 5
    events = command.store.read_events(command.store.open(binding.engagement_id))
    assert events[0]["payload"]["policy_source_digests"] == list(
        snapshot.policy_source_digests,
    )


@pytest.mark.asyncio
async def test_high_intensity_sets_bounded_defaults(
    command: AriadneCommand,
    valid_answers: dict,
) -> None:
    result = await handle_prepare_engagement(
        {**valid_answers, "intensity": "high"},
        session_id="high-intensity-session",
        ariadne_command=command,
        consent_gateway=ContractConsent(),
    )

    binding = command.get_session_binding("high-intensity-session")
    assert result["status"] == "active"
    assert binding is not None and binding.engagement_id is not None
    snapshot = command.store.open(binding.engagement_id).snapshot
    assert snapshot.constraints.max_requests_per_second == 50
    assert snapshot.constraints.max_concurrent_checks == 10


@pytest.mark.asyncio
async def test_prepare_fails_closed_without_trusted_session(
    command: AriadneCommand,
    valid_answers: dict,
) -> None:
    result = await handle_prepare_engagement(
        valid_answers,
        ariadne_command=command,
    )
    assert result["status"] == "error"
    assert "trusted" in result["message"].lower()
    assert list(command.store.iter_snapshots()) == []


@pytest.mark.asyncio
async def test_prepare_fails_closed_when_trusted_confirmation_is_declined(
    command: AriadneCommand,
    valid_answers: dict,
) -> None:
    result = await handle_prepare_engagement(
        valid_answers,
        session_id="trusted-hades-session",
        ariadne_command=command,
        consent_gateway=ContractConsent(ConsentDecision.DECLINE),
    )
    assert result["status"] == "blocked"
    assert "not confirmed" in result["message"].lower()
    assert list(command.store.iter_snapshots()) == []


@pytest.mark.asyncio
async def test_prepare_fails_closed_when_policy_sources_cannot_load(
    command: AriadneCommand,
    valid_answers: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing or malformed policy file must not escape the tool boundary."""
    from ariadne.hades_adapter import commands

    def reject_policy(profile, constraints):
        raise PolicyConfigurationError("policy source unavailable")

    monkeypatch.setattr(commands, "build_effective_policy", reject_policy)
    result = await handle_prepare_engagement(
        valid_answers,
        session_id="trusted-hades-session",
        ariadne_command=command,
        consent_gateway=ContractConsent(),
    )

    assert result["status"] == "error"
    assert "policy source unavailable" in result["message"]
    assert list(command.store.iter_snapshots()) == []


@pytest.mark.asyncio
async def test_binding_survives_service_recreation(
    store: RunStore,
    valid_answers: dict,
) -> None:
    first = AriadneCommand(ledger=ChallengeLedger(), store=store)
    created = await handle_prepare_engagement(
        valid_answers,
        session_id="restart-safe-session",
        ariadne_command=first,
        consent_gateway=ContractConsent(),
    )
    assert created["status"] == "active"

    recreated_store = RunStore(base_path=store.base_path)
    recreated = AriadneCommand(
        ledger=ChallengeLedger(),
        store=recreated_store,
    )
    status = await handle_status(
        {},
        session_id="restart-safe-session",
        ariadne_command=recreated,
    )
    assert status["status"] == "active"
    assert recreated.get_session_binding("restart-safe-session") is not None


@pytest.mark.asyncio
async def test_amendment_creates_linked_revision_and_rebinds_session(
    command: AriadneCommand,
    valid_answers: dict,
) -> None:
    created = await handle_prepare_engagement(
        valid_answers,
        session_id="amend-session",
        ariadne_command=command,
        consent_gateway=ContractConsent(),
    )

    amended = await handle_amend_engagement(
        {
            "add_targets": ["192.168.2.149"],
            "intensity": "high",
            "exclusions": ["dos"],
            "reason": "Distinct host discovered from local route evidence.",
            "candidate_id": "candidate-1",
        },
        session_id="amend-session",
        ariadne_command=command,
        consent_gateway=ContractConsent(),
    )

    assert amended["status"] == "active"
    assert amended["snapshot_hash"] != created["snapshot_hash"]
    binding = command.get_session_binding("amend-session")
    assert binding is not None
    snapshot = command.store.open(binding.engagement_id).snapshot
    assert snapshot.revision == 2
    assert snapshot.previous_snapshot_hash == created["snapshot_hash"]
    assert snapshot.intensity == "high"
    assert snapshot.constraints.max_requests_per_second == 50
    assert snapshot.constraints.max_concurrent_checks == 10
    assert {target.host for target in snapshot.targets} == {
        "192.168.2.148",
        "192.168.2.149",
    }


@pytest.mark.asyncio
async def test_amendment_freezes_current_policy_provenance(
    command: AriadneCommand,
    valid_answers: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await handle_prepare_engagement(
        valid_answers,
        session_id="policy-refresh-session",
        ariadne_command=command,
        consent_gateway=ContractConsent(),
    )
    binding = command.get_session_binding("policy-refresh-session")
    assert binding is not None and binding.engagement_id is not None
    original = command.store.open(binding.engagement_id)
    assert original is not None
    refreshed = ("d" * 64, "e" * 64, "f" * 64)

    from ariadne.core.policy import build_effective_policy

    effective = build_effective_policy(
        original.snapshot.profile,
        original.snapshot.constraints,
    ).model_copy(update={"source_digests": refreshed})
    monkeypatch.setattr(
        "ariadne.hades_adapter.commands.build_effective_policy",
        lambda _profile, _constraints: effective,
    )

    amended = await handle_amend_engagement(
        {
            "intensity": "high",
            "reason": "Refresh immutable policy provenance.",
        },
        session_id="policy-refresh-session",
        ariadne_command=command,
        consent_gateway=ContractConsent(),
    )

    assert amended["status"] == "active"
    current = command.store.open(binding.engagement_id)
    assert current is not None
    assert current.snapshot.policy_source_digests == refreshed


@pytest.mark.asyncio
async def test_declined_scope_candidate_can_be_reopened_by_explicit_amendment(
    command: AriadneCommand,
    valid_answers: dict,
) -> None:
    await handle_prepare_engagement(
        valid_answers,
        session_id="decline-session",
        ariadne_command=command,
        consent_gateway=ContractConsent(),
    )
    binding = command.get_session_binding("decline-session")
    assert binding is not None and binding.engagement_id is not None
    handle = command.store.open(binding.engagement_id)
    assert handle is not None
    from datetime import UTC, datetime

    command.store.append_event(
        handle,
        Event(
            event_type="scope_candidate_discovered",
            payload={
                "candidate_id": "candidate-declined",
                "target": "orion.test",
                "source_target": "192.168.2.148",
                "relation": "redirect",
            },
            timestamp=datetime.now(UTC),
        ),
    )
    payload = {
        "add_targets": ["orion.test"],
        "reason": "Approve the observed HTTP virtual-host alias.",
        "candidate_id": "candidate-declined",
    }
    declined = await handle_amend_engagement(
        payload,
        session_id="decline-session",
        ariadne_command=command,
        consent_gateway=ContractConsent(ConsentDecision.DECLINE),
    )
    reopened = await handle_amend_engagement(
        payload,
        session_id="decline-session",
        ariadne_command=command,
        consent_gateway=ContractConsent(),
    )

    assert declined["boundary"] == "amendment_declined"
    assert reopened["status"] == "active"
    binding = command.get_session_binding("decline-session")
    assert binding is not None and binding.engagement_id is not None
    handle = command.store.open(binding.engagement_id)
    assert handle is not None
    events = command.store.read_events(handle)
    assert any(
        event["event_type"] == "scope_candidate_blocked"
        and event["payload"]["candidate_id"] == "candidate-declined"
        for event in events
    )
    assert any(
        event["event_type"] == "scope_alias_approved"
        and event["payload"]["candidate_id"] == "candidate-declined"
        and event["payload"]["network_target"] == "192.168.2.148"
        and event["payload"]["http_host"] == "orion.test"
        for event in events
    )
    assert [target.host for target in handle.snapshot.targets] == ["192.168.2.148"]


class FailSecondEventStore(RunStore):
    """Fault-injection store that fails before persisting session_bound."""

    def __init__(self, base_path) -> None:
        super().__init__(base_path=base_path)
        self.append_count = 0

    def append_event(self, handle, event) -> None:
        self.append_count += 1
        if self.append_count == 2:
            raise OSError("injected session_bound write failure")
        super().append_event(handle, event)


class FailSessionReboundStore(RunStore):
    def append_event(self, handle, event) -> None:
        if event.event_type == "session_rebound":
            raise OSError("injected amendment failure")
        super().append_event(handle, event)


@pytest.mark.asyncio
async def test_failed_amendment_restores_previous_active_revision(
    tmp_path,
    valid_answers: dict,
) -> None:
    store = FailSessionReboundStore(base_path=tmp_path)
    command = AriadneCommand(ledger=ChallengeLedger(), store=store)
    created = await handle_prepare_engagement(
        valid_answers,
        session_id="rollback-session",
        ariadne_command=command,
        consent_gateway=ContractConsent(),
    )

    failed = await handle_amend_engagement(
        {
            "add_targets": ["192.168.2.149"],
            "reason": "candidate",
        },
        session_id="rollback-session",
        ariadne_command=command,
        consent_gateway=ContractConsent(),
    )

    binding = command.get_session_binding("rollback-session")
    assert failed["status"] == "error"
    assert binding is not None and binding.snapshot_hash == created["snapshot_hash"]
    assert store.open(binding.engagement_id).snapshot.revision == 1


def test_partial_prepare_never_binds_in_memory_or_after_restart(
    tmp_path,
    valid_answers: dict,
) -> None:
    store = FailSecondEventStore(tmp_path)
    command = AriadneCommand(ledger=ChallengeLedger(), store=store)

    with pytest.raises(OSError, match="injected"):
        command.prepare(
            valid_answers,
            session_id="partial-session",
            trusted_confirmation_digest="a" * 64,
        )

    assert command.ledger.get_session_binding("partial-session") is None
    recreated = AriadneCommand(
        ledger=ChallengeLedger(),
        store=RunStore(base_path=tmp_path),
    )
    assert recreated.get_session_binding("partial-session") is None


def test_prepare_persists_adjacent_correlated_transaction_events(
    command: AriadneCommand,
    valid_answers: dict,
) -> None:
    created = command.prepare(
        valid_answers,
        session_id="correlated-session",
        trusted_confirmation_digest="a" * 64,
    )
    handle = command.store.open(created.engagement_id)
    assert handle is not None
    events = command.store.read_events(handle)
    assert [event["event_type"] for event in events] == [
        "engagement_locked",
        "session_bound",
    ]
    transaction_id = events[0]["payload"]["transaction_id"]
    assert transaction_id
    assert events[1]["payload"]["transaction_id"] == transaction_id


@pytest.mark.asyncio
async def test_recovery_rejects_isolated_session_bound_event(
    tmp_path,
    valid_answers: dict,
) -> None:
    del valid_answers
    store = RunStore(base_path=tmp_path)
    snapshot = lock_attested_engagement(
        EngagementDraft(
            authorization_attested=True,
            disclaimer_version=CURRENT_DISCLAIMER_VERSION,
            profile=EnvironmentProfile.PRIVATE_LAB,
            autonomy=AutonomyMode.FULL,
            target=TargetSpec(host="192.168.2.148"),
            objectives=[Objective(kind="proof")],
        ),
        max_duration_minutes=30,
        policy_source_digests=("a" * 64, "b" * 64, "c" * 64),
    )
    handle = store.create(snapshot)
    from datetime import UTC, datetime

    store.append_event(
        handle,
        Event(
            event_type="session_bound",
            payload={
                "session_id": "complete-session",
                "snapshot_hash": snapshot.snapshot_hash,
            },
            timestamp=datetime.now(UTC),
        ),
    )

    recreated = AriadneCommand(
        ledger=ChallengeLedger(),
        store=store,
    )
    assert recreated.get_session_binding("complete-session") is None


@pytest.mark.asyncio
async def test_recovery_rejects_tampered_lock_even_with_updated_manifest(
    tmp_path,
    valid_answers: dict,
) -> None:
    command = AriadneCommand(
        ledger=ChallengeLedger(),
        store=RunStore(base_path=tmp_path),
    )
    created = command.prepare(
        valid_answers,
        session_id="tampered-session",
        trusted_confirmation_digest="a" * 64,
    )
    handle = command.store.open(created.engagement_id)
    assert handle is not None
    lock_path = handle.path / "engagement.lock.yaml"
    lock_text = lock_path.read_text(encoding="utf-8").replace(
        "192.168.2.148",
        "192.168.2.149",
    )
    lock_path.write_text(lock_text, encoding="utf-8")
    command.store._update_manifest(
        handle.path,
        "engagement.lock.yaml",
        __import__("hashlib").sha256(lock_path.read_bytes()).hexdigest(),
    )

    recreated = AriadneCommand(
        ledger=ChallengeLedger(),
        store=RunStore(base_path=tmp_path),
    )
    assert recreated.get_session_binding("tampered-session") is None


@pytest.mark.parametrize("tamper", ["manifest", "events"])
def test_recovery_fails_closed_on_manifest_or_event_tampering(
    tmp_path,
    valid_answers: dict,
    tamper: str,
) -> None:
    command = AriadneCommand(
        ledger=ChallengeLedger(),
        store=RunStore(base_path=tmp_path),
    )
    created = command.prepare(
        valid_answers,
        session_id=f"{tamper}-session",
        trusted_confirmation_digest="a" * 64,
    )
    handle = command.store.open(created.engagement_id)
    assert handle is not None
    if tamper == "manifest":
        (handle.path / "integrity.manifest").write_text("{}", encoding="utf-8")
    else:
        events_path = handle.path / "events.jsonl"
        events_path.write_text(
            events_path.read_text(encoding="utf-8") + "tampered\n",
            encoding="utf-8",
        )

    recreated = AriadneCommand(
        ledger=ChallengeLedger(),
        store=RunStore(base_path=tmp_path),
    )
    assert recreated.get_session_binding(f"{tamper}-session") is None


@pytest.mark.parametrize("variant", ["missing", "mismatch", "intermediate"])
def test_recovery_rejects_uncorrelated_or_nonadjacent_transaction_events(
    tmp_path,
    variant: str,
) -> None:
    store = RunStore(base_path=tmp_path)
    snapshot = lock_attested_engagement(
        EngagementDraft(
            authorization_attested=True,
            disclaimer_version=CURRENT_DISCLAIMER_VERSION,
            profile=EnvironmentProfile.PRIVATE_LAB,
            autonomy=AutonomyMode.FULL,
            target=TargetSpec(host="192.168.2.148"),
            objectives=[Objective(kind="proof")],
        ),
        max_duration_minutes=30,
        policy_source_digests=("a" * 64, "b" * 64, "c" * 64),
    )
    handle = store.create(snapshot)
    from datetime import UTC, datetime

    lock_transaction = "" if variant == "missing" else "transaction-a"
    bind_transaction = (
        "transaction-b" if variant == "mismatch" else lock_transaction
    )
    store.append_event(
        handle,
        Event(
            event_type="engagement_locked",
            payload={
                "snapshot_hash": snapshot.snapshot_hash,
                "authorization_attested": True,
                "disclaimer_version": CURRENT_DISCLAIMER_VERSION,
                "transaction_id": lock_transaction,
            },
            timestamp=datetime.now(UTC),
        ),
    )
    if variant == "intermediate":
        store.append_event(
            handle,
            Event(
                event_type="diagnostic",
                payload={"status": "intermediate"},
                timestamp=datetime.now(UTC),
            ),
        )
    store.append_event(
        handle,
        Event(
            event_type="session_bound",
            payload={
                "session_id": f"{variant}-transaction-session",
                "snapshot_hash": snapshot.snapshot_hash,
                "transaction_id": bind_transaction,
            },
            timestamp=datetime.now(UTC),
        ),
    )

    recreated = AriadneCommand(ledger=ChallengeLedger(), store=store)
    assert (
        recreated.get_session_binding(f"{variant}-transaction-session")
        is None
    )
