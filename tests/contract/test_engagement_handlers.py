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
from ariadne.hades_adapter.commands import CURRENT_DISCLAIMER_VERSION, AriadneCommand
from ariadne.hades_adapter.handlers import (
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
    )

    assert result["status"] == "active"
    assert result["engagement_id"]
    assert len(result["snapshot_hash"]) == 64
    assert "challenge_id" not in result
    binding = command.get_session_binding("trusted-hades-session")
    assert binding is not None
    assert binding.snapshot_hash == result["snapshot_hash"]


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


@pytest.mark.parametrize(
    ("override", "expected"),
    [
        ({"authorization_attested": False}, "authorization"),
        ({"disclaimer_version": "stale-version"}, "disclaimer"),
    ],
)
@pytest.mark.asyncio
async def test_prepare_rejects_missing_authorization_or_wrong_disclaimer(
    command: AriadneCommand,
    valid_answers: dict,
    override: dict,
    expected: str,
) -> None:
    result = await handle_prepare_engagement(
        valid_answers | override,
        session_id="trusted-hades-session",
        ariadne_command=command,
    )
    assert result["status"] == "error"
    assert expected in result["message"].lower()
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


def test_partial_prepare_never_binds_in_memory_or_after_restart(
    tmp_path,
    valid_answers: dict,
) -> None:
    store = FailSecondEventStore(tmp_path)
    command = AriadneCommand(ledger=ChallengeLedger(), store=store)

    with pytest.raises(OSError, match="injected"):
        command.prepare(valid_answers, session_id="partial-session")

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
    created = command.prepare(valid_answers, session_id="correlated-session")
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
    created = command.prepare(valid_answers, session_id="tampered-session")
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
    created = command.prepare(valid_answers, session_id=f"{tamper}-session")
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
