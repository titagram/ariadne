"""Contract tests for Ariadne's atomic engagement lock."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

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
from ariadne.store.run_store import RunStore


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
