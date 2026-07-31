"""Bounded strategy-hint bridge tests.

Hints are supervisor guidance, not evidence.  They can only reopen a
playbook whose normal catalog prerequisites are already satisfied.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ariadne.adapters import AdapterRegistry
from ariadne.adapters.nmap import NmapAdapter
from ariadne.core.planner import Planner
from ariadne.core.workflow import (
    Playbook,
    PlaybookAction,
    PlaybookLimits,
    Trigger,
    WorkflowCatalog,
)
from ariadne.hades_adapter.commands import CURRENT_DISCLAIMER_VERSION, AriadneCommand
from ariadne.hades_adapter.consent import ConsentDecision
from ariadne.hades_adapter.handlers import (
    _determine_engagement_state,
    _record_dead_end_once,
    handle_prepare_engagement,
    handle_propose_plan,
    handle_run_engagement,
    handle_strategy_hint,
)
from ariadne.hades_adapter.session import ChallengeLedger
from ariadne.store.run_store import Event, RunStore


class _AcceptContract:
    async def request_contract(self, summary: object) -> ConsentDecision:
        del summary
        return ConsentDecision.ACCEPT


def _catalog() -> WorkflowCatalog:
    playbook = Playbook(
        id="discovery.test.v1",
        version=1,
        stage="discovery",
        triggers=(Trigger(kind="engagement_state", types=("discovery",)),),
        required_evidence_types=frozenset(),
        capabilities=frozenset({"scan.tcp"}),
        actions=(
            PlaybookAction(
                adapter="nmap",
                operation="investigate",
                inputs={},
            ),
        ),
        limits=PlaybookLimits(max_attempts=1, max_duration_seconds=5),
        stop_conditions=("bounded",),
        success_emits=("port_open",),
        next_playbooks=(),
        report_sections=("discovery",),
    )
    return WorkflowCatalog(playbooks={playbook.id: playbook})


async def _prepared(tmp_path):
    catalog = _catalog()
    store = RunStore(base_path=tmp_path)
    command = AriadneCommand(store=store, ledger=ChallengeLedger())
    registry = AdapterRegistry()
    registry.register("nmap", NmapAdapter())
    prepared = await handle_prepare_engagement(
        {
            "authorization_attested": True,
            "disclaimer_version": CURRENT_DISCLAIMER_VERSION,
            "profile": "private-lab",
            "target_host": "192.0.2.10",
            "objectives": ["proof"],
            "autonomy": "full",
            "intensity": "normal",
        },
        session_id="hint-session",
        ariadne_command=command,
        consent_gateway=_AcceptContract(),
    )
    binding = command.get_session_binding("hint-session")
    assert binding is not None and binding.engagement_id is not None
    handle = store.open(binding.engagement_id)
    assert handle is not None
    store.append_event(
        handle,
        Event(
            event_type="evidence_collected",
            payload={
                "evidence_type": "preflight_passed",
                "execution_classification": "success",
                "observation_data": {"type": "preflight_passed"},
            },
            timestamp=datetime.now(UTC),
        ),
    )
    # Simulate a prior, exhausted attempt.  The hint must not manufacture
    # evidence; it can only reopen this already-compatible playbook.
    store.append_event(
        handle,
        Event(
            event_type="plan_executed",
            payload={"playbook_id": "discovery.test.v1", "status": "success"},
            timestamp=datetime.now(UTC),
        ),
    )
    state, _ = _determine_engagement_state(store, handle)
    assert state.value == "discovery"
    _record_dead_end_once(store, handle, boundary="no_eligible_plan", state=state)
    return command, catalog, Planner(catalog=catalog), prepared["snapshot_hash"], handle


@pytest.mark.asyncio
async def test_strategy_hint_reopens_only_compatible_playbook_and_is_audited(tmp_path):
    command, catalog, planner, snapshot_hash, handle = await _prepared(tmp_path)

    result = await handle_strategy_hint(
        {
            "snapshot_hash": snapshot_hash,
            "hint": "Re-evaluate the already observed discovery branch.",
            "playbook_id": "discovery.test.v1",
        },
        session_id="hint-session",
        ariadne_command=command,
        catalog=catalog,
    )
    assert result["status"] == "accepted"
    events = command.store.read_events(handle)
    hint_events = [e for e in events if e["event_type"] == "strategy_hint_received"]
    assert len(hint_events) == 1
    assert not any(
        e["event_type"] == "evidence_collected" and e["payload"].get("hint")
        for e in events
    )

    proposal = await handle_propose_plan(
        {"snapshot_hash": snapshot_hash, "hypothesis": "resume supported branch"},
        session_id="hint-session",
        ariadne_command=command,
        planner=planner,
        catalog=catalog,
    )
    assert proposal["playbook_id"] == "discovery.test.v1"
    applied = [
        e
        for e in command.store.read_events(handle)
        if e["event_type"] == "strategy_hint_applied"
    ]
    assert len(applied) == 1


@pytest.mark.asyncio
async def test_strategy_hint_rejects_incompatible_and_replay_without_loop(tmp_path):
    command, catalog, _planner, snapshot_hash, handle = await _prepared(tmp_path)
    bad = await handle_strategy_hint(
        {
            "snapshot_hash": snapshot_hash,
            "hint": "Try an unobserved privilege escalation branch.",
            "playbook_id": "missing.playbook.v1",
        },
        session_id="hint-session",
        ariadne_command=command,
        catalog=catalog,
    )

    assert bad["status"] == "blocked"
    assert bad["boundary"] == "strategy_hint_incompatible"

    accepted = await handle_strategy_hint(
        {
            "snapshot_hash": snapshot_hash,
            "hint": "Re-evaluate the already observed discovery branch.",
            "playbook_id": "discovery.test.v1",
        },
        session_id="hint-session",
        ariadne_command=command,
        catalog=catalog,
    )
    assert accepted["status"] == "accepted"
    replay = await handle_strategy_hint(
        {
            "snapshot_hash": snapshot_hash,
            "hint": "Re-evaluate the already observed discovery branch.",
            "playbook_id": "different.playbook.v1",
        },
        session_id="hint-session",
        ariadne_command=command,
        catalog=catalog,
    )
    assert replay["status"] == "blocked"
    assert replay["boundary"] == "strategy_hint_replay"
    assert (
        len(
            [
                e
                for e in command.store.read_events(handle)
                if e["event_type"] == "strategy_hint_received"
            ]
        )
        == 1
    )


@pytest.mark.asyncio
async def test_strategy_hint_rejects_operationally_ineligible_ssh_branch(tmp_path):
    command, catalog, _planner, snapshot_hash, _handle = await _prepared(tmp_path)
    ssh_playbook = catalog.playbooks["discovery.test.v1"].model_copy(
        update={
            "id": "ssh.test.v1",
            "actions": (
                PlaybookAction(
                    adapter="ssh",
                    operation="connect",
                    inputs={"credential_ref": "secrets/ssh.secret"},
                ),
            ),
        }
    )
    ssh_catalog = WorkflowCatalog(playbooks={ssh_playbook.id: ssh_playbook})
    result = await handle_strategy_hint(
        {
            "snapshot_hash": snapshot_hash,
            "hint": "Try SSH without an observed service or credential.",
            "playbook_id": "ssh.test.v1",
        },
        session_id="hint-session",
        ariadne_command=command,
        catalog=ssh_catalog,
    )
    assert result["status"] == "blocked"
    assert result["boundary"] == "strategy_hint_incompatible"


@pytest.mark.asyncio
async def test_run_consumes_pending_hint_instead_of_repeating_dead_end(tmp_path, monkeypatch):
    command, catalog, _planner, snapshot_hash, _handle = await _prepared(tmp_path)
    accepted = await handle_strategy_hint(
        {
            "snapshot_hash": snapshot_hash,
            "hint": "Re-evaluate the already observed discovery branch.",
            "playbook_id": "discovery.test.v1",
        },
        session_id="hint-session",
        ariadne_command=command,
        catalog=catalog,
    )
    assert accepted["status"] == "accepted"
    calls = 0

    async def fake_propose(args, **context):
        nonlocal calls
        del args, context
        calls += 1
        return {
            "status": "blocked",
            "boundary": "no_eligible_plan",
            "message": "synthetic planner boundary",
        }

    monkeypatch.setattr(
        "ariadne.hades_adapter.handlers.handle_propose_plan",
        fake_propose,
    )
    result = await handle_run_engagement(
        {"max_steps": 1},
        session_id="hint-session",
        ariadne_command=command,
        catalog=catalog,
    )
    assert calls == 1
    assert result["boundary"] == "no_eligible_plan"
    assert "Unchanged terminal boundary" not in result["message"]

    resumed = await handle_run_engagement(
        {"max_steps": 1},
        session_id="hint-session",
        ariadne_command=command,
        catalog=catalog,
    )
    assert calls == 1
    assert resumed["boundary"] == "no_eligible_plan"
    assert "Unchanged terminal boundary" in resumed["message"]
    assert any(
        event["event_type"] == "strategy_hint_rejected"
        for event in command.store.read_events(_handle)
    )
    replay = await handle_strategy_hint(
        {
            "snapshot_hash": snapshot_hash,
            "hint": "Re-evaluate the already observed discovery branch.",
            "playbook_id": "discovery.test.v1",
        },
        session_id="hint-session",
        ariadne_command=command,
        catalog=catalog,
    )
    assert replay["boundary"] == "strategy_hint_replay"
