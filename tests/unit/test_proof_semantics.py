"""Proof promotion remains tied to independent, objective evidence."""

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from ariadne.core.engagement import EngagementSnapshot, TargetSpec
from ariadne.core.enums import AutonomyMode, EngagementState, EnvironmentProfile
from ariadne.core.observations import Observation
from ariadne.hades_adapter.handlers import (
    _dead_end_for_state,
    _determine_engagement_state,
    _record_dead_end_once,
    _typed_progression_observations,
)
from ariadne.store.run_store import Event, RunStore

_SANITIZED_REPLAY = (
    Path(__file__).parents[1]
    / "fixtures"
    / "scenarios"
    / "sanitized-events-194-216.json"
)


def _observation(source: str, data: dict[str, object]) -> Observation:
    return Observation(
        observation_id=uuid4(),
        target=TargetSpec(host="192.0.2.10"),
        source=source,
        data=data,
    )


def test_screenshot_cannot_establish_a_foothold_without_session_proof(tmp_path) -> None:
    """Restoring screenshot-to-foothold promotion would falsely advance the run."""
    screenshot = tmp_path / "browser-error.png"
    screenshot.write_bytes(b"not-a-session")

    progressed = _typed_progression_observations(
        playbook_id="foothold.confirmation.v1",
        adapter="screenshot",
        operation="capture",
        action_inputs={"proof_kind": "initial_access"},
        target=TargetSpec(host="192.0.2.10"),
        observations=(
            _observation("screenshot", {"type": "screenshot", "path": str(screenshot)}),
        ),
        classification_kind="success",
    )

    assert tuple(observation.source for observation in progressed) == ("screenshot",)


def test_info_only_nuclei_match_cannot_validate_a_cve() -> None:
    """Treating informational scanner output as validation would create a false finding."""
    progressed = _typed_progression_observations(
        playbook_id="vulnerability.nuclei.v1",
        adapter="nuclei",
        operation="scan",
        action_inputs={
            "validated_candidates": (
                {
                    "target": "192.0.2.10",
                    "validation_status": "validated",
                    "compatible": True,
                    "cve_id": "CVE-2021-41773",
                    "product": "Apache HTTP Server",
                },
            )
        },
        target=TargetSpec(host="192.0.2.10"),
        observations=(
            _observation(
                "nuclei",
                {
                    "type": "http",
                    "template_id": "CVE-2021-41773",
                    "matched_at": "https://192.0.2.10/",
                    "severity": "info",
                },
            ),
        ),
        classification_kind="success",
    )

    assert tuple(observation.source for observation in progressed) == ("nuclei",)


def test_stale_screenshot_foothold_evidence_cannot_advance_state(tmp_path) -> None:
    """A historic browser capture must not become a session proof on replay."""
    store = RunStore(base_path=tmp_path)
    run = store.create(
        EngagementSnapshot(
            engagement_id=uuid4(),
            revision=1,
            previous_snapshot_hash=None,
            snapshot_hash="a" * 64,
            confirmed_at=datetime.now(UTC),
            authorization_attested=True,
            disclaimer_version="test",
            profile=EnvironmentProfile.HTB,
            autonomy=AutonomyMode.CONTROLLED,
            targets=(TargetSpec(host="192.0.2.10"),),
            objectives=(),
        )
    )
    store.append_event(
        run,
        Event(
            event_type="evidence_collected",
            payload={
                "evidence_type": "foothold_established",
                "execution_classification": "success",
                "observation_data": {"type": "foothold_established", "path": "error.png"},
            },
            timestamp=datetime.now(UTC),
        ),
    )

    state, _ = _determine_engagement_state(store, run)

    assert state is not EngagementState.POST_EXPLOITATION


def test_sanitized_events_194_to_216_replay_never_creates_foothold_or_ssh(tmp_path) -> None:
    """The failed wave remains a non-terminal evidence boundary on replay."""
    store = RunStore(base_path=tmp_path)
    run = store.create(
        EngagementSnapshot(
            engagement_id=uuid4(),
            revision=1,
            previous_snapshot_hash=None,
            snapshot_hash="b" * 64,
            confirmed_at=datetime.now(UTC),
            authorization_attested=True,
            disclaimer_version="test",
            profile=EnvironmentProfile.HTB,
            autonomy=AutonomyMode.CONTROLLED,
            targets=(TargetSpec(host="192.0.2.10"),),
            objectives=(),
        )
    )
    for item in json.loads(_SANITIZED_REPLAY.read_text()):
        if item["event_type"] != "evidence_collected":
            continue
        store.append_event(
            run,
            Event(
                event_type="evidence_collected",
                payload={
                    "evidence_type": item["evidence_type"],
                    "execution_classification": "success",
                    "observation_data": item["observation_data"],
                },
                timestamp=datetime.now(UTC),
            ),
        )
    state, observations = _determine_engagement_state(store, run)
    assert state not in {EngagementState.FOOTHOLD, EngagementState.POST_EXPLOITATION}
    assert not any(
        observation.source == "foothold_established"
        and observation.data.get("method") == "ssh_password"
        for observation in observations
    )


def test_new_evidence_invalidates_a_persisted_dead_end(tmp_path) -> None:
    """An unchanged dead-end is sticky until new evidence changes its signature."""
    store = RunStore(base_path=tmp_path)
    run = store.create(
        EngagementSnapshot(
            engagement_id=uuid4(),
            revision=1,
            previous_snapshot_hash=None,
            snapshot_hash="c" * 64,
            confirmed_at=datetime.now(UTC),
            authorization_attested=True,
            disclaimer_version="test",
            profile=EnvironmentProfile.HTB,
            autonomy=AutonomyMode.CONTROLLED,
            targets=(TargetSpec(host="192.0.2.10"),),
            objectives=(),
        )
    )
    state = EngagementState.ENVIRONMENT_PREFLIGHT

    _record_dead_end_once(store, run, boundary="no_eligible_plan", state=state)
    assert _dead_end_for_state(store, run, state) is not None

    store.append_event(
        run,
        Event(
            event_type="evidence_collected",
            payload={
                "evidence_type": "research_complete",
                "execution_classification": "success",
                "observation_data": {"type": "research_complete", "product": "fixture"},
            },
            timestamp=datetime.now(UTC),
        ),
    )

    assert _dead_end_for_state(store, run, state) is None
