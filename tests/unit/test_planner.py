"""Task 6: bounded plan construction tests."""

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from ariadne.core.engagement import EngagementSnapshot, TargetSpec
from ariadne.core.enums import AutonomyMode, EngagementState, EnvironmentProfile
from ariadne.core.observations import Hypothesis
from ariadne.core.policy import CapabilityRule, EffectivePolicy
from ariadne.core.workflow import PlanningContext, WorkflowCatalog


@pytest.fixture
def catalog() -> WorkflowCatalog:
    """Load the minimal playbook fixture from tests/fixtures/workflows/."""
    fixtures_dir = Path(__file__).parents[2] / "tests" / "fixtures" / "workflows"
    return WorkflowCatalog.load(fixtures_dir)


@pytest.fixture
def snapshot() -> EngagementSnapshot:
    return EngagementSnapshot(
        engagement_id=uuid4(),
        revision=1,
        previous_snapshot_hash=None,
        snapshot_hash="abc123",
        confirmed_at=datetime.now(UTC),
        authorization_attested=True,
        disclaimer_version="2026-07-27",
        profile=EnvironmentProfile.HTB,
        autonomy=AutonomyMode.CONTROLLED,
        targets=(TargetSpec(host="10.10.10.1"),),
        objectives=(),
    )


@pytest.fixture
def hypothesis() -> Hypothesis:
    return Hypothesis(
        hypothesis_id=uuid4(),
        target=TargetSpec(host="10.10.10.1"),
        statement="TCP services are running on common ports",
        confidence=0.8,
    )


@pytest.fixture
def effective_policy() -> EffectivePolicy:
    return EffectivePolicy(
        name="test ∩ htb",
        version=1,
        capabilities={
            "scan.tcp": CapabilityRule(
                allowed=True,
                max_rate=100,
                max_concurrency=5,
                max_attempts=1,
                max_duration_seconds=300,
                max_output_bytes=10485760,
            ),
        },
        source_digests=("digest1", "digest2"),
    )


@pytest.fixture
def planning_context(
    snapshot: EngagementSnapshot,
    hypothesis: Hypothesis,
    effective_policy: EffectivePolicy,
) -> PlanningContext:
    return PlanningContext(
        snapshot=snapshot,
        state=EngagementState.ACTION_PLANNING,
        observations=(),
        assets=(),
        effective_policy=effective_policy,
        hypothesis=hypothesis,
        now=datetime.now(UTC),
    )


class TestPlanCarriesSnapshotAndExpiry:
    """A built plan must reference its source snapshot and carry expiry."""

    def test_plan_has_snapshot_and_expiry(
        self, catalog: WorkflowCatalog, planning_context: PlanningContext
    ) -> None:
        from ariadne.core.planner import Planner

        plan = Planner(catalog).build("network.tcp-discovery.v1", planning_context)
        assert plan.snapshot_hash == planning_context.snapshot.snapshot_hash
        assert plan.expires_at > plan.created_at
        # Only the adapter may generate an argument vector — at planning
        # time every action's argv must be None.
        assert all(action.argv is None for action in plan.actions)
