"""Bounded action plans."""

from uuid import UUID

from pydantic import BaseModel, ConfigDict

from ariadne.core.engagement import TargetSpec


class ActionPlan(BaseModel):
    """A bounded, approved action plan for a specific hypothesis."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    plan_id: UUID
    snapshot_hash: str
    target: TargetSpec
    hypothesis: str
    actions: list[str]
    expected_evidence: list[str]
    stop_conditions: list[str]
    expires_at: str
