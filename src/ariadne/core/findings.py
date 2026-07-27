"""Validated finding and remediation models."""

from uuid import UUID

from pydantic import BaseModel, ConfigDict

from ariadne.core.engagement import TargetSpec
from ariadne.core.enums import FindingStatus


class Finding(BaseModel):
    """A validated or candidate finding with evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: UUID
    target: TargetSpec
    title: str
    severity: str
    status: FindingStatus
    description: str
    evidence: list[str]
