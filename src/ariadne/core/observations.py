"""Observations, assets, and hypotheses."""

from uuid import UUID

from pydantic import BaseModel, ConfigDict

from ariadne.core.engagement import TargetSpec
from ariadne.core.enums import AssetStatus


class Observation(BaseModel):
    """A raw observation from a tool execution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    observation_id: UUID
    target: TargetSpec
    source: str
    data: dict[str, object]


class Asset(BaseModel):
    """A discovered or declared engagement asset."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    asset_id: UUID
    target: TargetSpec
    status: AssetStatus


class Hypothesis(BaseModel):
    """A ranked hypothesis for the attack path."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    hypothesis_id: UUID
    target: TargetSpec
    statement: str
    confidence: float
