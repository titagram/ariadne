"""Observations, assets, and hypotheses."""

import ipaddress
from typing import Literal
from uuid import NAMESPACE_URL, UUID, uuid5

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


class ScopeCandidate(BaseModel):
    """A distinct discovered host/container that is not yet active scope."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    candidate_id: UUID
    target: TargetSpec
    source_target: TargetSpec
    reason: str
    evidence_ids: tuple[str, ...]
    relation: Literal["lateral_host", "container", "redirect", "route"]
    status: AssetStatus = AssetStatus.SCOPE_CANDIDATE


def discovered_asset_status(
    discovered: TargetSpec,
    current_target: TargetSpec,
) -> AssetStatus:
    """Classify local/current-machine services without expanding scope."""
    if discovered == current_target:
        return AssetStatus.IN_SCOPE
    try:
        if ipaddress.ip_address(discovered.host).is_loopback:
            return AssetStatus.IN_SCOPE
    except ValueError:
        if discovered.host == "localhost":
            return AssetStatus.IN_SCOPE
    return AssetStatus.SCOPE_CANDIDATE


def create_scope_candidate(
    *,
    target: TargetSpec,
    source_target: TargetSpec,
    reason: str,
    evidence_ids: tuple[str, ...],
    relation: Literal["lateral_host", "container", "redirect", "route"],
) -> ScopeCandidate:
    """Create a candidate from local evidence only; this sends no traffic."""
    if discovered_asset_status(target, source_target) is not AssetStatus.SCOPE_CANDIDATE:
        raise ValueError("Local or current-target services are already within scope")
    if not reason.strip() or not evidence_ids:
        raise ValueError("A scope candidate requires a reason and local evidence")
    return ScopeCandidate(
        candidate_id=uuid5(
            NAMESPACE_URL,
            (
                f"ariadne:{source_target.host}:{target.host}:"
                f"{relation}"
            ),
        ),
        target=target,
        source_target=source_target,
        reason=reason.strip(),
        evidence_ids=evidence_ids,
        relation=relation,
    )


class Hypothesis(BaseModel):
    """A ranked hypothesis for the attack path."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    hypothesis_id: UUID
    target: TargetSpec
    statement: str
    confidence: float
