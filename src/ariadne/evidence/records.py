"""Artifact metadata and provenance models for collected evidence.

Every evidence artifact records a stable identifier, engagement linkage,
provenance (playbook, adapter, tool version, plan), a reproducible redacted
command, the SHA-256 digest of the collected content, and transformation
history.

Original binary evidence is immutable. A transformation (crop, annotation,
or redaction) creates a new related artifact — never overwrites the original.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class EvidenceRecord(BaseModel):
    """An immutable evidence artifact record.

    Stores the full provenance and content metadata for a single piece of
    collected evidence from a tool execution, screenshot, or file capture.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: UUID = Field(default_factory=uuid4)
    engagement_id: UUID
    snapshot_hash: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    asset: str
    adapter: str
    tool_version: str | None = None
    plan_id: str | None = None
    command_redacted: tuple[str, ...] = Field(default_factory=tuple)
    sha256: str
    exit_code: int = 0
    parser_status: str = "completed"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    provenance: str = ""
    parent_evidence_id: UUID | None = None
    content_type: str = "text/plain"


class TransformationRecord(BaseModel):
    """A derived artifact produced from an original evidence record.

    Captures the transformation type (e.g. ``redaction``, ``crop``,
    ``annotation``) and the original evidence's ID for provenance
    tracking. The SHA-256 is computed from the transformed content.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    transformation_id: UUID = Field(default_factory=uuid4)
    parent_id: UUID
    engagement_id: UUID
    snapshot_hash: str
    plan_id: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    reason: str
    sha256: str
    asset: str
    origin_command: tuple[str, ...] = Field(default_factory=tuple)
    origin_tool_version: str | None = None
