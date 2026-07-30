"""Shared, immutable data types for report dossier renderers."""

from __future__ import annotations

from pathlib import Path
from typing import NamedTuple

from pydantic import BaseModel, ConfigDict, Field


class ReportTarget(BaseModel):
    """An in-scope target copied from the immutable engagement snapshot."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str


class ReportObjective(BaseModel):
    """An objective and its persisted completion state."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str
    description: str
    completed: bool = False
    completion_evidence: str | None = None
    flag_value: str | None = None
    flag_value_available: bool = False


class ReportEvidence(BaseModel):
    """Evidence backed by both an event and a real on-disk artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    filename: str
    path: Path
    sha256: str
    size_bytes: int
    finding: str | None = None
    asset: str | None = None
    evidence_type: str | None = None
    finding_id: str | None = None


class ReportFinding(BaseModel):
    """A persisted candidate or separately validated finding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: str | None = None
    title: str
    severity: str | None = None
    status: str = "validated"
    target: str | None = None
    description: str | None = None
    evidence: tuple[str, ...] = ()
    remediation: tuple[str, ...] = ()


class ReportLifecycleEntry(BaseModel):
    """A human-readable activity derived from one persisted event."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_type: str
    summary: str
    timestamp: str | None = None
    target: str | None = None
    status: str | None = None


class ReportModel(BaseModel):
    """Single source of truth shared by every report renderer."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    engagement_id: str
    snapshot_hash: str
    generated_at: str
    authorization_attested: bool
    profile: str
    autonomy: str
    targets: tuple[ReportTarget, ...]
    objectives: tuple[ReportObjective, ...]
    evidence: tuple[ReportEvidence, ...] = ()
    findings: tuple[ReportFinding, ...] = ()
    lifecycle: tuple[ReportLifecycleEntry, ...] = ()
    cleanup: tuple[str, ...] = ()
    remediation: tuple[str, ...] = ()
    compromised: tuple[str, ...] = ()
    lessons: tuple[str, ...] = ()
    commands: tuple[str, ...] = ()
    risk_counts: dict[str, int] = Field(default_factory=dict)


class RenderedReport(NamedTuple):
    """A rendered report with its text content and supporting assets.

    Attributes:
        text: The rendered report text (Markdown for walkthrough, HTML for
            professional report).
        template: Name of the template used for rendering.
        assets: List of paths to copied/exported evidence assets.
    """

    text: str
    template: str = ""
    assets: list[Path] = []
