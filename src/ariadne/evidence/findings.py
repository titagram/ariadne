"""Candidate-to-validated finding service.

The ``FindingService`` manages the lifecycle of findings from candidate
status through to validated, exploited, false positive, or informational.
Each transition requires bounded evidence: a scanner alert cannot be
promoted to ``validated`` without at least one evidence record.
"""

from __future__ import annotations

from uuid import UUID, uuid4

from ariadne.core.engagement import TargetSpec
from ariadne.core.enums import FindingStatus
from ariadne.core.errors import AriadneError


class FindingValidationError(AriadneError):
    """Raised when a finding validation operation fails."""


class _FindingRecord:
    """Internal mutable finding record.

    The public API returns a snapshot-like dict; the internal record
    carries the mutable status for lifecycle transitions.
    """

    def __init__(
        self,
        finding_id: UUID,
        title: str,
        description: str,
        target: TargetSpec,
        severity: str,
        source: str,
    ) -> None:
        self.finding_id = finding_id
        self.title = title
        self.description = description
        self.target = target
        self.severity = severity
        self.source = source
        self.status = FindingStatus.CANDIDATE
        self.evidence_ids: list[UUID] = []

    def to_snapshot(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "target": self.target,
            "severity": self.severity,
            "source": self.source,
            "status": self.status,
            "evidence_ids": list(self.evidence_ids),
        }


class FindingSnapshot:
    """Immutable snapshot of a finding at a point in time."""

    def __init__(self, data: dict) -> None:
        self._data = dict(data)

    @property
    def finding_id(self) -> UUID:
        return self._data["finding_id"]

    @property
    def title(self) -> str:
        return self._data["title"]

    @property
    def description(self) -> str:
        return self._data["description"]

    @property
    def target(self) -> TargetSpec:
        return self._data["target"]

    @property
    def severity(self) -> str:
        return self._data["severity"]

    @property
    def source(self) -> str:
        return self._data["source"]

    @property
    def status(self) -> FindingStatus:
        return self._data["status"]

    @property
    def evidence_ids(self) -> list[UUID]:
        return list(self._data["evidence_ids"])


class FindingService:
    """Manages finding lifecycle from candidate through validated states.

    Simple in-memory service for the v1 evidence dossier.  Each finding
    starts as a ``candidate`` and may be promoted to ``validated`` when
    at least one evidence record is supplied, or moved to
    ``false_positive``, ``exploited``, or ``informational``.
    """

    def __init__(self) -> None:
        self._findings: dict[UUID, _FindingRecord] = {}

    # ------------------------------------------------------------------
    # Candidate creation
    # ------------------------------------------------------------------

    def candidate(
        self,
        title: str,
        description: str,
        target: TargetSpec | None,
        severity: str = "medium",
        source: str = "",
    ) -> FindingSnapshot:
        """Register a new candidate finding.

        Args:
            title: Short finding title.
            description: Detailed description of the finding.
            target: The affected ``TargetSpec`` (required).
            severity: Severity string (``"low"``, ``"medium"``, ``"high"``,
                      ``"critical"``).
            source: Source tool or observation that generated this finding.

        Returns:
            An immutable ``FindingSnapshot`` in ``CANDIDATE`` status.

        Raises:
            ValueError: If *target* is ``None``.
        """
        if target is None:
            raise ValueError("target is required")
        finding_id = uuid4()
        record = _FindingRecord(
            finding_id=finding_id,
            title=title,
            description=description,
            target=target,
            severity=severity,
            source=source,
        )
        self._findings[finding_id] = record
        return FindingSnapshot(record.to_snapshot())

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(
        self,
        finding_id: UUID,
        evidence_ids: tuple[UUID, ...] = (),
    ) -> FindingSnapshot:
        """Promote a candidate finding to ``VALIDATED`` status.

        Requires at least one evidence record ID to support the validation.
        The evidence IDs are linked to the finding for future auditing.

        Args:
            finding_id: UUID of the candidate finding.
            evidence_ids: One or more evidence record UUIDs (must be non-empty).

        Returns:
            An immutable ``FindingSnapshot`` with ``VALIDATED`` status.

        Raises:
            FindingValidationError: If the finding is not found or no
                evidence IDs are provided.
        """
        record = self._findings.get(finding_id)
        if record is None:
            raise FindingValidationError(f"Finding {finding_id} not found")

        if not evidence_ids:
            raise FindingValidationError(
                f"Cannot validate finding {finding_id}: at least one "
                f"evidence record is required"
            )

        record.status = FindingStatus.VALIDATED
        record.evidence_ids = list(evidence_ids)
        return FindingSnapshot(record.to_snapshot())

    # ------------------------------------------------------------------
    # Status management
    # ------------------------------------------------------------------

    def mark_status(
        self,
        finding_id: UUID,
        status: FindingStatus,
    ) -> FindingSnapshot:
        """Manually set a finding's status.

        Unlike ``validate()``, this method does not require evidence IDs;
        it is intended for triage operations such as marking a candidate
        as ``false_positive`` or ``informational``.

        Args:
            finding_id: UUID of the finding.
            status: The new ``FindingStatus`` value.

        Returns:
            An immutable ``FindingSnapshot`` with the updated status.

        Raises:
            FindingValidationError: If the finding is not found.
        """
        record = self._findings.get(finding_id)
        if record is None:
            raise FindingValidationError(f"Finding {finding_id} not found")
        record.status = status
        return FindingSnapshot(record.to_snapshot())

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def list_findings(
        self,
        status: FindingStatus | None = None,
    ) -> list[FindingSnapshot]:
        """Return all findings, optionally filtered by *status*."""
        result = []
        for record in self._findings.values():
            if status is None or record.status == status:
                result.append(FindingSnapshot(record.to_snapshot()))
        return result
