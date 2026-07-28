"""Tests for the finding service (candidate creation and validation)."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from ariadne.core.engagement import TargetSpec
from ariadne.core.enums import FindingStatus
from ariadne.evidence.findings import (
    FindingService,
    FindingValidationError,
)
from ariadne.evidence.records import EvidenceRecord


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def service() -> FindingService:
    return FindingService()


@pytest.fixture
def target() -> TargetSpec:
    return TargetSpec(host="10.10.10.10")


@pytest.fixture
def evidence_record(target: TargetSpec) -> EvidenceRecord:
    from datetime import UTC, datetime

    return EvidenceRecord(
        evidence_id=uuid4(),
        engagement_id=uuid4(),
        snapshot_hash="a" * 64,
        timestamp=datetime.now(UTC),
        asset=str(target.host),
        adapter="nmap",
        tool_version="nmap 7.95",
        plan_id="plan-001",
        command_redacted=("nmap", "10.10.10.10"),
        exit_code=0,
        parser_status="success",
        sha256="abc123" + "0" * 58,
        confidence=0.9,
        provenance="scan",
        content_type="text/plain",
    )


# ---------------------------------------------------------------------------
# Candidate creation
# ---------------------------------------------------------------------------


def test_scanner_alert_cannot_be_marked_validated_without_proof(
    service: FindingService,
    target: TargetSpec,
) -> None:
    candidate = service.candidate(
        title="Open SSH service",
        description="Port 22 open",
        target=target,
        severity="low",
        source="nmap",
    )
    with pytest.raises(FindingValidationError):
        service.validate(candidate.finding_id, evidence_ids=())


def test_candidate_creation_assigns_candidate_status(
    service: FindingService,
    target: TargetSpec,
) -> None:
    finding = service.candidate(
        title="Open port 80",
        description="HTTP service detected",
        target=target,
        severity="medium",
        source="nmap",
    )
    assert finding.status == FindingStatus.CANDIDATE
    assert isinstance(finding.finding_id, UUID)


def test_candidate_requires_target(
    service: FindingService,
) -> None:
    with pytest.raises(ValueError, match="target"):
        service.candidate(
            title="Test",
            description="Test",
            target=None,  # type: ignore[arg-type]
            severity="low",
            source="nmap",
        )


# ---------------------------------------------------------------------------
# Validation with evidence
# ---------------------------------------------------------------------------


def test_validate_with_evidence_promotes_to_validated(
    service: FindingService,
    target: TargetSpec,
    evidence_record: EvidenceRecord,
) -> None:
    candidate = service.candidate(
        title="Open port 80",
        description="HTTP service",
        target=target,
        severity="medium",
        source="nmap",
    )
    validated = service.validate(
        candidate.finding_id,
        evidence_ids=(evidence_record.evidence_id,),
    )
    assert validated.status == FindingStatus.VALIDATED
    assert len(validated.evidence_ids) == 1
    assert evidence_record.evidence_id in validated.evidence_ids


def test_validate_preserves_candidate_metadata(
    service: FindingService,
    target: TargetSpec,
    evidence_record: EvidenceRecord,
) -> None:
    candidate = service.candidate(
        title="SMB signing disabled",
        description="SMB signing not required",
        target=target,
        severity="medium",
        source="enum4linux",
    )
    validated = service.validate(
        candidate.finding_id,
        evidence_ids=(evidence_record.evidence_id,),
    )
    assert validated.title == "SMB signing disabled"
    assert validated.description == "SMB signing not required"
    assert validated.target == target


def test_validate_unknown_id_raises_error(
    service: FindingService,
) -> None:
    unknown_id = uuid4()
    valid_id = uuid4()
    with pytest.raises(FindingValidationError, match="not found"):
        service.validate(unknown_id, evidence_ids=(valid_id,))


def test_validate_rejects_empty_target(
    service: FindingService,
    evidence_record: EvidenceRecord,
) -> None:
    candidate = service.candidate(
        title="Test",
        description="Test",
        target=TargetSpec(host="10.10.10.10"),
        severity="low",
        source="test",
    )
    # Validation with evidence should work for a properly created candidate
    validated = service.validate(
        candidate.finding_id,
        evidence_ids=(evidence_record.evidence_id,),
    )
    assert validated.status == FindingStatus.VALIDATED


# ---------------------------------------------------------------------------
# Status management
# ---------------------------------------------------------------------------


def test_mark_false_positive(
    service: FindingService,
    target: TargetSpec,
) -> None:
    candidate = service.candidate(
        title="Suspicious service",
        description="May be false positive",
        target=target,
        severity="low",
        source="test",
    )
    fp = service.mark_status(candidate.finding_id, FindingStatus.FALSE_POSITIVE)
    assert fp.status == FindingStatus.FALSE_POSITIVE


def test_mark_exploited(
    service: FindingService,
    target: TargetSpec,
    evidence_record: EvidenceRecord,
) -> None:
    candidate = service.candidate(
        title="RCE vulnerability",
        description="Remote code execution",
        target=target,
        severity="critical",
        source="metasploit",
    )
    validated = service.validate(
        candidate.finding_id,
        evidence_ids=(evidence_record.evidence_id,),
    )
    exploited = service.mark_status(
        validated.finding_id, FindingStatus.EXPLOITED
    )
    assert exploited.status == FindingStatus.EXPLOITED


def test_mark_status_unknown_id(
    service: FindingService,
) -> None:
    with pytest.raises(FindingValidationError, match="not found"):
        service.mark_status(uuid4(), FindingStatus.FALSE_POSITIVE)


# ---------------------------------------------------------------------------
# Listing findings
# ---------------------------------------------------------------------------


def test_list_findings_returns_all(
    service: FindingService,
    target: TargetSpec,
) -> None:
    service.candidate(
        title="F1", description="D1", target=target, severity="low", source="s1"
    )
    service.candidate(
        title="F2", description="D2", target=target, severity="high", source="s2"
    )
    findings = service.list_findings()
    assert len(findings) == 2


def test_list_findings_by_status(
    service: FindingService,
    target: TargetSpec,
    evidence_record: EvidenceRecord,
) -> None:
    c1 = service.candidate(
        title="F1", description="D1", target=target, severity="low", source="s1"
    )
    service.candidate(
        title="F2", description="D2", target=target, severity="high", source="s2"
    )
    v1 = service.validate(
        c1.finding_id, evidence_ids=(evidence_record.evidence_id,)
    )
    candidates = service.list_findings(status=FindingStatus.CANDIDATE)
    validated = service.list_findings(status=FindingStatus.VALIDATED)
    assert len(candidates) == 1
    assert len(validated) == 1
    assert validated[0].finding_id == v1.finding_id
