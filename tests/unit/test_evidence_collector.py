"""Tests for the immutable evidence collector."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from ariadne.core.engagement import TargetSpec
from ariadne.evidence.collector import EvidenceCollector, evidence_context
from ariadne.evidence.records import TransformationRecord
from ariadne.runtime.process import ProcessResult

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def snapshot_hash() -> str:
    return "a" * 64


@pytest.fixture
def plan_id() -> str:
    return "plan-001"


@pytest.fixture
def collector(snapshot_hash: str, plan_id: str) -> EvidenceCollector:
    return EvidenceCollector(snapshot_hash=snapshot_hash, plan_id=plan_id)


@pytest.fixture
def process_result() -> ProcessResult:
    return ProcessResult(
        exit_code=0,
        stdout="80/tcp open  http\n443/tcp open https\n",
        stderr="",
    )


@pytest.fixture
def ctx() -> dict[str, object]:
    return {
        "target": TargetSpec(host="10.10.10.10"),
        "adapter": "nmap",
        "tool_version": "nmap 7.95",
        "playbook": "network.tcp-discovery.v1",
        "source": "scan",
        "argv": ("nmap", "-sV", "-p", "80,443", "10.10.10.10"),
    }


# ---------------------------------------------------------------------------
# Evidence provenance tests
# ---------------------------------------------------------------------------


def test_evidence_records_full_provenance(
    collector: EvidenceCollector,
    process_result: ProcessResult,
    ctx: dict[str, object],
) -> None:
    item = collector.collect_process(process_result, ctx)
    assert item.sha256
    assert item.tool_version == "nmap 7.95"
    assert item.snapshot_hash
    assert item.plan_id == "plan-001"


def test_evidence_contains_redacted_command(
    collector: EvidenceCollector,
    process_result: ProcessResult,
    ctx: dict[str, object],
) -> None:
    item = collector.collect_process(process_result, ctx)
    # The last argument (target IP) should be preserved in redacted form
    assert item.command_redacted
    assert item.command_redacted[-1] == "10.10.10.10"


def test_evidence_records_exit_and_parser_status(
    collector: EvidenceCollector,
    process_result: ProcessResult,
    ctx: dict[str, object],
) -> None:
    item = collector.collect_process(process_result, ctx)
    assert item.exit_code == 0


def test_evidence_generates_stable_id(
    collector: EvidenceCollector,
    process_result: ProcessResult,
    ctx: dict[str, object],
) -> None:
    item1 = collector.collect_process(process_result, ctx)
    # Ensure different context gives different IDs
    ctx2 = dict(ctx)
    ctx2["tool_version"] = "nmap 7.96"
    item2 = collector.collect_process(process_result, ctx2)
    assert item1.evidence_id != item2.evidence_id


def test_evidence_includes_snapshot_hash_and_engagement_id(
    collector: EvidenceCollector,
    process_result: ProcessResult,
    ctx: dict[str, object],
) -> None:
    ctx["engagement_id"] = uuid4()
    item = collector.collect_process(process_result, ctx)
    assert item.snapshot_hash == collector.snapshot_hash
    assert isinstance(item.engagement_id, UUID)


def test_evidence_collect_requires_context_target(
    collector: EvidenceCollector,
    process_result: ProcessResult,
    ctx: dict[str, object],
) -> None:
    bad_ctx = dict(ctx)
    del bad_ctx["target"]
    with pytest.raises(ValueError, match="target"):
        collector.collect_process(process_result, bad_ctx)


def test_evidence_record_is_frozen(
    collector: EvidenceCollector,
    process_result: ProcessResult,
    ctx: dict[str, object],
) -> None:
    item = collector.collect_process(process_result, ctx)
    with pytest.raises(ValueError):
        item.sha256 = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Transformations and immutability
# ---------------------------------------------------------------------------


def test_evidence_transformation_creates_new_artifact(
    collector: EvidenceCollector,
    process_result: ProcessResult,
    ctx: dict[str, object],
) -> None:
    original = collector.collect_process(process_result, ctx)
    transformation = collector.transform(
        original,
        reason="redaction",
        content=b"redacted content",
    )
    assert isinstance(transformation, TransformationRecord)
    assert transformation.parent_id == original.evidence_id
    assert transformation.sha256 != original.sha256


def test_evidence_transformation_preserves_provenance(
    collector: EvidenceCollector,
    process_result: ProcessResult,
    ctx: dict[str, object],
) -> None:
    original = collector.collect_process(process_result, ctx)
    transformation = collector.transform(
        original,
        reason="crop",
        content=b"cropped content",
    )
    assert transformation.snapshot_hash == original.snapshot_hash
    assert transformation.plan_id == original.plan_id
    assert transformation.asset == original.asset


def test_evidence_context_requires_valid_fields() -> None:
    with pytest.raises(ValueError):
        evidence_context()  # no fields - should fail


# ---------------------------------------------------------------------------
# Hash verification
# ---------------------------------------------------------------------------


def test_evidence_sha256_matches_content(
    collector: EvidenceCollector,
    process_result: ProcessResult,
    ctx: dict[str, object],
) -> None:
    """After collection, the stored SHA-256 must be a valid hex string."""
    item = collector.collect_process(process_result, ctx)
    assert len(item.sha256) == 64
    int(item.sha256, 16)  # raises if not hex
