"""Contract tests for the NucleiAdapter.

Verifies template-catalog validation, scope-boundary enforcement,
and JSONL parsing for the Nuclei vulnerability-scanning adapter.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from ariadne.adapters.base import (
    AdapterContext,
    PlannedAction,
)
from ariadne.adapters.nuclei import NucleiAdapter
from ariadne.core.engagement import TargetSpec
from ariadne.core.errors import AdapterError, AdapterPolicyError
from ariadne.runtime.process import ProcessResult

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def context() -> AdapterContext:
    return AdapterContext(
        target=TargetSpec(host="10.10.10.10"),
        snapshot_hash="abc123",
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name="nuclei",
    )


@pytest.fixture
def load_fixture() -> type:
    """Helper that reads a fixture file from tests/fixtures/nuclei/."""

    def _load(name: str) -> str:
        p = Path(__file__).parents[2] / "tests" / "fixtures" / "nuclei" / name
        return p.read_text()

    return _load  # type: ignore[return-value]


def action(operation: str, **inputs: object) -> PlannedAction:
    return PlannedAction(operation=operation, inputs=inputs)


def validated_candidate(
    *,
    target: str = "10.10.10.10",
    cve_id: str = "CVE-2021-41773",
) -> dict[str, object]:
    return {
        "candidate_id": "research-41773",
        "cve_id": cve_id,
        "product": "Apache HTTP Server",
        "version": "2.4.49",
        "target": target,
        "validation_status": "validated",
        "compatible": True,
        "applicability_evidence": ["nvd-description:version=2.4.49"],
        "evidence_id": "evidence-1",
        "provenance": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
    }


# ── Plan (command building) ──────────────────────────────────────────────────


class TestNucleiPlan:
    """Verify that NucleiAdapter.plan() builds correct ProcessSpec arguments."""

    def test_scan_plan_includes_target(self, context: AdapterContext) -> None:
        spec = NucleiAdapter().plan(
            action("scan", validated_candidates=[validated_candidate()]),
            context,
        )
        assert spec.argv[0] == "nuclei"
        argv_str = " ".join(spec.argv)
        assert "10.10.10.10" in argv_str

    def test_scan_plan_selects_exact_cve_from_pinned_catalog(self, context: AdapterContext) -> None:
        spec = NucleiAdapter().plan(
            action(
                "scan",
                validated_candidates=[validated_candidate()],
            ),
            context,
        )
        argv_str = " ".join(spec.argv)
        assert "/opt/nuclei-templates/http/cves/2021/CVE-2021-41773.yaml" in argv_str
        assert "apache-answer" not in argv_str
        assert "main/http" not in argv_str

    def test_rejects_unlocked_template_directory(self, context: AdapterContext) -> None:
        """An arbitrary template directory outside the pinned catalog is rejected."""
        with pytest.raises(AdapterPolicyError):
            NucleiAdapter().plan(
                action("scan", template_dir="/tmp/download"),
                context,
            )

    def test_rejects_unknown_operation(self, context: AdapterContext) -> None:
        with pytest.raises(AdapterError):
            NucleiAdapter().plan(action("unknown_op"), context)

    def test_scan_requires_validated_template_candidates(self, context: AdapterContext) -> None:
        with pytest.raises(AdapterPolicyError, match="validated template"):
            NucleiAdapter().plan(action("scan"), context)

    def test_scan_rejects_candidate_for_another_target(self, context: AdapterContext) -> None:
        with pytest.raises(AdapterPolicyError, match="current target"):
            NucleiAdapter().plan(
                action(
                    "scan",
                    validated_candidates=[
                        validated_candidate(target="10.10.10.11"),
                    ],
                ),
                context,
            )

    def test_sets_bounded_timeout_and_output(self, context: AdapterContext) -> None:
        spec = NucleiAdapter().plan(
            action("scan", validated_candidates=[validated_candidate()]),
            context,
        )
        assert 1 <= spec.timeout_seconds <= 3600
        assert spec.max_output_bytes >= 1024


# ── Parse ─────────────────────────────────────────────────────────────────────


class TestNucleiParse:
    """Verify that NucleiAdapter.parse() extracts typed observations."""

    def test_parses_template_matches(self, load_fixture) -> None:
        result = ProcessResult(
            exit_code=0,
            stdout=load_fixture("results.jsonl"),
            stderr="",
        )
        obs = NucleiAdapter().parse(result)
        assert len(obs) == 3

        # First match: curated non-CVE template
        assert obs[0].data["template_id"] == "misconfig-dir-listing"
        assert obs[0].data["severity"] == "medium"
        assert obs[0].data["matched_at"] == "https://10.10.10.10/admin"
        assert obs[0].source == "nuclei"

        # Second match: tech detection
        assert obs[1].data["template_id"] == "tech-detect-apache"
        assert obs[1].data["severity"] == "info"

        # Third match: high severity
        assert obs[2].data["severity"] == "high"

    def test_empty_output_returns_empty_tuple(self) -> None:
        result = ProcessResult(exit_code=0, stdout="", stderr="")
        obs = NucleiAdapter().parse(result)
        assert obs == ()

    def test_malformed_jsonl_skips_bad_lines(self) -> None:
        result = ProcessResult(
            exit_code=0,
            stdout=(
                '{"template-id": "good", "host": "10.10.10.10"}\n'
                "not json\n"
                '{"template-id": "also-good", "host": "10.10.10.10"}\n'
            ),
            stderr="",
        )
        obs = NucleiAdapter().parse(result)
        assert len(obs) == 2


# ── Probe ─────────────────────────────────────────────────────────────────────


class TestNucleiProbe:
    """Verify probe metadata."""

    def test_nuclei_adapter_has_name(self) -> None:
        adapter = NucleiAdapter()
        assert hasattr(adapter, "name")
        assert adapter.name == "nuclei"


# ── Protocol shape ────────────────────────────────────────────────────────────


class TestNucleiProtocol:
    """Verify NucleiAdapter satisfies the ToolAdapter protocol."""

    def test_is_tool_adapter(self) -> None:
        from ariadne.adapters.base import ToolAdapter

        assert isinstance(NucleiAdapter(), ToolAdapter)
