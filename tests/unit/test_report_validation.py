"""Quality-gate and golden-output tests for report validation and rendering.

Run::

    uv run pytest tests/unit/test_report_validation.py -v
"""

from __future__ import annotations

import hashlib
import json

import pytest

from ariadne.reporting.dossier import DossierBuilder
from ariadne.reporting.models import RenderedReport
from ariadne.reporting.professional import ProfessionalRenderer
from ariadne.reporting.validation import (
    ReportOptions,
    ReportValidator,
    ValidationResult,
    _has_unredacted_secrets,
)
from ariadne.reporting.walkthrough import WalkthroughRenderer
from ariadne.store.run_store import RunHandle

REQUIRED_PROFESSIONAL_SECTIONS = (
    "executive summary",
    "methodology",
    "risk summary",
    "technical findings",
    "remediation",
    "compromise narrative",
)


# ── Quality-gate tests (fail-closed) ───────────────────────────────────────────


@pytest.mark.parametrize(
    "broken_fixture",
    [
        "missing-snapshot",
        "finding-without-evidence",
        "missing-image",
        "bad-hash",
        "out-of-scope-asset",
        "objective-without-proof",
        "secret-leak",
        "missing-remediation",
    ],
)
def test_report_validation_fails_closed(
    load_run: callable,
    default_options: ReportOptions,
    broken_fixture: str,
) -> None:
    """Every broken fixture must fail validation."""
    result: ValidationResult = ReportValidator().validate(
        load_run(broken_fixture), default_options,
    )
    assert not result.valid, (
        f"Expected broken fixture {broken_fixture!r} to fail validation, "
        f"but it passed. Errors: {result.errors}"
    )


# ── Professional report content tests ──────────────────────────────────────────


def test_professional_report_contains_required_sections(
    valid_run: RunHandle,
    default_options: ReportOptions,
) -> None:
    """A valid run must produce a professional report with required sections."""
    validator = ReportValidator()
    result = validator.validate(valid_run, default_options)
    assert result.valid, f"Valid run failed validation: {result.errors}"

    renderer = ProfessionalRenderer()
    rendered = renderer.render(valid_run, default_options)
    assert isinstance(rendered, RenderedReport)
    html = rendered.text.lower()
    for heading in REQUIRED_PROFESSIONAL_SECTIONS:
        assert heading in html, (
            f"Required section {heading!r} not found in rendered report"
        )


# ── Walkthrough report rendering test ──────────────────────────────────────────


def test_walkthrough_report_renders_without_error(
    valid_run: RunHandle,
    default_options: ReportOptions,
) -> None:
    """A valid run must produce a walkthrough report without errors."""
    validator = ReportValidator()
    result = validator.validate(valid_run, default_options)
    assert result.valid, f"Valid run failed validation: {result.errors}"

    renderer = WalkthroughRenderer()
    rendered = renderer.render(valid_run, default_options)
    assert isinstance(rendered, RenderedReport)
    assert len(rendered.text) > 0, "Walkthrough report is empty"


def test_dossier_keeps_sha256_objective_proof_and_execution_boundary(
    valid_run: RunHandle,
    default_options: ReportOptions,
) -> None:
    events_path = valid_run.path / "events.jsonl"
    events = [
        json.loads(line)
        for line in events_path.read_text(encoding="utf-8").splitlines()
    ]
    events[2]["payload"]["proof"] = "a" * 64
    events.append(
        {
            "event_type": "execution_boundary",
            "payload": {
                "target": "10.0.0.1",
                "boundary": "kali_runtime",
                "reason": "Bounded version/help inspection failed for zaproxy.",
            },
        }
    )
    events_path.write_text(
        "\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n",
        encoding="utf-8",
    )

    dossier = DossierBuilder().build(valid_run, default_options)

    assert dossier.objectives[0].completion_evidence == "a" * 64
    assert dossier.lifecycle[-1].event_type == "execution_boundary"
    assert dossier.lifecycle[-1].summary == (
        "Bounded version/help inspection failed for zaproxy."
    )


def test_reports_disclose_limitations_and_absent_screenshots(
    valid_run: RunHandle,
    default_options: ReportOptions,
) -> None:
    run = RunHandle(
        engagement_id=valid_run.engagement_id,
        path=valid_run.path,
        snapshot=valid_run.snapshot.model_copy(
            update={"exclusions": ("DoS", "resource exhaustion")}
        ),
    )

    walkthrough = WalkthroughRenderer().render(run, default_options).text
    professional = ProfessionalRenderer().render(run, default_options).text

    for rendered in (walkthrough, professional):
        assert "DoS" in rendered
        assert "resource exhaustion" in rendered
        assert "No screenshots were acquired during this run." in rendered


# ── Validation edge cases ──────────────────────────────────────────────────────


def test_validation_result_is_dataclass(default_options: ReportOptions) -> None:
    """ValidationResult should be usable as a boolean gate."""
    passed = ValidationResult(valid=True)
    failed = ValidationResult(valid=False, errors=["something went wrong"])
    assert passed.valid
    assert not failed.valid
    assert len(failed.errors) == 1


def test_secret_scan_distinguishes_sha256_proofs_from_base64_secrets() -> None:
    assert _has_unredacted_secrets(
        json.dumps({"root_flag_sha256": "a" * 64}).encode()
    ) == []
    assert _has_unredacted_secrets(("Q" * 48 + "==").encode())


def test_secret_scan_does_not_treat_local_artifact_paths_as_base64() -> None:
    content = json.dumps(
        {
            "filename_effective": (
                "/Users/operator/.hades/ariadne/runs/"
                "b95266f7cbad40e9b81c55cb169c921d/probes/"
                "webref_74374e7442767efde077_0.body"
            )
        }
    ).encode()

    assert _has_unredacted_secrets(content) == []


def test_secret_scan_does_not_treat_subresource_integrity_as_secret() -> None:
    content = (
        '<script integrity="sha384-'
        + ("Q" * 64)
        + '" crossorigin="anonymous"></script>'
    ).encode()

    assert _has_unredacted_secrets(content) == []


def test_every_objective_in_a_multi_objective_contract_needs_its_own_proof(
    valid_run: RunHandle,
    default_options: ReportOptions,
) -> None:
    lock_path = valid_run.path / "engagement.lock.yaml"
    snapshot = json.loads(lock_path.read_text(encoding="utf-8"))
    snapshot["objectives"].append({"kind": "root_flag", "description": ""})
    lock_bytes = json.dumps(snapshot, sort_keys=True, indent=2).encode("utf-8")
    lock_path.write_bytes(lock_bytes)
    manifest_path = valid_run.path / "integrity.manifest"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["engagement.lock.yaml"] = hashlib.sha256(lock_bytes).hexdigest()
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2))

    result = ReportValidator().validate(valid_run, default_options)

    assert not result.valid
    assert any("root_flag" in error for error in result.errors)
