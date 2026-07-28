"""Quality-gate and golden-output tests for report validation and rendering.

Run::

    uv run pytest tests/unit/test_report_validation.py -v
"""

from __future__ import annotations

import pytest

from ariadne.reporting.models import RenderedReport
from ariadne.reporting.professional import ProfessionalRenderer
from ariadne.reporting.validation import ReportOptions, ReportValidator, ValidationResult
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


# ── Validation edge cases ──────────────────────────────────────────────────────


def test_validation_result_is_dataclass(default_options: ReportOptions) -> None:
    """ValidationResult should be usable as a boolean gate."""
    passed = ValidationResult(valid=True)
    failed = ValidationResult(valid=False, errors=["something went wrong"])
    assert passed.valid
    assert not failed.valid
    assert len(failed.errors) == 1
