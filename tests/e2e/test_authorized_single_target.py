"""End-to-end test: authorized single-target engagement reaches reports.

Exercises the full contract → policy → execution → evidence → reporting
pipeline against an isolated lab fixture.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.e2e


@pytest.mark.e2e
def test_authorized_target_reaches_reports(
    hades_fixture: object,
    lab_fixture: object,
) -> None:
    """Confirm a private-lab engagement, run to completion, verify reports."""
    engagement = hades_fixture.confirm_contract(
        profile="private-lab",
        target=lab_fixture.host,
        objective="proof",
    )
    hades_fixture.run_until_complete(engagement)
    assert engagement.snapshot_path.is_file()
    assert engagement.walkthrough_path.is_file()
    assert engagement.professional_pdf_path.is_file()
    assert engagement.sysreptor_bundle_path.is_file()
    assert engagement.integrity.valid
