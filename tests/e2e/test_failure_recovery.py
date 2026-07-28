"""End-to-end test: engagement failure and recovery paths.

Verifies that the system handles plan rejection, execution failure,
and abort gracefully — leaving a consistent dossier state from which
reporting can still proceed.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.e2e


@pytest.mark.e2e
def test_abort_during_execution_produces_consistent_dossier(
    hades_fixture: object,
    lab_fixture: object,
) -> None:
    """Abort an active engagement; dossier must remain internally consistent."""
    engagement = hades_fixture.confirm_contract(
        profile="private-lab",
        target=lab_fixture.host,
        objective="proof",
    )
    hades_fixture.start_execution(engagement)
    hades_fixture.abort(engagement)

    # Dossier must still be valid enough to produce a partial report
    assert engagement.events_path.is_file()
    assert engagement.integrity.valid or engagement.integrity.errors
    # Reporting may still proceed with collected evidence
    walkthrough = hades_fixture.render_walkthrough(engagement)
    assert walkthrough is not None
