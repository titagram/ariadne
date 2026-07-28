"""End-to-end test: scope amendment creates a new linked snapshot.

Verifies that amending the target list produces a new snapshot revision
with a valid parent chain, and that the engagement can still reach
reporting through the amended scope.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.e2e


@pytest.mark.e2e
def test_scope_amendment_produces_linked_snapshot(
    hades_fixture: object,
    lab_fixture: object,
) -> None:
    """Amend scope with an additional target, verify linked snapshot chain."""
    engagement = hades_fixture.confirm_contract(
        profile="private-lab",
        target=lab_fixture.host,
        objective="proof",
    )
    original_hash = engagement.snapshot.snapshot_hash

    amended = hades_fixture.amend_scope(
        engagement,
        additional_host=lab_fixture.neighbor_host,
    )
    assert amended.snapshot.revision == engagement.snapshot.revision + 1
    assert amended.snapshot.previous_snapshot_hash == original_hash
    assert amended.snapshot.snapshot_hash != original_hash

    hades_fixture.run_until_complete(amended)
    assert amended.walkthrough_path.is_file()
    assert amended.integrity.valid
