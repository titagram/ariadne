"""End-to-end test: HTB policy blocks resource-stress and cross-target actions.

Verifies that the HTB environment profile correctly denies capabilities
that violate platform rules, and that no runner invocations occur for
blocked requests.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.e2e


@pytest.mark.e2e
def test_htb_dos_never_reaches_runner(
    hades_fixture: object,
    htb_engagement: object,
) -> None:
    """Request a resource-stress capability under HTB; must be blocked pre-runner."""
    result = hades_fixture.request_capability(htb_engagement, "resource.stress")
    assert not result.allowed
    assert hades_fixture.runner_calls == []
