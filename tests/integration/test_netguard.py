"""Integration tests for the netguard egress firewall.

Requires a running Docker Compose stack with:
- ``netguard`` (nftables egress firewall)
- ``kali`` (shares netguard's network namespace)
- ``target-http`` (the allowed target at 10.10.10.10)
- ``neighbor-blocked`` (a non-allowlisted host at 10.10.10.11)
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def test_netguard_allows_target_and_blocks_neighbor(
    integration_runtime: object,
    integration_targets: object,
) -> None:
    """Allowlist target must be reachable; blocked neighbor must be denied."""
    targets = integration_targets
    runtime = integration_runtime

    # The allowed target (target-http) serves on port 80
    assert runtime.tcp_reachable(targets.allowed_host, 80), (
        "Netguard should allow TCP to the confirmed target"
    )

    # The blocked neighbor serves on port 8080
    assert not runtime.tcp_reachable(targets.blocked_host, 8080), (
        "Netguard should block TCP to a non-allowlisted neighbor"
    )
