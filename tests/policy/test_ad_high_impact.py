"""Negative and positive policy tests for AD high-impact capability gates.

Verifies that high-impact AD operations (password_spray, credential_dump,
ntlm_poisoning, ntlm_relay, ticket_manipulation, object_modification,
adcs_abuse) are blocked when the corresponding capability is not granted.
"""

from __future__ import annotations

from uuid import UUID

import pytest

from ariadne.adapters.active_directory import ActiveDirectoryAdapter
from ariadne.adapters.base import AdapterContext, PlannedAction
from ariadne.core.engagement import TargetSpec
from ariadne.core.errors import AdapterPolicyError

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def adapter() -> ActiveDirectoryAdapter:
    return ActiveDirectoryAdapter()


def _ctx(
    extra_env: dict[str, str] | None = None,
) -> AdapterContext:
    env: dict[str, str] = {"TARGET_OS": "windows", "DOMAIN": "contoso.local"}
    if extra_env:
        env.update(extra_env)
    return AdapterContext(
        target=TargetSpec(host="192.168.1.10"),
        snapshot_hash="abc123",
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name="active_directory",
        environment=env,
    )


def action(operation: str, **inputs: object) -> PlannedAction:
    return PlannedAction(operation=operation, inputs=inputs)


# Each high-impact operation and its required capability key
_HIGH_IMPACT_OPS: dict[str, str] = {
    "password_spray": "ad.password_spray",
    "credential_dump": "ad.credential_dump",
    "ntlm_poisoning": "ad.ntlm_poisoning",
    "ntlm_relay": "ad.ntlm_relay",
    "ticket_manipulation": "ad.ticket_manipulation",
    "object_modification": "ad.object_modification",
    "certipy_relay": "ad.adcs_abuse",
}


def _capability_env_key(capability: str) -> str:
    safe = capability.replace(".", "_").replace("-", "_")
    return f"CAPABILITY_{safe}"


# ── High-impact operation tests ───────────────────────────────────────────────


class TestAdHighImpactDeny:
    """All AD high-impact operations are blocked without the exact capability."""

    @pytest.mark.parametrize("op,cap", list(_HIGH_IMPACT_OPS.items()))
    def test_high_impact_blocked_without_capability(
        self, adapter: ActiveDirectoryAdapter, op: str, cap: str
    ) -> None:
        """Without the specific AD capability, the operation is blocked."""
        ctx = _ctx()  # no AD capabilities
        with pytest.raises(AdapterPolicyError, match=cap.replace(".", r"\.")):
            adapter.plan(action(op), ctx)

    @pytest.mark.parametrize("op,cap", list(_HIGH_IMPACT_OPS.items()))
    def test_high_impact_blocked_with_explicit_deny(
        self, adapter: ActiveDirectoryAdapter, op: str, cap: str
    ) -> None:
        """Explicit deny of the capability blocks the operation."""
        env_key = _capability_env_key(cap)
        ctx = _ctx(extra_env={env_key: "deny"})
        with pytest.raises(AdapterPolicyError, match=cap.replace(".", r"\.")):
            adapter.plan(action(op), ctx)

    @pytest.mark.parametrize("op,cap", list(_HIGH_IMPACT_OPS.items()))
    def test_high_impact_allowed_with_explicit_allow(
        self, adapter: ActiveDirectoryAdapter, op: str, cap: str
    ) -> None:
        """Explicit allow of the capability permits the operation."""
        env_key = _capability_env_key(cap)
        ctx = _ctx(extra_env={env_key: "allow"})
        spec = adapter.plan(action(op), ctx)
        assert spec is not None
        assert spec.timeout_seconds >= 1

    def test_discovery_ops_not_blocked(
        self, adapter: ActiveDirectoryAdapter
    ) -> None:
        """Discovery operations (no capability required) are never blocked."""
        ctx = _ctx()
        for op in ("domain_discovery", "ldap_rootdse", "smb_enumeration"):
            spec = adapter.plan(action(op), ctx)
            assert spec is not None

    def test_certipy_find_not_blocked_without_adcs_abuse(
        self, adapter: ActiveDirectoryAdapter
    ) -> None:
        """certipy_find is discovery, not abuse, so it never requires ad.adcs_abuse."""
        ctx = _ctx()
        spec = adapter.plan(action("certipy_find"), ctx)
        assert spec is not None
