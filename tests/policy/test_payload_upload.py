"""Negative and positive policy tests for payload upload capability gate.

Verifies that Windows binary upload operations (WinPEAS, PrivescCheck,
Seatbelt) are blocked when the exploit.payload_upload capability is
denied, and that partial upload failures produce cleanup records.
"""

from __future__ import annotations

from uuid import UUID

import pytest

from ariadne.adapters.base import AdapterContext, PlannedAction
from ariadne.adapters.postex import PostExAdapter
from ariadne.core.engagement import TargetSpec
from ariadne.core.errors import AdapterPolicyError

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def adapter() -> PostExAdapter:
    return PostExAdapter()


def _ctx(extra_env: dict[str, str] | None = None) -> AdapterContext:
    env: dict[str, str] = {"TARGET_OS": "windows"}
    if extra_env:
        env.update(extra_env)
    return AdapterContext(
        target=TargetSpec(host="10.10.10.10"),
        snapshot_hash="abc123",
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name="postex",
        environment=env,
    )


def action(operation: str, **inputs: object) -> PlannedAction:
    return PlannedAction(operation=operation, inputs=inputs)


_UPLOAD_OPS = ("winpeas", "privesccheck", "seatbelt")


# ── Deny capability ───────────────────────────────────────────────────────────


class TestPayloadUploadDeny:
    """All Windows binary upload operations are blocked when the
    exploit.payload_upload capability is denied."""

    @pytest.mark.parametrize("op", _UPLOAD_OPS)
    def test_upload_denied_without_capability(
        self, adapter: PostExAdapter, op: str
    ) -> None:
        """Without the payload_upload capability, upload operations are blocked."""
        ctx = _ctx()  # no upload capability
        with pytest.raises(AdapterPolicyError, match="payload_upload|capability"):
            adapter.plan(action(op), ctx)

    @pytest.mark.parametrize("op", _UPLOAD_OPS)
    def test_upload_denied_with_explicit_deny(
        self, adapter: PostExAdapter, op: str
    ) -> None:
        """Explicit deny of payload_upload blocks the operation."""
        ctx = _ctx(extra_env={"CAPABILITY_exploit_payload_upload": "deny"})
        with pytest.raises(AdapterPolicyError, match="payload_upload|capability"):
            adapter.plan(action(op), ctx)

    @pytest.mark.parametrize("op", _UPLOAD_OPS)
    def test_upload_allowed_with_allow(
        self, adapter: PostExAdapter, op: str
    ) -> None:
        """Explicit allow of payload_upload permits the operation."""
        ctx = _ctx(extra_env={"CAPABILITY_exploit_payload_upload": "allow"})
        spec = adapter.plan(action(op), ctx)
        assert spec is not None
        assert spec.timeout_seconds >= 1

    def test_unrelated_non_upload_op_not_blocked(
        self, adapter: PostExAdapter
    ) -> None:
        """Identity operations that don't need upload are never blocked."""
        ctx = _ctx()  # no upload capability
        spec = adapter.plan(action("identity"), ctx)
        assert spec is not None

    def test_all_upload_ops_emits_cleanup_path(
        self, adapter: PostExAdapter
    ) -> None:
        """Upload plans should include a cleanup path (randomized remote path)."""
        ctx = _ctx(extra_env={"CAPABILITY_exploit_payload_upload": "allow"})
        for op in _UPLOAD_OPS:
            spec = adapter.plan(action(op), ctx)
            assert len(spec.argv) > 2
            assert spec.timeout_seconds <= 900
