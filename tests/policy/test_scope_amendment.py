"""Negative and positive policy tests for pivot scope amendment constraints.

Verifies that pivot discovery produces scope_candidate observations, that
scanning discovered hosts requires a scope amendment, and that no route is
added for an unconfirmed network.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from ariadne.adapters.base import AdapterContext, PlannedAction
from ariadne.adapters.pivot import PivotAdapter
from ariadne.core.engagement import TargetSpec
from ariadne.core.errors import ScopeAmendmentRequiredError
from ariadne.runtime.process import ProcessResult

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def adapter() -> PivotAdapter:
    return PivotAdapter()


def _ctx(
    host: str = "10.10.10.10",
    extra_env: dict[str, str] | None = None,
) -> AdapterContext:
    env: dict[str, str] = {}
    if extra_env:
        env.update(extra_env)
    return AdapterContext(
        target=TargetSpec(host=host),
        snapshot_hash="abc123",
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name="pivot",
        environment=env,
    )


@pytest.fixture
def pivot_context() -> AdapterContext:
    return _ctx()


def action(operation: str, **inputs: object) -> PlannedAction:
    return PlannedAction(operation=operation, inputs=inputs)


def load_fixture(name: str) -> str:
    """Load a fixture file from tests/fixtures/pivot/."""
    path = Path(__file__).parent.parent / "fixtures" / "pivot" / name
    return path.read_text()


# ── Discovered host constraints ───────────────────────────────────────────────


class TestPivotScopeAmendment:
    """Verify pivot discovery produces scope_candidate observations and requires
    scope amendment for active actions."""

    def test_pivot_discovery_never_expands_scope(
        self, adapter: PivotAdapter, pivot_context: AdapterContext
    ) -> None:
        """Discovered hosts are candidates and cannot be directly acted upon."""
        observations = adapter.parse(
            ProcessResult(exit_code=0, stdout=load_fixture("discovered-host.json"), stderr="")
        )
        assert len(observations) >= 1
        data = observations[0].data
        assert data.get("status") == "scope_candidate"
        assert observations[0].target.host == "172.16.5.10"
        with pytest.raises(ScopeAmendmentRequiredError):
            adapter.plan(action("scan_discovered_host"), pivot_context)

    def test_add_route_requires_confirmed_network(
        self, adapter: PivotAdapter, pivot_context: AdapterContext
    ) -> None:
        """No route is added for an unconfirmed network."""
        with pytest.raises(ScopeAmendmentRequiredError):
            adapter.plan(
                action("add_route", network="10.99.99.0/24"), pivot_context
            )

    def test_discovery_observation_asset_status(
        self, adapter: PivotAdapter, pivot_context: AdapterContext
    ) -> None:
        """Observations from pivot discovery should reflect the asset
        is a scope candidate and not automatically in scope."""
        observations = adapter.parse(
            ProcessResult(exit_code=0, stdout=load_fixture("discovered-host.json"), stderr="")
        )
        assert len(observations) >= 1
        data = observations[0].data
        assert data.get("status") == "scope_candidate", (
            f"Expected scope_candidate status, got {data.get('status')!r}"
        )
        assert data.get("discovered_host"), "Missing discovered_host in observation data"

    def test_tunnel_start_does_not_require_amendment(
        self, adapter: PivotAdapter, pivot_context: AdapterContext
    ) -> None:
        """Starting a tunnel to the confirmed target does not require amendment."""
        spec = adapter.plan(action("start_tunnel"), pivot_context)
        assert spec is not None

    def test_stop_tunnel_does_not_require_amendment(
        self, adapter: PivotAdapter, pivot_context: AdapterContext
    ) -> None:
        """Stopping a tunnel never requires amendment."""
        adapter.plan(action("start_tunnel"), pivot_context)
        tunnel_id = list(adapter._tunnels.keys())[0]
        spec = adapter.plan(action("stop_tunnel", tunnel_id=tunnel_id), pivot_context)
        assert spec is not None
