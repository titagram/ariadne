from __future__ import annotations

import asyncio
import threading
from contextvars import ContextVar
from datetime import UTC, datetime, timedelta

import pytest

from ariadne.core.engagement import TargetSpec
from ariadne.core.planner import Plan, PlannedAction
from ariadne.core.workflow import PlaybookLimits
from ariadne.hades_adapter.consent import ConsentDecision, HadesConsentGateway


def _plan() -> Plan:
    now = datetime.now(UTC)
    return Plan(
        plan_id="plan-consent-test",
        snapshot_hash="a" * 64,
        target=TargetSpec(host="10.10.10.10"),
        hypothesis="bounded test",
        playbook_id="test.v1",
        capabilities=("preflight.check",),
        actions=(
            PlannedAction(
                adapter="research",
                operation="investigate",
                inputs={"product": "preflight"},
            ),
        ),
        limits=PlaybookLimits(
            max_duration_seconds=30,
            max_output_bytes=4096,
        ),
        expected_evidence=("preflight_complete",),
        stop_conditions=("timeout",),
        requires_manual_approval=True,
        manual_capabilities=("preflight.check",),
        approval_reasons=("manual test",),
        created_at=now,
        expires_at=now + timedelta(minutes=15),
    )


@pytest.mark.asyncio
async def test_sync_requester_keeps_loop_responsive_and_receives_contextvar() -> None:
    session_key: ContextVar[str] = ContextVar("session_key", default="")
    token = session_key.set("trusted-session")
    entered = threading.Event()
    release = threading.Event()
    observed: dict[str, object] = {}
    main_thread = threading.get_ident()

    def requester(**kwargs: object) -> str:
        observed["session"] = session_key.get()
        observed["thread"] = threading.get_ident()
        observed["surface"] = kwargs["surface"]
        entered.set()
        release.wait(1)
        return "accept"

    try:
        gateway = HadesConsentGateway(
            requester,
            requester_timeout_seconds=0.2,
            external_timeout_seconds=0.3,
        )
        task = asyncio.create_task(gateway.request_plan(_plan()))
        assert await asyncio.to_thread(entered.wait, 0.2)

        heartbeat = asyncio.Event()
        asyncio.get_running_loop().call_soon(heartbeat.set)
        await asyncio.wait_for(heartbeat.wait(), timeout=0.05)
        assert not task.done()

        release.set()
        assert await task == ConsentDecision.ACCEPT
        assert observed["session"] == "trusted-session"
        assert observed["surface"] == "ariadne-plan"
        assert observed["thread"] != main_thread
    finally:
        release.set()
        session_key.reset(token)


@pytest.mark.asyncio
async def test_external_timeout_fails_closed_without_blocking_loop() -> None:
    release = threading.Event()

    def requester(**kwargs: object) -> str:
        del kwargs
        release.wait(1)
        return "accept"

    gateway = HadesConsentGateway(
        requester,
        requester_timeout_seconds=0.01,
        external_timeout_seconds=0.02,
    )
    try:
        assert await gateway.request_plan(_plan()) == ConsentDecision.CANCEL
    finally:
        release.set()


@pytest.mark.asyncio
async def test_unexpected_awaitable_result_is_awaited_then_fails_closed() -> None:
    async def unexpected() -> object:
        await asyncio.sleep(0)
        return object()

    def requester(**kwargs: object) -> object:
        del kwargs
        return unexpected()

    gateway = HadesConsentGateway(
        requester,
        requester_timeout_seconds=0.1,
        external_timeout_seconds=0.2,
    )
    assert await gateway.request_plan(_plan()) == ConsentDecision.UNAVAILABLE
