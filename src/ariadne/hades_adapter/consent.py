"""Composition-owned Hades consent gateway.

Only the composition root loads Hades' public elicitation function.  Handlers
consume this typed gateway and never accept a requester from model tool input.
"""

from __future__ import annotations

import asyncio
from enum import StrEnum
from inspect import isawaitable
from typing import Any, Protocol, runtime_checkable

from ariadne.core.planner import Plan


class ConsentDecision(StrEnum):
    """Normalized outcomes from Hades' trusted consent surface."""

    ACCEPT = "accept"
    DECLINE = "decline"
    CANCEL = "cancel"
    UNAVAILABLE = "unavailable"


@runtime_checkable
class ConsentGateway(Protocol):
    """Trusted gateway owned by :class:`ServiceContainer`."""

    async def request_plan(self, plan: Plan) -> ConsentDecision:
        """Request a bounded decision for *plan*."""
        ...


class UnavailableConsentGateway:
    """Fail-closed gateway used when Hades' API is unavailable."""

    async def request_plan(self, plan: Plan) -> ConsentDecision:
        del plan
        return ConsentDecision.UNAVAILABLE

    async def request_contract(self, summary: dict[str, object]) -> ConsentDecision:
        del summary
        return ConsentDecision.UNAVAILABLE

    async def request_amendment(self, summary: dict[str, object]) -> ConsentDecision:
        del summary
        return ConsentDecision.UNAVAILABLE


class HadesConsentGateway:
    """Adapter for Hades' ContextVar-scoped public elicitation API."""

    def __init__(
        self,
        requester: Any,
        *,
        interactive_requester: Any | None = None,
        requester_timeout_seconds: float = 120,
        external_timeout_seconds: float | None = None,
    ) -> None:
        if not callable(requester):
            raise TypeError("Hades consent requester must be callable")
        if interactive_requester is not None and not callable(interactive_requester):
            raise TypeError("Hades interactive consent requester must be callable")
        if requester_timeout_seconds <= 0:
            raise ValueError("Requester timeout must be positive")
        external_timeout = (
            requester_timeout_seconds + 5
            if external_timeout_seconds is None
            else external_timeout_seconds
        )
        if external_timeout <= requester_timeout_seconds:
            raise ValueError("External timeout must exceed the requester timeout")
        self._requester = requester
        self._interactive_requester = interactive_requester
        self._requester_timeout_seconds = requester_timeout_seconds
        self._external_timeout_seconds = external_timeout

    async def request_plan(self, plan: Plan) -> ConsentDecision:
        import json

        message = f"Authorize Ariadne plan {plan.plan_id[:8]} for target {plan.target.host}?"
        description = json.dumps(
            {
                "plan_id": plan.plan_id,
                "target": plan.target.host,
                "hypothesis": plan.hypothesis[:500],
                "capabilities": list(plan.capabilities),
                "manual_capabilities": list(plan.manual_capabilities),
                "approval_reasons": list(plan.approval_reasons),
                "actions": [
                    {
                        "adapter": action.adapter,
                        "operation": action.operation,
                    }
                    for action in plan.actions
                ],
                "limits": plan.limits.model_dump(mode="json"),
                "expires_at": plan.expires_at.isoformat(),
            },
            sort_keys=True,
        )
        return await self._request(
            message=message,
            description=description,
            surface="ariadne-plan",
        )

    async def request_contract(
        self,
        summary: dict[str, object],
    ) -> ConsentDecision:
        import json

        target = str(summary.get("target", ""))
        return await self._request(
            message=f"Confirm the Ariadne engagement contract for {target}?",
            description=json.dumps(summary, sort_keys=True),
            surface="ariadne-contract",
        )

    async def request_amendment(
        self,
        summary: dict[str, object],
    ) -> ConsentDecision:
        import json

        return await self._request(
            message="Confirm this targeted Ariadne contract amendment?",
            description=json.dumps(summary, sort_keys=True),
            surface="ariadne-amendment",
        )

    async def _request(
        self,
        *,
        message: str,
        description: str,
        surface: str,
    ) -> ConsentDecision:
        if self._interactive_requester is not None:
            try:
                outcome = self._interactive_requester(
                    message=message,
                    description=description,
                    surface=surface,
                )
            except Exception:
                return ConsentDecision.UNAVAILABLE
            if outcome is not None:
                return self._normalize(outcome)

        async def invoke() -> object:
            outcome = await asyncio.to_thread(
                self._requester,
                message=message,
                description=description,
                timeout_seconds=self._requester_timeout_seconds,
                surface=surface,
            )
            return await outcome if isawaitable(outcome) else outcome

        try:
            outcome = await asyncio.wait_for(
                invoke(),
                timeout=self._external_timeout_seconds,
            )
        except TimeoutError:
            return ConsentDecision.CANCEL
        except Exception:
            return ConsentDecision.UNAVAILABLE
        return self._normalize(outcome)

    @staticmethod
    def _normalize(outcome: object) -> ConsentDecision:
        if not isinstance(outcome, str):
            return ConsentDecision.UNAVAILABLE
        try:
            decision = ConsentDecision(outcome)
        except ValueError:
            return ConsentDecision.UNAVAILABLE
        if decision == ConsentDecision.UNAVAILABLE:
            return ConsentDecision.UNAVAILABLE
        return decision


def load_hades_consent_gateway() -> ConsentGateway:
    """Load Hades' requester once at the composition boundary."""
    from importlib import import_module

    try:
        requester = import_module("tools.approval").request_elicitation_consent
    except (AttributeError, ImportError):
        return UnavailableConsentGateway()
    if not callable(requester):
        return UnavailableConsentGateway()

    try:
        callback_getter = import_module("tools.terminal_tool")._get_approval_callback
    except (AttributeError, ImportError):
        callback_getter = None

    def request_interactively(
        *,
        message: str,
        description: str,
        surface: str,
    ) -> str | None:
        del surface
        if not callable(callback_getter):
            return None
        callback = callback_getter()
        if callback is None:
            return None
        choice = callback(
            message,
            description,
            allow_permanent=False,
        )
        if choice in {"once", "session", "always"}:
            return ConsentDecision.ACCEPT.value
        return ConsentDecision.DECLINE.value

    return HadesConsentGateway(
        requester,
        interactive_requester=request_interactively,
    )
