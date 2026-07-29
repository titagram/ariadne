"""Composition-owned Hades consent gateway.

Only the composition root loads Hades' public elicitation function.  Handlers
consume this typed gateway and never accept a requester from model tool input.
"""

from __future__ import annotations

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


class HadesConsentGateway:
    """Adapter for Hades' ContextVar-scoped public elicitation API."""

    def __init__(self, requester: Any) -> None:
        if not callable(requester):
            raise TypeError("Hades consent requester must be callable")
        self._requester = requester

    async def request_plan(self, plan: Plan) -> ConsentDecision:
        import json

        message = (
            f"Authorize Ariadne plan {plan.plan_id[:8]} for target "
            f"{plan.target.host}?"
        )
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
        try:
            outcome = self._requester(
                message=message,
                description=description,
                timeout_seconds=120,
                surface="ariadne-plan",
            )
            if isawaitable(outcome):
                outcome = await outcome
        except TimeoutError:
            return ConsentDecision.CANCEL
        except Exception:
            return ConsentDecision.UNAVAILABLE
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
        requester = import_module(
            "tools.approval"
        ).request_elicitation_consent
    except (AttributeError, ImportError):
        return UnavailableConsentGateway()
    if not callable(requester):
        return UnavailableConsentGateway()
    return HadesConsentGateway(requester)
