"""Evidence-gated engagement state machine for Ariadne.

Defines the legal transition table between all engagement states,
enforcing required fields and minimum evidence before any transition
is permitted. Unknown or illegal transitions raise TransitionDenied
and emit no state change.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict

from ariadne.core.enums import EngagementState
from ariadne.core.errors import TransitionDeniedError

# ── Request / Result models ──────────────────────────────────────────────────


class TransitionRequest(BaseModel):
    """Payload for requesting an engagement state transition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    next_state: EngagementState
    plan_id: str | None = None
    approval_id: str | None = None
    evidence_ids: tuple[str, ...] = ()
    reason: str = ""


class TransitionResult(BaseModel):
    """Outcome of a successful state transition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    previous_state: EngagementState
    next_state: EngagementState
    event_type: str = "transition"


# ── Rule definition ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TransitionRule:
    """Describes one legal transition in the engagement state machine.

    Attributes:
        sources: Set of states this transition is valid from.
        destination: The single destination state.
        required_fields: Field names on TransitionRequest that must be
            non-None (and non-empty for sequence fields) for this
            transition.
        minimum_evidence: Minimum number of evidence ids required.
    """

    sources: frozenset[EngagementState]
    destination: EngagementState
    required_fields: frozenset[str] = frozenset()
    minimum_evidence: int = 0


# ── Helper to build frozensets concisely ─────────────────────────────────────


def _states(*states: EngagementState) -> frozenset[EngagementState]:
    return frozenset(states)


# ── Transition table ─────────────────────────────────────────────────────────
# Every EngagementState value must appear at least once as source or
# destination.  Terminal states (COMPLETE, FAILED, ABORTED) have no
# outgoing rules.

TRANSITION_RULES: tuple[TransitionRule, ...] = (
    # ── Primary flow ──────────────────────────────────────────────────────
    TransitionRule(
        sources=_states(EngagementState.IDLE),
        destination=EngagementState.ENGAGEMENT_DRAFT,
    ),
    TransitionRule(
        sources=_states(EngagementState.ENGAGEMENT_DRAFT),
        destination=EngagementState.AWAITING_CONFIRMATION,
    ),
    TransitionRule(
        sources=_states(EngagementState.AWAITING_CONFIRMATION),
        destination=EngagementState.SNAPSHOT_LOCKED,
    ),
    TransitionRule(
        sources=_states(EngagementState.SNAPSHOT_LOCKED),
        destination=EngagementState.ENVIRONMENT_PREFLIGHT,
    ),
    TransitionRule(
        sources=_states(EngagementState.ENVIRONMENT_PREFLIGHT),
        destination=EngagementState.DISCOVERY,
    ),
    TransitionRule(
        sources=_states(EngagementState.DISCOVERY),
        destination=EngagementState.ENUMERATION,
        minimum_evidence=1,
    ),
    TransitionRule(
        sources=_states(EngagementState.ENUMERATION),
        destination=EngagementState.HYPOTHESIS,
        minimum_evidence=1,
    ),
    TransitionRule(
        sources=_states(EngagementState.HYPOTHESIS),
        destination=EngagementState.ACTION_PLANNING,
        minimum_evidence=1,
    ),
    TransitionRule(
        sources=_states(EngagementState.ACTION_PLANNING),
        destination=EngagementState.AWAITING_APPROVAL,
        required_fields=frozenset({"plan_id"}),
    ),
    TransitionRule(
        sources=_states(EngagementState.ACTION_PLANNING),
        destination=EngagementState.AUTO_APPROVED,
        required_fields=frozenset({"plan_id"}),
    ),
    TransitionRule(
        sources=_states(EngagementState.AWAITING_APPROVAL),
        destination=EngagementState.EXECUTION,
        required_fields=frozenset({"plan_id", "approval_id"}),
        minimum_evidence=1,
    ),
    TransitionRule(
        sources=_states(EngagementState.AUTO_APPROVED),
        destination=EngagementState.EXECUTION,
        required_fields=frozenset({"plan_id", "approval_id"}),
        minimum_evidence=1,
    ),
    TransitionRule(
        sources=_states(EngagementState.EXECUTION),
        destination=EngagementState.VALIDATION,
        minimum_evidence=1,
    ),
    TransitionRule(
        sources=_states(EngagementState.VALIDATION),
        destination=EngagementState.FOOTHOLD,
        minimum_evidence=1,
    ),
    TransitionRule(
        sources=_states(EngagementState.FOOTHOLD),
        destination=EngagementState.POST_EXPLOITATION,
        minimum_evidence=1,
    ),
    TransitionRule(
        sources=_states(EngagementState.POST_EXPLOITATION),
        destination=EngagementState.PRIVILEGE_ESCALATION,
        minimum_evidence=1,
    ),
    TransitionRule(
        sources=_states(EngagementState.PRIVILEGE_ESCALATION),
        destination=EngagementState.OBJECTIVE_VALIDATION,
        minimum_evidence=1,
    ),
    TransitionRule(
        sources=_states(EngagementState.OBJECTIVE_VALIDATION),
        destination=EngagementState.CLEANUP,
        minimum_evidence=1,
    ),
    TransitionRule(
        sources=_states(EngagementState.CLEANUP),
        destination=EngagementState.REPORTING,
    ),
    TransitionRule(
        sources=_states(EngagementState.REPORTING),
        destination=EngagementState.COMPLETE,
    ),
    # ── Side state: scope amendment ───────────────────────────────────────
    TransitionRule(
        sources=_states(
            EngagementState.DISCOVERY,
            EngagementState.ENUMERATION,
            EngagementState.HYPOTHESIS,
            EngagementState.ACTION_PLANNING,
        ),
        destination=EngagementState.SCOPE_AMENDMENT_REQUIRED,
        minimum_evidence=1,
    ),
    # ── Side state: uncurated PoC approval ────────────────────────────────
    TransitionRule(
        sources=_states(EngagementState.ACTION_PLANNING),
        destination=EngagementState.UNCURATED_POC_APPROVAL,
        required_fields=frozenset({"plan_id"}),
    ),
    # ── Side state: host installation approval ────────────────────────────
    TransitionRule(
        sources=_states(EngagementState.ENVIRONMENT_PREFLIGHT),
        destination=EngagementState.HOST_INSTALLATION_APPROVAL,
    ),
    # ── Pause (from any non-terminal active state) ────────────────────────
    TransitionRule(
        sources=_states(*(
            s for s in EngagementState
            if s not in (
                EngagementState.IDLE,
                EngagementState.COMPLETE,
                EngagementState.FAILED,
                EngagementState.ABORTED,
            )
        )),
        destination=EngagementState.PAUSED,
    ),
    # ── Resume from pause ─────────────────────────────────────────────────
    TransitionRule(
        sources=_states(EngagementState.PAUSED),
        destination=EngagementState.ENGAGEMENT_DRAFT,
    ),
    TransitionRule(
        sources=_states(EngagementState.PAUSED),
        destination=EngagementState.AWAITING_CONFIRMATION,
    ),
    TransitionRule(
        sources=_states(EngagementState.PAUSED),
        destination=EngagementState.SNAPSHOT_LOCKED,
    ),
    TransitionRule(
        sources=_states(EngagementState.PAUSED),
        destination=EngagementState.ENVIRONMENT_PREFLIGHT,
    ),
    TransitionRule(
        sources=_states(EngagementState.PAUSED),
        destination=EngagementState.DISCOVERY,
    ),
    TransitionRule(
        sources=_states(EngagementState.PAUSED),
        destination=EngagementState.ENUMERATION,
    ),
    TransitionRule(
        sources=_states(EngagementState.PAUSED),
        destination=EngagementState.HYPOTHESIS,
    ),
    TransitionRule(
        sources=_states(EngagementState.PAUSED),
        destination=EngagementState.ACTION_PLANNING,
    ),
    TransitionRule(
        sources=_states(EngagementState.PAUSED),
        destination=EngagementState.AWAITING_APPROVAL,
    ),
    TransitionRule(
        sources=_states(EngagementState.PAUSED),
        destination=EngagementState.AUTO_APPROVED,
    ),
    TransitionRule(
        sources=_states(EngagementState.PAUSED),
        destination=EngagementState.EXECUTION,
    ),
    TransitionRule(
        sources=_states(EngagementState.PAUSED),
        destination=EngagementState.VALIDATION,
    ),
    TransitionRule(
        sources=_states(EngagementState.PAUSED),
        destination=EngagementState.FOOTHOLD,
    ),
    TransitionRule(
        sources=_states(EngagementState.PAUSED),
        destination=EngagementState.POST_EXPLOITATION,
    ),
    TransitionRule(
        sources=_states(EngagementState.PAUSED),
        destination=EngagementState.PRIVILEGE_ESCALATION,
    ),
    TransitionRule(
        sources=_states(EngagementState.PAUSED),
        destination=EngagementState.OBJECTIVE_VALIDATION,
    ),
    TransitionRule(
        sources=_states(EngagementState.PAUSED),
        destination=EngagementState.CLEANUP,
    ),
    TransitionRule(
        sources=_states(EngagementState.PAUSED),
        destination=EngagementState.REPORTING,
    ),
    # ── Blocked (from any non-terminal active state) ──────────────────────
    TransitionRule(
        sources=_states(*(
            s for s in EngagementState
            if s not in (
                EngagementState.IDLE,
                EngagementState.COMPLETE,
                EngagementState.FAILED,
                EngagementState.ABORTED,
                EngagementState.BLOCKED,
            )
        )),
        destination=EngagementState.BLOCKED,
    ),
    # ── Failed (terminal — from any non-terminal active state) ────────────
    TransitionRule(
        sources=_states(*(
            s for s in EngagementState
            if s not in (
                EngagementState.IDLE,
                EngagementState.COMPLETE,
                EngagementState.FAILED,
                EngagementState.ABORTED,
            )
        )),
        destination=EngagementState.FAILED,
    ),
    # ── Aborted (terminal — from any non-terminal active state) ───────────
    TransitionRule(
        sources=_states(*(
            s for s in EngagementState
            if s not in (
                EngagementState.IDLE,
                EngagementState.COMPLETE,
                EngagementState.FAILED,
                EngagementState.ABORTED,
            )
        )),
        destination=EngagementState.ABORTED,
    ),
)


# ── Transition engine ────────────────────────────────────────────────────────


def _field_is_set(request: TransitionRequest, field: str) -> bool:
    """Check whether a required field on the request is meaningfully set."""
    value = getattr(request, field, None)
    if value is None:
        return False
    # Sequence fields like evidence_ids must be non-empty.
    if isinstance(value, (tuple, list)) and len(value) == 0:
        return False
    # String fields must be non-empty.
    return not (isinstance(value, str) and value == "")


def transition(
    current: EngagementState,
    request: TransitionRequest,
) -> TransitionResult:
    """Attempt a state transition.

    Args:
        current: The current engagement state.
        request: The transition request specifying next state and any
            required fields.

    Returns:
        A TransitionResult with previous and next state.

    Raises:
        TransitionDeniedError: If no matching rule exists, required fields
            are missing, or minimum evidence is not met.
    """
    # Find a matching rule.
    matching: TransitionRule | None = None
    for rule in TRANSITION_RULES:
        if current in rule.sources and request.next_state == rule.destination:
            matching = rule
            break

    if matching is None:
        raise TransitionDeniedError(
            f"Transition from {current.value} to {request.next_state.value} "
            "is not a legal transition"
        )

    # Validate required fields.
    for field in matching.required_fields:
        if not _field_is_set(request, field):
            raise TransitionDeniedError(
                f"Transition from {current.value} to {request.next_state.value} "
                f"requires field '{field}'"
            )

    # Validate minimum evidence.
    if len(request.evidence_ids) < matching.minimum_evidence:
        raise TransitionDeniedError(
            f"Transition from {current.value} to {request.next_state.value} "
            f"requires at least {matching.minimum_evidence} evidence id(s), "
            f"got {len(request.evidence_ids)}"
        )

    return TransitionResult(
        previous_state=current,
        next_state=request.next_state,
    )
