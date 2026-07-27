"""Task 5: evidence-gated engagement state machine contract tests."""

import pytest
from pydantic import ValidationError

from ariadne.core.enums import EngagementState
from ariadne.core.errors import TransitionDeniedError
from ariadne.core.state_machine import (
    TRANSITION_RULES,
    TransitionRequest,
    TransitionRule,
    transition,
)

# ── TransitionRequest validation ─────────────────────────────────────────────


def test_transition_request_rejects_extra_fields() -> None:
    """TransitionRequest must be frozen and forbid extras."""
    with pytest.raises(ValidationError):
        TransitionRequest(
            next_state=EngagementState.EXECUTION,
            invalid_field="nope",
        )


# ── Primary state machine: IDLE → REPORTING → COMPLETE ─────────────────────


def test_idle_to_engagement_draft_is_legal() -> None:
    """The first state transition must be permitted."""
    result = transition(EngagementState.IDLE, TransitionRequest(
        next_state=EngagementState.ENGAGEMENT_DRAFT,
    ))
    assert result.previous_state is EngagementState.IDLE
    assert result.next_state is EngagementState.ENGAGEMENT_DRAFT
    assert result.event_type == "transition"


def test_engagement_draft_to_awaiting_confirmation() -> None:
    """Draft moves to confirmation."""
    result = transition(EngagementState.ENGAGEMENT_DRAFT, TransitionRequest(
        next_state=EngagementState.AWAITING_CONFIRMATION,
    ))
    assert result.next_state is EngagementState.AWAITING_CONFIRMATION


def test_awaiting_confirmation_to_snapshot_locked() -> None:
    """Confirmed engagement locks the snapshot."""
    result = transition(EngagementState.AWAITING_CONFIRMATION, TransitionRequest(
        next_state=EngagementState.SNAPSHOT_LOCKED,
    ))
    assert result.next_state is EngagementState.SNAPSHOT_LOCKED


def test_snapshot_locked_to_environment_preflight() -> None:
    """Locked snapshot proceeds to preflight."""
    result = transition(EngagementState.SNAPSHOT_LOCKED, TransitionRequest(
        next_state=EngagementState.ENVIRONMENT_PREFLIGHT,
    ))
    assert result.next_state is EngagementState.ENVIRONMENT_PREFLIGHT


def test_environment_preflight_to_discovery() -> None:
    """Preflight passes into discovery."""
    result = transition(EngagementState.ENVIRONMENT_PREFLIGHT, TransitionRequest(
        next_state=EngagementState.DISCOVERY,
    ))
    assert result.next_state is EngagementState.DISCOVERY


def test_discovery_to_enumeration_requires_evidence() -> None:
    """Discovery → Enumeration requires at least one evidence id."""
    request = TransitionRequest(
        next_state=EngagementState.ENUMERATION,
        evidence_ids=(),
    )
    with pytest.raises(TransitionDeniedError):
        transition(EngagementState.DISCOVERY, request)


def test_discovery_to_enumeration_with_evidence_passes() -> None:
    """Discovery → Enumeration succeeds when evidence is provided."""
    result = transition(EngagementState.DISCOVERY, TransitionRequest(
        next_state=EngagementState.ENUMERATION,
        evidence_ids=("nmap-scan-1",),
    ))
    assert result.next_state is EngagementState.ENUMERATION


def test_enumeration_to_hypothesis_requires_evidence() -> None:
    """Enumeration → Hypothesis requires at least one evidence id."""
    with pytest.raises(TransitionDeniedError):
        transition(EngagementState.ENUMERATION, TransitionRequest(
            next_state=EngagementState.HYPOTHESIS,
            evidence_ids=(),
        ))


def test_enumeration_to_hypothesis_with_evidence_passes() -> None:
    """Enumeration → Hypothesis succeeds with evidence."""
    result = transition(EngagementState.ENUMERATION, TransitionRequest(
        next_state=EngagementState.HYPOTHESIS,
        evidence_ids=("port-scan-1",),
    ))
    assert result.next_state is EngagementState.HYPOTHESIS


def test_hypothesis_to_action_planning_requires_evidence() -> None:
    """Hypothesis → Action Planning requires evidence."""
    with pytest.raises(TransitionDeniedError):
        transition(EngagementState.HYPOTHESIS, TransitionRequest(
            next_state=EngagementState.ACTION_PLANNING,
            evidence_ids=(),
        ))


def test_hypothesis_to_action_planning_with_evidence_passes() -> None:
    """Hypothesis → Action Planning succeeds with evidence."""
    result = transition(EngagementState.HYPOTHESIS, TransitionRequest(
        next_state=EngagementState.ACTION_PLANNING,
        evidence_ids=("vuln-hint-1",),
    ))
    assert result.next_state is EngagementState.ACTION_PLANNING


# ── Approval and execution gates ─────────────────────────────────────────────


def test_action_planning_to_awaiting_approval_requires_plan_id() -> None:
    """A plan must have a plan_id before entering awaiting approval."""
    request = TransitionRequest(
        next_state=EngagementState.AWAITING_APPROVAL,
        plan_id=None,
    )
    with pytest.raises(TransitionDeniedError):
        transition(EngagementState.ACTION_PLANNING, request)


def test_action_planning_to_awaiting_approval_with_plan_id() -> None:
    """With a plan_id the transition to awaiting approval succeeds."""
    result = transition(EngagementState.ACTION_PLANNING, TransitionRequest(
        next_state=EngagementState.AWAITING_APPROVAL,
        plan_id="plan-1",
    ))
    assert result.next_state is EngagementState.AWAITING_APPROVAL


def test_action_planning_to_auto_approved_requires_plan_id() -> None:
    """Auto-approval also requires a plan_id."""
    request = TransitionRequest(
        next_state=EngagementState.AUTO_APPROVED,
        plan_id=None,
    )
    with pytest.raises(TransitionDeniedError):
        transition(EngagementState.ACTION_PLANNING, request)


def test_action_planning_to_auto_approved_with_plan_id() -> None:
    """With a plan_id the auto-approve transition succeeds."""
    result = transition(EngagementState.ACTION_PLANNING, TransitionRequest(
        next_state=EngagementState.AUTO_APPROVED,
        plan_id="plan-2",
    ))
    assert result.next_state is EngagementState.AUTO_APPROVED


def test_execution_requires_approved_plan_and_minimum_evidence() -> None:
    """Execution is denied if approval_id or plan_id or evidence is missing."""
    request = TransitionRequest(
        next_state=EngagementState.EXECUTION,
        plan_id="plan-1",
        approval_id=None,
        evidence_ids=(),
    )
    with pytest.raises(TransitionDeniedError):
        transition(EngagementState.AWAITING_APPROVAL, request)


def test_execution_from_awaiting_approval_with_all_fields() -> None:
    """Execution from AWAITING_APPROVAL succeeds with plan_id, approval_id, and evidence."""
    result = transition(EngagementState.AWAITING_APPROVAL, TransitionRequest(
        next_state=EngagementState.EXECUTION,
        plan_id="plan-1",
        approval_id="approval-1",
        evidence_ids=("auth-check-1",),
    ))
    assert result.next_state is EngagementState.EXECUTION


def test_execution_from_auto_approved_with_all_fields() -> None:
    """Execution from AUTO_APPROVED also succeeds with all required fields."""
    result = transition(EngagementState.AUTO_APPROVED, TransitionRequest(
        next_state=EngagementState.EXECUTION,
        plan_id="plan-1",
        approval_id="approval-1",
        evidence_ids=("auto-auth-1",),
    ))
    assert result.next_state is EngagementState.EXECUTION


def test_execution_missing_plan_id() -> None:
    """Execution without a plan_id is denied."""
    with pytest.raises(TransitionDeniedError):
        transition(EngagementState.AWAITING_APPROVAL, TransitionRequest(
            next_state=EngagementState.EXECUTION,
            plan_id=None,
            approval_id="approval-1",
            evidence_ids=("e1",),
        ))


def test_execution_missing_approval_id() -> None:
    """Execution without an approval_id is denied."""
    with pytest.raises(TransitionDeniedError):
        transition(EngagementState.AWAITING_APPROVAL, TransitionRequest(
            next_state=EngagementState.EXECUTION,
            plan_id="plan-1",
            approval_id=None,
            evidence_ids=("e1",),
        ))


# ── Post-execution chain ─────────────────────────────────────────────────────


def test_execution_to_validation_requires_evidence() -> None:
    """Execution → Validation requires evidence."""
    with pytest.raises(TransitionDeniedError):
        transition(EngagementState.EXECUTION, TransitionRequest(
            next_state=EngagementState.VALIDATION,
            evidence_ids=(),
        ))


def test_execution_to_validation_with_evidence() -> None:
    """Execution → Validation succeeds with evidence."""
    result = transition(EngagementState.EXECUTION, TransitionRequest(
        next_state=EngagementState.VALIDATION,
        evidence_ids=("cmd-output-1",),
    ))
    assert result.next_state is EngagementState.VALIDATION


def test_validation_to_foothold_requires_evidence() -> None:
    """Validation → Foothold requires evidence."""
    with pytest.raises(TransitionDeniedError):
        transition(EngagementState.VALIDATION, TransitionRequest(
            next_state=EngagementState.FOOTHOLD,
            evidence_ids=(),
        ))


def test_validation_to_foothold_with_evidence() -> None:
    """Validation → Foothold succeeds with evidence."""
    result = transition(EngagementState.VALIDATION, TransitionRequest(
        next_state=EngagementState.FOOTHOLD,
        evidence_ids=("exploit-proof-1",),
    ))
    assert result.next_state is EngagementState.FOOTHOLD


def test_foothold_to_post_exploitation_requires_evidence() -> None:
    """Foothold → Post Exploitation requires evidence."""
    with pytest.raises(TransitionDeniedError):
        transition(EngagementState.FOOTHOLD, TransitionRequest(
            next_state=EngagementState.POST_EXPLOITATION,
            evidence_ids=(),
        ))


def test_foothold_to_post_exploitation_with_evidence() -> None:
    """Foothold → Post Exploitation succeeds with evidence."""
    result = transition(EngagementState.FOOTHOLD, TransitionRequest(
        next_state=EngagementState.POST_EXPLOITATION,
        evidence_ids=("shell-1",),
    ))
    assert result.next_state is EngagementState.POST_EXPLOITATION


def test_post_exploitation_to_privilege_escalation_requires_evidence() -> None:
    """Post-exploitation → PrivEsc requires evidence."""
    with pytest.raises(TransitionDeniedError):
        transition(EngagementState.POST_EXPLOITATION, TransitionRequest(
            next_state=EngagementState.PRIVILEGE_ESCALATION,
            evidence_ids=(),
        ))


def test_post_exploitation_to_privilege_escalation_with_evidence() -> None:
    """Post-exploitation → PrivEsc succeeds with evidence."""
    result = transition(EngagementState.POST_EXPLOITATION, TransitionRequest(
        next_state=EngagementState.PRIVILEGE_ESCALATION,
        evidence_ids=("enum-output-1",),
    ))
    assert result.next_state is EngagementState.PRIVILEGE_ESCALATION


def test_privilege_escalation_to_objective_validation_requires_evidence() -> None:
    """PrivEsc → Objective Validation requires evidence."""
    with pytest.raises(TransitionDeniedError):
        transition(EngagementState.PRIVILEGE_ESCALATION, TransitionRequest(
            next_state=EngagementState.OBJECTIVE_VALIDATION,
            evidence_ids=(),
        ))


def test_privilege_escalation_to_objective_validation_with_evidence() -> None:
    """PrivEsc → Objective Validation succeeds with evidence."""
    result = transition(EngagementState.PRIVILEGE_ESCALATION, TransitionRequest(
        next_state=EngagementState.OBJECTIVE_VALIDATION,
        evidence_ids=("root-flag-1",),
    ))
    assert result.next_state is EngagementState.OBJECTIVE_VALIDATION


def test_objective_validation_to_cleanup_requires_evidence() -> None:
    """Objective Validation → Cleanup requires evidence."""
    with pytest.raises(TransitionDeniedError):
        transition(EngagementState.OBJECTIVE_VALIDATION, TransitionRequest(
            next_state=EngagementState.CLEANUP,
            evidence_ids=(),
        ))


def test_objective_validation_to_cleanup_with_evidence() -> None:
    """Objective Validation → Cleanup succeeds with evidence."""
    result = transition(EngagementState.OBJECTIVE_VALIDATION, TransitionRequest(
        next_state=EngagementState.CLEANUP,
        evidence_ids=("flag-proof-1",),
    ))
    assert result.next_state is EngagementState.CLEANUP


def test_cleanup_to_reporting() -> None:
    """Cleanup → Reporting does not require evidence."""
    result = transition(EngagementState.CLEANUP, TransitionRequest(
        next_state=EngagementState.REPORTING,
    ))
    assert result.next_state is EngagementState.REPORTING


def test_reporting_to_complete() -> None:
    """Reporting → Complete."""
    result = transition(EngagementState.REPORTING, TransitionRequest(
        next_state=EngagementState.COMPLETE,
    ))
    assert result.next_state is EngagementState.COMPLETE


# ── Side states: scope amendment ─────────────────────────────────────────────


def test_new_asset_enters_scope_amendment_state() -> None:
    """Enumeration can transition to SCOPE_AMENDMENT_REQUIRED."""
    result = transition(
        EngagementState.ENUMERATION,
        TransitionRequest(
            next_state=EngagementState.SCOPE_AMENDMENT_REQUIRED,
            evidence_ids=("asset-observation-1",),
        ),
    )
    assert result.next_state is EngagementState.SCOPE_AMENDMENT_REQUIRED


def test_scope_amendment_requires_evidence() -> None:
    """Scope amendment requires at least one evidence id."""
    with pytest.raises(TransitionDeniedError):
        transition(EngagementState.DISCOVERY, TransitionRequest(
            next_state=EngagementState.SCOPE_AMENDMENT_REQUIRED,
            evidence_ids=(),
        ))


def test_scope_amendment_from_discovery() -> None:
    """Discovery can also enter scope amendment."""
    result = transition(EngagementState.DISCOVERY, TransitionRequest(
        next_state=EngagementState.SCOPE_AMENDMENT_REQUIRED,
        evidence_ids=("new-host-1",),
    ))
    assert result.next_state is EngagementState.SCOPE_AMENDMENT_REQUIRED


# ── Side states: pause, block, fail, abort ───────────────────────────────────


@pytest.mark.parametrize("source", [
    EngagementState.DISCOVERY,
    EngagementState.ENUMERATION,
    EngagementState.ACTION_PLANNING,
    EngagementState.EXECUTION,
    EngagementState.VALIDATION,
])
def test_pause_is_reachable_from_active_states(source: EngagementState) -> None:
    """Any active state can transition to PAUSED."""
    result = transition(source, TransitionRequest(
        next_state=EngagementState.PAUSED,
        reason="Operator requested pause",
    ))
    assert result.next_state is EngagementState.PAUSED


@pytest.mark.parametrize("source", [
    EngagementState.DISCOVERY,
    EngagementState.EXECUTION,
    EngagementState.POST_EXPLOITATION,
])
def test_blocked_is_reachable(source: EngagementState) -> None:
    """Any active state can transition to BLOCKED."""
    result = transition(source, TransitionRequest(
        next_state=EngagementState.BLOCKED,
        reason="Ambiguous target classification",
    ))
    assert result.next_state is EngagementState.BLOCKED


@pytest.mark.parametrize("source", [
    EngagementState.DISCOVERY,
    EngagementState.VALIDATION,
    EngagementState.CLEANUP,
])
def test_failed_is_reachable(source: EngagementState) -> None:
    """Any active state can transition to FAILED."""
    result = transition(source, TransitionRequest(
        next_state=EngagementState.FAILED,
        reason="Irrecoverable error",
    ))
    assert result.next_state is EngagementState.FAILED


@pytest.mark.parametrize("source", [
    EngagementState.ENUMERATION,
    EngagementState.ACTION_PLANNING,
    EngagementState.EXECUTION,
    EngagementState.CLEANUP,
])
def test_aborted_is_reachable(source: EngagementState) -> None:
    """Any active state can transition to ABORTED."""
    result = transition(source, TransitionRequest(
        next_state=EngagementState.ABORTED,
        reason="User aborted engagement",
    ))
    assert result.next_state is EngagementState.ABORTED


def test_resume_from_paused_to_discovery() -> None:
    """PAUSED can resume back to a previous active state."""
    result = transition(EngagementState.PAUSED, TransitionRequest(
        next_state=EngagementState.DISCOVERY,
        reason="Resume after operator review",
    ))
    assert result.next_state is EngagementState.DISCOVERY


def test_resume_from_paused_to_enumeration() -> None:
    """PAUSED can resume to enumeration."""
    result = transition(EngagementState.PAUSED, TransitionRequest(
        next_state=EngagementState.ENUMERATION,
        reason="Resume assessment",
    ))
    assert result.next_state is EngagementState.ENUMERATION


def test_uncurated_poc_approval_from_action_planning() -> None:
    """Action planning can enter uncurated PoC approval."""
    result = transition(EngagementState.ACTION_PLANNING, TransitionRequest(
        next_state=EngagementState.UNCURATED_POC_APPROVAL,
        plan_id="poc-plan-1",
    ))
    assert result.next_state is EngagementState.UNCURATED_POC_APPROVAL


def test_host_installation_approval_from_preflight() -> None:
    """Preflight can enter host installation approval."""
    result = transition(EngagementState.ENVIRONMENT_PREFLIGHT, TransitionRequest(
        next_state=EngagementState.HOST_INSTALLATION_APPROVAL,
    ))
    assert result.next_state is EngagementState.HOST_INSTALLATION_APPROVAL


# ── Illegal transitions ──────────────────────────────────────────────────────


def test_idle_to_execution_is_denied() -> None:
    """Skipping directly to execution from IDLE must be denied."""
    with pytest.raises(TransitionDeniedError):
        transition(EngagementState.IDLE, TransitionRequest(
            next_state=EngagementState.EXECUTION,
        ))


def test_idle_to_complete_is_denied() -> None:
    """Skipping directly to COMPLETE from IDLE must be denied."""
    with pytest.raises(TransitionDeniedError):
        transition(EngagementState.IDLE, TransitionRequest(
            next_state=EngagementState.COMPLETE,
        ))


def test_idle_to_reporting_is_denied() -> None:
    """Skipping directly to REPORTING from IDLE must be denied."""
    with pytest.raises(TransitionDeniedError):
        transition(EngagementState.IDLE, TransitionRequest(
            next_state=EngagementState.REPORTING,
        ))


def test_idle_to_foothold_is_denied() -> None:
    """Skipping directly to FOOTHOLD from IDLE must be denied."""
    with pytest.raises(TransitionDeniedError):
        transition(EngagementState.IDLE, TransitionRequest(
            next_state=EngagementState.FOOTHOLD,
        ))


def test_complete_to_any_state_is_denied() -> None:
    """COMPLETE is a terminal state — no outgoing transitions."""
    with pytest.raises(TransitionDeniedError):
        transition(EngagementState.COMPLETE, TransitionRequest(
            next_state=EngagementState.IDLE,
        ))


def test_failed_to_any_state_is_denied() -> None:
    """FAILED is a terminal state — no outgoing transitions."""
    with pytest.raises(TransitionDeniedError):
        transition(EngagementState.FAILED, TransitionRequest(
            next_state=EngagementState.IDLE,
        ))


def test_aborted_to_any_state_is_denied() -> None:
    """ABORTED is a terminal state — no outgoing transitions."""
    with pytest.raises(TransitionDeniedError):
        transition(EngagementState.ABORTED, TransitionRequest(
            next_state=EngagementState.IDLE,
        ))


# ── TransitionResult invariants ──────────────────────────────────────────────


def test_transition_result_differentiates_source_and_destination() -> None:
    """The result must correctly report both previous and next states."""
    result = transition(EngagementState.IDLE, TransitionRequest(
        next_state=EngagementState.ENGAGEMENT_DRAFT,
    ))
    assert result.previous_state is EngagementState.IDLE
    assert result.next_state is EngagementState.ENGAGEMENT_DRAFT
    assert result.previous_state is not result.next_state


def test_transition_result_event_type() -> None:
    """Every successful transition emits a 'transition' event type."""
    result = transition(EngagementState.IDLE, TransitionRequest(
        next_state=EngagementState.ENGAGEMENT_DRAFT,
    ))
    assert result.event_type == "transition"


# ── TRANSITION_RULES structural guarantees ───────────────────────────────────


def test_all_enum_states_appear_as_source_or_destination() -> None:
    """Every EngagementState value appears at least once as source or dest."""
    all_states = set(EngagementState)
    covered: set[EngagementState] = set()
    for rule in TRANSITION_RULES:
        covered.update(rule.sources)
        covered.add(rule.destination)
    uncovered = all_states - covered
    assert not uncovered, f"States never used in TRANSITION_RULES: {uncovered}"


def test_transition_rule_is_immutable() -> None:
    """TransitionRule fields must be frozen."""
    rule = TransitionRule(
        sources=frozenset({EngagementState.IDLE}),
        destination=EngagementState.ENGAGEMENT_DRAFT,
    )
    with pytest.raises(AttributeError):
        rule.destination = EngagementState.FAILED  # type: ignore[misc]
