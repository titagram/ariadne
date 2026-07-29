"""Bounded plan construction from validated playbooks.

The ``Planner`` consumes a ``WorkflowCatalog`` and a ``PlanningContext``
to produce a bounded ``Plan``. Each plan:
- references its source snapshot's hash for integrity binding;
- intersects playbook limits with effective policy bounds;
- sets a 15-minute expiry from the planning timestamp;
- rejects unregistered adapters, unmet evidence, any non-``in_scope``
  targets, or denied capabilities.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict

from ariadne.core.engagement import TargetSpec
from ariadne.core.errors import WorkflowConfigurationError
from ariadne.core.observations import AssetStatus
from ariadne.core.policy import CapabilityRule, EffectivePolicy, _min_or_none
from ariadne.core.workflow import (
    PlanningContext,
    PlaybookLimits,
    WorkflowCatalog,
)

# ── Registered adapters ───────────────────────────────────────────────────────
# Adjudicated at planning time so unregistered adapters are rejected early.

_REGISTERED_ADAPTERS: frozenset[str] = frozenset({
    "nmap",
    "httpx",
    "zap",
    "nuclei",
    "research",
    "metasploit",
    "postex",
    "active_directory",
    "pivot",
    "screenshot",
})

_MANUAL_ONLY_CAPABILITIES: frozenset[str] = frozenset({
    "scope.amend",
    "guardrail.exception",
    "host.install",
    "poc.uncurated",
    "sysreptor.push",
})

# ── Planner models ────────────────────────────────────────────────────────────


class PlannedAction(BaseModel):
    """A single action within a bounded plan.

    ``argv`` is always ``None`` at planning time — only the named adapter
    may generate the final argument vector at execution time.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    adapter: str
    operation: str
    inputs: dict[str, Any] = {}
    argv: list[str] | None = None


class Plan(BaseModel):
    """A bounded action plan for a specific hypothesis and playbook.

    Attributes:
        plan_id: Unique identifier for this plan.
        snapshot_hash: Hash of the engagement snapshot that was current
            when this plan was built. A new snapshot invalidates this plan.
        target: The target the plan applies to.
        hypothesis: The hypothesis this plan is testing / exploiting.
        playbook_id: The playbook from which this plan was derived.
        capabilities: Frozen capabilities authorized for the playbook.
        actions: Ordered actions to execute.  Every action's ``argv`` is
            ``None`` at planning time; adapters generate argv at run time.
        limits: Intersected limits (playbook ∩ effective policy).
        expected_evidence: Evidence types this plan is expected to produce.
        stop_conditions: Conditions that should cause plan execution to
            halt.
        cleanup: Cleanup actions associated with this plan.
        requires_manual_approval: Deterministic approval verdict derived
            from the playbook capabilities and effective policy.
        manual_capabilities: Capabilities that prevent auto-approval.
        approval_reasons: Human-readable reasons for the manual verdict.
        created_at: When the plan was constructed.
        expires_at: When the plan expires (15 min after creation).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    plan_id: str
    snapshot_hash: str
    target: TargetSpec
    hypothesis: str
    playbook_id: str
    capabilities: tuple[str, ...]
    actions: tuple[PlannedAction, ...]
    limits: PlaybookLimits
    expected_evidence: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    cleanup: tuple[str, ...] = ()
    requires_manual_approval: bool
    manual_capabilities: tuple[str, ...]
    approval_reasons: tuple[str, ...]
    created_at: datetime
    expires_at: datetime


# ── Planner ────────────────────────────────────────────────────────────────────


class Planner:
    """Build bounded plans from validated playbooks.

    Args:
        catalog: A loaded ``WorkflowCatalog`` whose playbooks serve as
            plan templates.
    """

    def __init__(self, catalog: WorkflowCatalog) -> None:
        self._catalog = catalog

    def build(self, playbook_id: str, context: PlanningContext) -> Plan:
        """Build a bounded ``Plan`` from a playbook and planning context.

        Args:
            playbook_id: The stable id of the playbook to build from.
            context: The current engagement planning context.

        Returns:
            A validated, bounded ``Plan`` ready for approval.

        Raises:
            WorkflowConfigurationError: If the playbook is unknown, an
                adapter is unregistered, evidence is unmet, the target is
                not ``in_scope``, or a capability is denied.
        """
        # 1. Resolve playbook
        playbook = self._catalog.playbooks.get(playbook_id)
        if playbook is None:
            raise WorkflowConfigurationError(
                f"Unknown playbook {playbook_id!r}"
            )

        # 2. Validate target status (fail-closed for every non-scope state)
        target = context.hypothesis.target
        for asset in context.assets:
            if asset.target == target and asset.status != AssetStatus.IN_SCOPE:
                raise WorkflowConfigurationError(
                    f"Target {target.host!r} is {asset.status.value} — "
                    f"planning requires an in_scope asset"
                )

        # 3. Validate capabilities against effective policy
        for cap in playbook.capabilities:
            rule: CapabilityRule | None = context.effective_policy.capabilities.get(cap)
            if rule is None or not rule.allowed:
                raise WorkflowConfigurationError(
                    f"Capability {cap!r} is not allowed by effective policy"
                )

        # 4. Validate evidence requirements
        if playbook.required_evidence_types:
            observed_types = {o.source for o in context.observations}
            missing = playbook.required_evidence_types - observed_types
            if missing:
                raise WorkflowConfigurationError(
                    f"Missing required evidence types: {sorted(missing)}"
                )

        # 5. Validate adapters
        for action in playbook.actions:
            if action.adapter not in _REGISTERED_ADAPTERS:
                raise WorkflowConfigurationError(
                    f"Unregistered adapter {action.adapter!r} in playbook "
                    f"{playbook_id}"
                )

        # 6. Freeze the deterministic approval verdict from the same
        # effective policy used to construct and bound the plan.
        manual_capabilities = tuple(sorted(
            cap
            for cap in playbook.capabilities
            if (
                cap in _MANUAL_ONLY_CAPABILITIES
                or context.effective_policy.capabilities[cap].always_manual
            )
        ))
        approval_reasons = tuple(
            (
                f"{cap} is a non-delegable manual capability"
                if cap in _MANUAL_ONLY_CAPABILITIES
                else f"effective policy requires manual approval for {cap}"
            )
            for cap in manual_capabilities
        )

        # 7. Intersect limits
        intersected_limits = self._intersect_limits(
            playbook.limits, context.effective_policy, playbook.capabilities
        )

        # 8. Build actions (argv = None at planning time)
        planned_actions = tuple(
            PlannedAction(
                adapter=a.adapter,
                operation=a.operation,
                inputs=a.inputs,
                argv=None,
            )
            for a in playbook.actions
        )

        # 9. Set expiry (15 minutes from now)
        now = context.now
        expires_at = now + timedelta(minutes=15)

        return Plan(
            plan_id=str(uuid4()),
            snapshot_hash=context.snapshot.snapshot_hash,
            target=target,
            hypothesis=context.hypothesis.statement,
            playbook_id=playbook.id,
            capabilities=tuple(sorted(playbook.capabilities)),
            actions=planned_actions,
            limits=intersected_limits,
            expected_evidence=tuple(playbook.success_emits),
            stop_conditions=playbook.stop_conditions,
            requires_manual_approval=bool(manual_capabilities),
            manual_capabilities=manual_capabilities,
            approval_reasons=approval_reasons,
            created_at=now,
            expires_at=expires_at,
        )

    @staticmethod
    def _intersect_limits(
        playbook_limits: PlaybookLimits,
        policy: EffectivePolicy,
        capabilities: frozenset[str],
    ) -> PlaybookLimits:
        """Intersect playbook limits with effective policy for each capability.

        Uses the tightest bound across all relevant capabilities.
        """
        # Collect bounds from policy for all relevant capabilities
        max_rate: int | None = playbook_limits.max_rate
        max_concurrency: int | None = playbook_limits.max_concurrency
        max_attempts: int | None = playbook_limits.max_attempts
        max_duration_seconds: int | None = playbook_limits.max_duration_seconds
        max_output_bytes: int | None = playbook_limits.max_output_bytes

        for cap in capabilities:
            rule = policy.capabilities.get(cap)
            if rule is None:
                continue
            max_rate = _min_or_none(max_rate, rule.max_rate)
            max_concurrency = _min_or_none(max_concurrency, rule.max_concurrency)
            max_attempts = _min_or_none(max_attempts, rule.max_attempts)
            max_duration_seconds = _min_or_none(max_duration_seconds, rule.max_duration_seconds)
            max_output_bytes = _min_or_none(max_output_bytes, rule.max_output_bytes)

        return PlaybookLimits(
            max_rate=max_rate,
            max_concurrency=max_concurrency,
            max_attempts=max_attempts,
            max_duration_seconds=max_duration_seconds,
            max_output_bytes=max_output_bytes,
        )
