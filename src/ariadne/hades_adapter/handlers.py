"""Ariadne tool handlers.

Each handler is an async function registered with Hades via
``PluginContext.register_tool(…, handler=<this>, is_async=True)``.

These handlers delegate to ``AriadneCommand`` for engagement lifecycle
operations. Session identity always comes from trusted Hades context.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from ariadne.adapters import AdapterRegistry
from ariadne.adapters.base import AdapterContext, Runtime
from ariadne.core.engagement import EngagementSnapshot, TargetSpec
from ariadne.core.enums import AssetStatus, AutonomyMode, EngagementState
from ariadne.core.errors import WorkflowConfigurationError
from ariadne.core.observations import Asset, Hypothesis, Observation
from ariadne.core.planner import Planner
from ariadne.core.policy import EffectivePolicy
from ariadne.core.workflow import PlanningContext, WorkflowCatalog
from ariadne.evidence.collector import EvidenceCollector
from ariadne.hades_adapter.commands import AriadneCommand
from ariadne.hades_adapter.schemas import PrepareEngagementInput
from ariadne.reporting.models import RenderedReport
from ariadne.reporting.professional import ProfessionalRenderer
from ariadne.reporting.validation import ReportOptions, ReportValidator
from ariadne.reporting.walkthrough import WalkthroughRenderer
from ariadne.store.run_store import RunHandle, RunStore


def _get_command(context: dict[str, Any]) -> AriadneCommand:
    """Extract the AriadneCommand from the handler context."""
    cmd = context.get("ariadne_command")
    if cmd is None:
        raise ValueError(
            "No ariadne_command available in handler context. "
            "The composition root must pass it as a keyword argument."
        )
    if not isinstance(cmd, AriadneCommand):
        raise TypeError(
            f"Expected AriadneCommand, got {type(cmd).__name__}"
        )
    return cmd


def _get_planner(context: dict[str, Any]) -> Planner:
    """Extract the Planner from the handler context."""
    planner = context.get("planner")
    if planner is None:
        raise ValueError(
            "No planner available in handler context. "
            "The composition root must pass it as a keyword argument."
        )
    if not isinstance(planner, Planner):
        raise TypeError(
            f"Expected Planner, got {type(planner).__name__}"
        )
    return planner


def _get_catalog(context: dict[str, Any]) -> WorkflowCatalog:
    """Extract the WorkflowCatalog from the handler context."""
    catalog = context.get("catalog")
    if catalog is None:
        raise ValueError(
            "No catalog available in handler context."
        )
    if not isinstance(catalog, WorkflowCatalog):
        raise TypeError(
            f"Expected WorkflowCatalog, got {type(catalog).__name__}"
        )
    return catalog


def _get_adapter_registry(context: dict[str, Any]) -> AdapterRegistry:
    """Extract the AdapterRegistry from the handler context."""
    registry = context.get("adapter_registry")
    if registry is None:
        raise ValueError(
            "No adapter_registry available in handler context."
        )
    if not isinstance(registry, AdapterRegistry):
        raise TypeError(
            f"Expected AdapterRegistry, got {type(registry).__name__}"
        )
    return registry


def _get_runtime(context: dict[str, Any]) -> Runtime:
    """Extract the Runtime from the handler context."""
    runtime = context.get("runtime")
    if runtime is None:
        raise ValueError(
            "No runtime available in handler context."
        )
    return runtime


def _determine_engagement_state(
    store: RunStore,
    run_handle: RunHandle,
) -> tuple[EngagementState, tuple[Observation, ...]]:
    """Read the run store and determine the current engagement state.

    Checks the events log to find existing evidence types and maps them
    to the correct ``EngagementState``.

    Returns:
        A ``(state, observations)`` tuple where ``observations`` contains
        all past evidence observations reconstructed from store events.
    """
    events = store.read_events(run_handle)

    # Collect evidence type strings from evidence_collected events
    evidence_types: set[str] = set()
    observations: list[Observation] = []

    for evt in events:
        event_type = evt.get("event_type", "")
        payload = evt.get("payload", {})

        if event_type == "evidence_collected":
            evidence_type = payload.get("evidence_type", "")
            if evidence_type:
                evidence_types.add(evidence_type)

            # Build a synthetic observation from the evidence
            from uuid import uuid4

            obs = Observation(
                observation_id=uuid4(),
                target=run_handle.snapshot.targets[0]
                if run_handle.snapshot.targets
                else TargetSpec(host="unknown"),
                source=evidence_type or "unknown",
                data={
                    "event_type": event_type,
                    "finding": payload.get("finding", ""),
                    "artifact": payload.get("artifact", ""),
                },
            )
            observations.append(obs)

    # Get already-executed playbook IDs from the store
    executed_playbooks: set[str] = set()
    for evt in events:
        if evt.get("event_type") == "plan_executed":
            payload = evt.get("payload", {})
            if payload.get("status") in ("executed", "success", "failed"):
                pb_id = payload.get("playbook_id", "")
                if pb_id:
                    executed_playbooks.add(pb_id)

    # Check evidence types from most advanced to most basic.  Each emitted
    # evidence type advances to the stage of the next playbook.
    if "report_ready" in evidence_types:
        return EngagementState.COMPLETE, tuple(observations)
    if "cleanup_complete" in evidence_types:
        return EngagementState.REPORTING, tuple(observations)
    if "objective_proven" in evidence_types or "objective_completed" in evidence_types:
        return EngagementState.CLEANUP, tuple(observations)
    if "privesc_found" in evidence_types or "privesc_path_identified" in evidence_types:
        return EngagementState.OBJECTIVE_VALIDATION, tuple(observations)
    if (
        "host_info_collected" in evidence_types
        or "host_enumerated" in evidence_types
        or "postex_complete" in evidence_types
    ):
        return EngagementState.PRIVILEGE_ESCALATION, tuple(observations)
    if "foothold_established" in evidence_types:
        return EngagementState.POST_EXPLOITATION, tuple(observations)
    if "vulnerability_validated" in evidence_types or "exploit_succeeded" in evidence_types:
        return EngagementState.FOOTHOLD, tuple(observations)
    if "research_complete" in evidence_types or "cve_reference" in evidence_types:
        return EngagementState.VALIDATION, tuple(observations)
    if "protocol_routed" in evidence_types:
        return EngagementState.HYPOTHESIS, tuple(observations)
    if "service_fingerprinted" in evidence_types:
        return EngagementState.ENUMERATION, tuple(observations)
    if "port_open" in evidence_types:
        return EngagementState.ENUMERATION, tuple(observations)
    if "preflight_passed" in evidence_types or "research.preflight" in evidence_types:
        return EngagementState.DISCOVERY, tuple(observations)

    # If there are events but no preflight evidence, we're still in preflight
    if events:
        return EngagementState.ENVIRONMENT_PREFLIGHT, tuple(observations)

    # No events at all — brand new engagement, start at preflight
    return EngagementState.ENVIRONMENT_PREFLIGHT, ()


def _get_binding(cmd: AriadneCommand, session_id: str) -> dict[str, Any] | None:
    """Check for an active engagement binding and return its metadata.

    Returns None if the session has no active binding.
    """
    if not session_id:
        return None
    binding = cmd.get_session_binding(session_id)
    if binding is None:
        return None
    return {
        "snapshot_hash": binding.snapshot_hash,
        "engagement_id": binding.engagement_id,
        "session_id": binding.session_id,
    }


async def handle_prepare_engagement(
    args: dict[str, Any], **context: Any
) -> dict[str, Any]:
    """Validate the completed Q/A, then atomically lock and bind it."""
    cmd = _get_command(context)
    if "session_id" in args:
        return {
            "status": "error",
            "message": "session_id must come from trusted Hades context.",
            "engagement_id": "",
            "snapshot_hash": "",
        }
    session_id = context.get("session_id")
    if not isinstance(session_id, str) or not session_id.strip():
        return {
            "status": "error",
            "message": "A trusted Hades session_id is required.",
            "engagement_id": "",
            "snapshot_hash": "",
        }
    try:
        validated = PrepareEngagementInput.model_validate(args)
    except ValidationError as exc:
        return {
            "status": "error",
            "message": f"Invalid engagement answers: {exc}",
            "engagement_id": "",
            "snapshot_hash": "",
        }

    try:
        result = cmd.prepare(
            validated.model_dump(),
            session_id=session_id,
        )
    except (OSError, ValueError, TypeError) as exc:
        return {
            "status": "error",
            "message": f"Engagement was not locked: {exc}",
            "engagement_id": "",
            "snapshot_hash": "",
        }
    return {
        "status": result.status,
        "message": result.message,
        "engagement_id": str(result.engagement_id) if result.engagement_id else "",
        "snapshot_hash": result.snapshot_hash or "",
    }


async def handle_status(args: dict[str, Any], **context: Any) -> dict[str, Any]:
    """Return current engagement status.

    Checks the ``AriadneCommand`` for any active engagement in the
    ledger.  Otherwise falls back to the generic non-active response.
    """
    if "session_id" in args:
        return {
            "status": "error",
            "message": "session_id must come from trusted Hades context.",
        }
    try:
        cmd = _get_command(context)
        session_id = context.get("session_id", "")
        if cmd.get_session_binding(session_id) is not None:
            return {
                "status": "active",
                "message": "Active engagement found for this session.",
            }
    except (ValueError, TypeError):
        pass

    return {
        "status": "no_active_engagement",
        "message": "No active engagement.",
    }


async def handle_propose_plan(args: dict[str, Any], **context: Any) -> dict[str, Any]:
    """Propose a bounded action plan.

    Validates:
    - Active engagement binding exists for this session
    - Provided snapshot_hash matches the bound snapshot
    - All playbook preconditions (capabilities allowed, adapters registered)

    Builds a PlanningContext from the engagement snapshot, selects an
    eligible playbook, and constructs a bounded Plan.  The plan is
    recorded in the command's plan ledger. Controlled and manual-only plans
    await the user; eligible full-autonomy plans are durably auto-approved.
    """
    cmd = _get_command(context)
    if "session_id" in args:
        return {
            "status": "error",
            "message": "session_id must come from trusted Hades context.",
            "plan_id": "",
        }
    session_id = context.get("session_id", "")
    input_session_id = session_id

    # 1. Check active engagement FIRST (before getting planner/catalog)
    binding_info = _get_binding(cmd, input_session_id)
    if binding_info is None:
        return {
            "status": "error",
            "message": "No active engagement. Please bind an engagement first.",
            "plan_id": "",
        }

    planner = _get_planner(context)
    catalog = _get_catalog(context)

    snapshot_hash = args.get("snapshot_hash", "")
    hypothesis_str = args.get("hypothesis", "")

    # 2. Validate snapshot hash matches binding
    if snapshot_hash != binding_info["snapshot_hash"]:
        return {
            "status": "error",
            "message": (
                f"Snapshot hash mismatch: provided {snapshot_hash}, "
                f"expected {binding_info['snapshot_hash']}"
            ),
            "plan_id": "",
        }

    # 3. Rebuild the EngagementSnapshot from the store
    engagement_id = binding_info["engagement_id"]
    if not engagement_id:
        return {
            "status": "error",
            "message": "No engagement id in binding.",
            "plan_id": "",
        }

    run_handle = _get_run_handle(cmd.store, engagement_id)
    if run_handle is None:
        return {
            "status": "error",
            "message": "Engagement snapshot not found in store.",
            "plan_id": "",
        }

    snapshot = run_handle.snapshot

    # 4. Determine current engagement state from the run store
    state, observations = _determine_engagement_state(cmd.store, run_handle)

    # Also extract executed playbooks from events
    events = cmd.store.read_events(run_handle)
    executed_playbooks: set[str] = set()
    for evt in events:
        if evt.get("event_type") == "plan_executed":
            payload = evt.get("payload", {})
            if payload.get("status") in ("executed", "success", "failed"):
                pb_id = payload.get("playbook_id", "")
                if pb_id:
                    executed_playbooks.add(pb_id)

    # Use the first target as the hypothesis target
    first_target = snapshot.targets[0] if snapshot.targets else TargetSpec(host="unknown")

    from uuid import uuid4

    hypothesis = Hypothesis(
        hypothesis_id=uuid4(),
        target=first_target,
        statement=hypothesis_str or "Automated discovery playbook",
        confidence=0.5,
    )

    # Build minimal assets (target is in-scope)
    assets = tuple(
        Asset(
            asset_id=uuid4(),
            target=t,
            status=AssetStatus.IN_SCOPE,
        )
        for t in snapshot.targets
    )

    # Load effective policy from the store's engagement.lock.yaml
    effective_policy = _load_engagement_policy(snapshot)

    planning_context = PlanningContext(
        snapshot=snapshot,
        state=state,
        observations=observations,
        assets=assets,
        effective_policy=effective_policy,
        hypothesis=hypothesis,
        now=datetime.now(UTC),
    )

    # 5. Find eligible playbooks and build the first plan
    eligible = catalog.eligible(planning_context)
    # Filter out playbooks already executed in this engagement
    eligible = tuple(p for p in eligible if p.id not in executed_playbooks)
    if not eligible:
        # No eligible playbooks — check if any playbook exists at all
        if not catalog.playbooks:
            return {
                "status": "error",
                "message": "No playbooks configured in the workflow catalog.",
                "plan_id": "",
            }
        return {
            "status": "error",
            "message": (
                "No eligible playbooks for the current engagement state and evidence. "
                "Try collecting more evidence first."
            ),
            "plan_id": "",
        }

    playbook = eligible[0]
    try:
        plan = planner.build(playbook.id, planning_context)
    except WorkflowConfigurationError as exc:
        return {
            "status": "error",
            "message": f"Plan construction failed: {exc}",
            "plan_id": "",
        }

    # 6. Persist the proposal before exposing it through the in-memory ledger.
    from ariadne.store.run_store import Event

    capabilities = sorted(playbook.capabilities)
    proposal_payload = {
        "plan_id": plan.plan_id,
        "playbook_id": plan.playbook_id,
        "snapshot_hash": snapshot_hash,
        "session_id": input_session_id,
        "autonomy": snapshot.autonomy.value,
        "capabilities": capabilities,
        "requires_manual_approval": plan.requires_manual_approval,
        "manual_capabilities": list(plan.manual_capabilities),
        "approval_reasons": list(plan.approval_reasons),
    }
    try:
        cmd.store.append_event(
            run_handle,
            Event(
                event_type="plan_proposed",
                payload=proposal_payload,
                timestamp=datetime.now(UTC),
            ),
        )
    except Exception as exc:
        # The store is the authorization ledger. Any persistence failure,
        # regardless of backend exception type, must fail closed.
        return {
            "status": "error",
            "message": f"Could not persist plan proposal: {exc}",
            "plan_id": plan.plan_id,
        }

    # 7. Record the plan in the command's plan ledger, initially unapproved.
    cmd.add_plan(plan, snapshot_hash, input_session_id)

    should_auto_approve = (
        snapshot.autonomy == AutonomyMode.FULL
        and not plan.requires_manual_approval
    )
    if should_auto_approve:
        try:
            cmd.store.append_event(
                run_handle,
                Event(
                    event_type="plan_auto_approved",
                    payload={
                        **proposal_payload,
                        "reason": "full_autonomy_curated_in_policy",
                    },
                    timestamp=datetime.now(UTC),
                ),
            )
        except Exception as exc:
            # Never mutate the in-memory approval record unless the durable
            # event chain accepted the approval first.
            return {
                "status": "error",
                "message": (
                    "Could not persist automatic approval; "
                    f"the plan remains unapproved: {exc}"
                ),
                "plan_id": plan.plan_id,
            }
        cmd.auto_approve_plan(plan.plan_id)

    approval_status = (
        "auto_approved" if should_auto_approve else "awaiting_user_approval"
    )
    message = (
        f"Plan {plan.plan_id[:8]} auto-approved for full continuous mode. "
        "Call ariadne_execute_plan now; do not request /ariadne approve."
        if should_auto_approve
        else (
            f"Plan {plan.plan_id[:8]} proposed with {len(plan.actions)} action(s) "
            f"for target {plan.target.host}. "
            f"Use /ariadne approve {plan.plan_id} to approve, "
            f"then ariadne_execute_plan to run."
        )
    )

    return {
        "status": "plan_auto_approved" if should_auto_approve else "plan_proposed",
        "approval_status": approval_status,
        "plan_id": plan.plan_id,
        "playbook_id": plan.playbook_id,
        "actions": [
            {
                "adapter": a.adapter,
                "operation": a.operation,
            }
            for a in plan.actions
        ],
        "target": plan.target.host,
        "hypothesis": plan.hypothesis,
        "expires_at": plan.expires_at.isoformat(),
        "limits": plan.limits.model_dump(mode="json"),
        "requires_manual_approval": plan.requires_manual_approval,
        "manual_capabilities": list(plan.manual_capabilities),
        "approval_reasons": list(plan.approval_reasons),
        "message": message,
    }


async def handle_execute_plan(args: dict[str, Any], **context: Any) -> dict[str, Any]:
    """Execute an approved plan.

    Validates:
    - Active engagement binding exists for this session
    - Plan exists in the ledger
    - Plan has been manually or durably automatically approved
    - Plan has not expired

    For this vertical slice without real adapters, records the
    execution as an evidence event in the store.
    """
    cmd = _get_command(context)
    if "session_id" in args:
        return {
            "status": "error",
            "message": "session_id must come from trusted Hades context.",
            "plan_id": args.get("plan_id", ""),
        }
    session_id = context.get("session_id", "")
    input_session_id = session_id
    plan_id = args.get("plan_id", "")

    # 1. Check active engagement
    binding_info = _get_binding(cmd, input_session_id)
    if binding_info is None:
        return {
            "status": "error",
            "message": "No active engagement. Please bind an engagement first.",
            "plan_id": plan_id,
        }

    # 2. Check plan exists
    record = cmd.get_plan_record(plan_id)
    if record is None:
        return {
            "status": "error",
            "message": f"Unknown plan: {plan_id!r}",
            "plan_id": plan_id,
        }

    # 3. Bind the plan to its trusted session and current immutable snapshot.
    if record.session_id != input_session_id:
        return {
            "status": "error",
            "message": "Plan belongs to a different trusted Hades session.",
            "plan_id": plan_id,
        }

    engagement_id = binding_info["engagement_id"]
    if not engagement_id:
        return {
            "status": "error",
            "message": "No engagement id in binding.",
            "plan_id": plan_id,
        }
    run_handle = _get_run_handle(cmd.store, engagement_id)
    if run_handle is None:
        return {
            "status": "error",
            "message": "Engagement snapshot not found in store.",
            "plan_id": plan_id,
        }

    from ariadne.core.engagement import calculate_snapshot_hash
    from ariadne.store.integrity import verify_run

    active_hash = binding_info["snapshot_hash"]
    persisted_hash = run_handle.snapshot.snapshot_hash
    if (
        record.snapshot_hash != active_hash
        or record.plan.snapshot_hash != active_hash
        or persisted_hash != active_hash
        or calculate_snapshot_hash(run_handle.snapshot) != persisted_hash
        or not verify_run(run_handle.path).valid
    ):
        return {
            "status": "error",
            "message": "Plan snapshot is stale or the active run failed integrity checks.",
            "plan_id": plan_id,
        }

    # 4. Check plan is approved
    if not record.approved:
        return {
            "status": "error",
            "message": (
                f"Plan {plan_id[:8]} has not been approved yet. "
                f"Use /ariadne approve {plan_id} first."
            ),
            "plan_id": plan_id,
        }

    # 5. Check plan has not expired
    if cmd.is_plan_expired(plan_id):
        return {
            "status": "error",
            "message": f"Plan {plan_id[:8]} has expired. Propose a new plan.",
            "plan_id": plan_id,
        }

    # 6. Execute plan actions via registered adapters
    registry = _get_adapter_registry(context)
    runtime = _get_runtime(context)

    from ariadne.adapters.base import (
        PlannedAction as AdapterPlannedAction,
    )
    from ariadne.store.run_store import Event

    now = datetime.now(UTC)
    actions_executed = 0
    actions_failed = 0
    evidence_artifacts: list[dict[str, Any]] = []

    for action in record.plan.actions:
        adapter = registry.get(action.adapter)
        if adapter is None:
            actions_failed += 1
            # Record a failed execution event
            cmd.store.append_event(
                run_handle,
                Event(
                    event_type="plan_executed",
                    payload={
                        "plan_id": plan_id,
                        "playbook_id": record.plan.playbook_id,
                        "action": action.adapter,
                        "operation": action.operation,
                        "status": "failed",
                        "error": f"Adapter {action.adapter!r} not registered",
                        "target": record.plan.target.host,
                    },
                    timestamp=now,
                ),
            )
            continue

        # Build adapter context and planned action
        adapter_ctx = AdapterContext(
            target=record.plan.target,
            snapshot_hash=record.snapshot_hash,
            engagement_id=engagement_id,
            adapter_name=action.adapter,
        )

        planned_action = AdapterPlannedAction(
            operation=action.operation,
            inputs=dict(action.inputs),
        )

        try:
            # Generate ProcessSpec via adapter.plan() — argv at execution time
            process_spec = adapter.plan(planned_action, adapter_ctx)

            # Execute via runtime
            process_result = await adapter.execute(process_spec, runtime)

            # Parse observations from output
            observations = adapter.parse(process_result)

            # Classify the result
            classification = adapter.classify(process_result, observations)

            # Collect evidence
            evidence_collector = EvidenceCollector(
                snapshot_hash=record.snapshot_hash,
                plan_id=plan_id,
                engagement_id=engagement_id,
            )
            evidence_results = await adapter.collect(
                process_result, evidence_collector
            )

            # Determine status based on classification
            status = "executed"
            if classification.kind == "failure":
                status = "failed"
                actions_failed += 1
            else:
                actions_executed += 1

            # Record plan_executed event
            cmd.store.append_event(
                run_handle,
                Event(
                    event_type="plan_executed",
                    payload={
                        "plan_id": plan_id,
                        "playbook_id": record.plan.playbook_id,
                        "action": action.adapter,
                        "operation": action.operation,
                        "status": status,
                        "classification": classification.kind,
                        "confidence": classification.confidence,
                        "summary": classification.summary,
                        "target": record.plan.target.host,
                        "exit_code": process_result.exit_code,
                    },
                    timestamp=now,
                ),
            )

            # Record evidence collected events — one per observation
            for obs in observations:
                evidence_artifact = (
                    f"{action.adapter}_{action.operation}_"
                    f"{obs.observation_id.hex[:8]}.txt"
                )
                cmd.store.append_event(
                    run_handle,
                    Event(
                        event_type="evidence_collected",
                        payload={
                            "artifact": evidence_artifact,
                            "finding": _format_finding(action, obs),
                            "evidence_type": obs.source,
                            "asset": record.plan.target.host,
                            "observation_id": str(obs.observation_id),
                            "adapter": action.adapter,
                        },
                        timestamp=now,
                    ),
                )
                evidence_artifacts.append({
                    "artifact": evidence_artifact,
                    "observation_id": str(obs.observation_id),
                })

            # If the adapter produced its own evidence artifacts, record those too
            for ev_result in (evidence_results or ()):
                if ev_result not in ("evidence_collected",):
                    cmd.store.append_event(
                        run_handle,
                        Event(
                            event_type="evidence_collected",
                            payload={
                                "artifact": ev_result,
                                "finding": (
                                    f"{action.adapter}:{action.operation} "
                                    f"produced {ev_result}"
                                ),
                                "evidence_type": action.adapter,
                                "asset": record.plan.target.host,
                            },
                            timestamp=now,
                        ),
                    )
                    evidence_artifacts.append({
                        "artifact": ev_result,
                    })

        except Exception as exc:
            actions_failed += 1
            cmd.store.append_event(
                run_handle,
                Event(
                    event_type="plan_executed",
                    payload={
                        "plan_id": plan_id,
                        "playbook_id": record.plan.playbook_id,
                        "action": action.adapter,
                        "operation": action.operation,
                        "status": "error",
                        "error": str(exc),
                        "target": record.plan.target.host,
                    },
                    timestamp=now,
                ),
            )

    # Materialize the playbook's declared outputs after a fully successful run.
    # Adapter observations are implementation-specific; success_emits is the
    # workflow contract consumed by downstream playbooks and state transitions.
    if actions_executed > 0 and actions_failed == 0:
        catalog = _get_catalog(context)
        playbook = catalog.playbooks.get(record.plan.playbook_id)
        if playbook is not None:
            existing_evidence = {
                evt.get("payload", {}).get("evidence_type", "")
                for evt in cmd.store.read_events(run_handle)
                if evt.get("event_type") == "evidence_collected"
            }
            for evidence_type in playbook.success_emits:
                if evidence_type not in existing_evidence:
                    cmd.store.append_event(
                        run_handle,
                        Event(
                            event_type="evidence_collected",
                            payload={
                                "finding": (
                                    f"Playbook {playbook.id} emitted {evidence_type}"
                                ),
                                "evidence_type": evidence_type,
                                "asset": record.plan.target.host,
                                "playbook_id": playbook.id,
                            },
                            timestamp=now,
                        ),
                    )

            # Report validation consumes lifecycle events rather than evidence
            # types, so bridge the corresponding workflow outputs explicitly.
            lifecycle_events = {
                "objective_proven": "objective_completed",
                "cleanup_complete": "cleanup_completed",
            }
            existing_event_types = {
                evt.get("event_type", "")
                for evt in cmd.store.read_events(run_handle)
            }
            for evidence_type, event_type in lifecycle_events.items():
                if (
                    evidence_type in playbook.success_emits
                    and event_type not in existing_event_types
                ):
                    cmd.store.append_event(
                        run_handle,
                        Event(
                            event_type=event_type,
                            payload={
                                "plan_id": plan_id,
                                "playbook_id": playbook.id,
                                "target": record.plan.target.host,
                            },
                            timestamp=now,
                        ),
                    )

    # Compute overall status
    overall_status = "executed" if actions_failed == 0 else "partial"
    total_actions = actions_executed + actions_failed

    return {
        "status": overall_status,
        "plan_id": plan_id,
        "next_action": "continue_until_complete_then_render_offline_report",
        "message": (
            f"Plan {plan_id[:8]} executed with {actions_executed}/{total_actions} action(s) "
            f"against target {record.plan.target.host}. "
            f"{actions_failed} action(s) failed. Continue proposing and executing "
            "eligible plans until the objective and cleanup complete, then render "
            "the offline report automatically."
        ),
        "actions_executed": actions_executed,
        "actions_failed": actions_failed,
        "evidence_artifacts": evidence_artifacts,
    }


def _format_finding(
    action: Any,
    observation: Observation,
) -> str:
    """Format a human-readable finding from an action and observation."""
    parts = [f"{action.adapter}:{action.operation}"]
    data = observation.data or {}
    if isinstance(data, dict):
        summary = data.get("summary", "") or data.get("type", "")
        if summary:
            parts.append(str(summary))
    return " — ".join(parts)


async def handle_render_report(args: dict[str, Any], **context: Any) -> dict[str, Any]:
    """Render a walkthrough or professional report.

    Validates:
    - Active engagement binding exists for this session
    - Style is one of 'walkthrough' or 'professional'
    - Engagement run exists in the store with sufficient events

    Delegates to WalkthroughRenderer or ProfessionalRenderer after
    validation via ReportValidator.
    """
    cmd = _get_command(context)
    if "session_id" in args:
        return {
            "status": "error",
            "message": "session_id must come from trusted Hades context.",
            "path": "",
        }
    session_id = context.get("session_id", "")
    input_session_id = session_id
    style = args.get("style", "walkthrough")

    # 1. Check active engagement
    binding_info = _get_binding(cmd, input_session_id)
    if binding_info is None:
        return {
            "status": "error",
            "message": "No active engagement. Please bind an engagement first.",
            "path": "",
        }

    # 2. Validate style
    if style not in ("walkthrough", "professional"):
        return {
            "status": "error",
            "message": f"Unknown report style: {style!r}. Use 'walkthrough' or 'professional'.",
            "path": "",
        }

    # 3. Get the run handle
    engagement_id = binding_info["engagement_id"]
    if not engagement_id:
        return {
            "status": "error",
            "message": "No engagement id in binding.",
            "path": "",
        }

    run_handle = _get_run_handle(cmd.store, engagement_id)
    if run_handle is None:
        return {
            "status": "error",
            "message": "Engagement snapshot not found in store.",
            "path": "",
        }

    # 4. Validate the run
    validator = ReportValidator()
    validation = validator.validate(run_handle, ReportOptions())
    if not validation.valid:
        return {
            "status": "error",
            "message": (
                f"Report validation failed: {'; '.join(validation.errors)}"
            ),
            "path": "",
        }

    # 5. Render the report
    try:
        rendered: RenderedReport
        if style == "walkthrough":
            renderer = WalkthroughRenderer()
            rendered = renderer.render(run_handle, ReportOptions())
            ext = "md"
        else:
            renderer = ProfessionalRenderer()
            rendered = renderer.render(run_handle, ReportOptions())
            ext = "html"

        # Write to a file
        report_path = run_handle.path / f"{style}_report.{ext}"
        report_path.write_text(rendered.text, encoding="utf-8")

        return {
            "status": "report_rendered",
            "style": style,
            "path": str(report_path),
            "message": f"{style.title()} report written to {report_path.name}",
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Report rendering failed: {exc}",
            "path": "",
        }


# ── Internal helpers ──────────────────────────────────────────────────────


def _get_run_handle(store: RunStore, engagement_id: Any) -> RunHandle | None:
    """Retrieve a RunHandle from the store for the given engagement id.

    Returns None if the engagement has no store entry.
    """
    from uuid import UUID

    if isinstance(engagement_id, str):
        engagement_id = UUID(engagement_id)
    if not store.has_snapshot(engagement_id):
        return None

    # Reconstruct the snapshot from the lock file
    lock_path = store._engagement_path(engagement_id) / "engagement.lock.yaml"
    if not lock_path.is_file():
        return None

    import json

    try:
        data = json.loads(lock_path.read_text())
        snapshot = EngagementSnapshot.model_validate(data)
    except (json.JSONDecodeError, Exception):
        return None

    return RunHandle(
        engagement_id=engagement_id,
        path=store._engagement_path(engagement_id),
        snapshot=snapshot,
    )


def _load_engagement_policy(
    snapshot: EngagementSnapshot,
) -> EffectivePolicy:
    """Load or construct an effective policy for this engagement.

    For the vertical slice, build a minimal permissive policy from
    the snapshot's engagement constraints so that Planner validation
    (capability checks) can exercise real rejection paths.
    """
    from ariadne.core.policy import CapabilityRule

    return EffectivePolicy(
        name=f"engagement-{snapshot.engagement_id}",
        version=1,
        capabilities={
            "preflight.check": CapabilityRule(allowed=True),
            "scan.tcp": CapabilityRule(allowed=True),
            "scan.port": CapabilityRule(allowed=True),
            "service.discovery": CapabilityRule(allowed=True),
            "service.enum": CapabilityRule(allowed=True),
            "service.routing": CapabilityRule(allowed=True),
            "research.vulnerability": CapabilityRule(allowed=True),
            "exploit.validation": CapabilityRule(allowed=True),
            "foothold.confirm": CapabilityRule(allowed=True),
            "postex.enum": CapabilityRule(allowed=True),
            "privesc.enum": CapabilityRule(allowed=True),
            "objective.check": CapabilityRule(allowed=True),
            "cleanup.execute": CapabilityRule(allowed=True),
            "report.render": CapabilityRule(allowed=True),
            "exploit": CapabilityRule(allowed=False),
            "resource.stress": CapabilityRule(allowed=False),
            "persistence": CapabilityRule(allowed=False),
            "lateral_movement": CapabilityRule(allowed=False),
        },
        source_digests=(),
    )
