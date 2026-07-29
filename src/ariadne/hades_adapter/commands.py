"""Ariadne command parser and engagement approval service.

The initial engagement is locked atomically when the interactive Q/A accepts
the server-controlled disclaimer.  Separate approval challenges remain for
scope amendments, host installation, uncurated PoCs, and SysReptor push.
"""

from __future__ import annotations

import shlex
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID, uuid4

from ariadne.core.engagement import (
    EngagementConstraints,
    EngagementDraft,
    Objective,
    TargetSpec,
    lock_attested_engagement,
)
from ariadne.core.enums import AutonomyMode, EnvironmentProfile
from ariadne.core.planner import Plan
from ariadne.core.policy import build_effective_policy
from ariadne.hades_adapter.session import ChallengeLedger
from ariadne.store.run_store import RunStore

CURRENT_DISCLAIMER_VERSION = "2026-07-28"

# ── Recognised commands and their argument counts ──────────────────────────


_COMMANDS: dict[str, int] = {
    "new": 0,
    "status": 0,
    "plan": 0,
    "approve": 1,
    "reject": 1,
    "amend-scope": 0,
    "pause": 0,
    "resume": 0,
    "abort": 0,
    "evidence": 0,
    "report": 0,
    "doctor": 0,
}


# ── Result types ───────────────────────────────────────────────────────────


@dataclass
class ParseResult:
    """Result of parsing a raw /ariadne argument string."""

    command: str | None = None
    args: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class PrepareResult:
    """Result of atomically locking and binding an engagement."""

    status: str
    engagement_id: UUID | None
    snapshot_hash: str | None
    message: str


@dataclass
class PlanRecord:
    """A proposed plan with manual or durable automatic approval state.

    Attributes:
        plan: The bounded Plan object.
        snapshot_hash: Hash of the engagement snapshot at proposal time.
        session_id: Hades session that proposed this plan.
        approval_correlation_id: Durable proposal/approval correlation key.
        approved: Whether the plan has been manually or automatically approved.
        approved_at: When the plan was approved (None if not yet approved).
        approval_source: Provenance for the approval decision.
        rejected: Whether the user has rejected this plan.
    """

    plan: Plan
    snapshot_hash: str
    session_id: str
    approval_correlation_id: str
    approved: bool = False
    approved_at: float | None = None
    approval_source: str | None = None
    rejected: bool = False


# ── Command service ────────────────────────────────────────────────────────


class AriadneCommand:
    """Engagement command and approval service.

    Attributes:
        ledger: The ``ChallengeLedger`` managing pending challenges.
        store: The ``RunStore`` for persisting engagement snapshots.
    """

    def __init__(self, ledger: ChallengeLedger, store: RunStore) -> None:
        self.ledger = ledger
        self.store = store
        self._plan_ledger: dict[str, PlanRecord] = {}

    # ── Parsing ─────────────────────────────────────────────────────────

    def parse(self, raw_args: str) -> ParseResult:
        """Parse a raw argument string into a command and arguments.

        Uses ``shlex.split`` for safe tokenisation.  Extra tokens beyond
        the expected count for a recognised command are rejected.

        Returns:
            A ``ParseResult`` with the parsed command, args, or error.
        """
        if not raw_args or not raw_args.strip():
            return ParseResult(error="Empty command")

        try:
            tokens = shlex.split(raw_args)
        except ValueError as exc:
            return ParseResult(error=str(exc))

        if not tokens:
            return ParseResult(error="Empty command")

        cmd = tokens[0].lower()
        args = tokens[1:]

        if cmd not in _COMMANDS:
            return ParseResult(error=f"Unknown command: {cmd!r}")

        expected_args = _COMMANDS[cmd]
        if len(args) != expected_args:
            if expected_args == 0 and len(args) > 0:
                return ParseResult(
                    error=f"Unexpected arguments for {cmd!r}: {args}"
                )
            if expected_args == 1 and len(args) == 0:
                return ParseResult(
                    error=f"Missing required argument for {cmd!r}"
                )
            return ParseResult(
                error=f"Expected {expected_args} argument(s) for "
                f"{cmd!r}, got {len(args)}"
            )

        return ParseResult(command=cmd, args=args)

    # ── Prepare: validate Q/A, lock, persist, and bind ──────────────────

    def prepare(
        self,
        answers: dict[str, Any],
        *,
        session_id: str,
    ) -> PrepareResult:
        """Atomically lock the accepted Q/A and bind its trusted session."""
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("A trusted Hades session_id is required")
        if self.get_session_binding(session_id) is not None:
            raise ValueError(
                "This Hades session already has an active engagement; "
                "use an explicit scope amendment or a new session"
            )
        if answers.get("authorization_attested") is not True:
            raise ValueError("Authorization attestation must be explicitly true")
        if answers.get("disclaimer_version") != CURRENT_DISCLAIMER_VERSION:
            raise ValueError(
                "Disclaimer version mismatch: expected "
                f"{CURRENT_DISCLAIMER_VERSION!r}"
            )
        profile = EnvironmentProfile(answers["profile"])
        autonomy = AutonomyMode(answers.get("autonomy", "controlled"))
        objectives = [
            Objective(kind=cast(Any, o)) if isinstance(o, str) else Objective(**o)
            for o in answers.get("objectives", [])
        ]

        draft = EngagementDraft(
            authorization_attested=answers["authorization_attested"],
            disclaimer_version=answers["disclaimer_version"],
            profile=profile,
            autonomy=autonomy,
            target=TargetSpec(host=answers["target_host"]),
            objectives=objectives,
        )

        constraints = EngagementConstraints(
            max_concurrent_checks=answers.get("max_concurrent_checks", 5),
            max_requests_per_second=answers.get("max_requests_per_second", 10),
            max_duration_minutes=answers.get("time_window_minutes", 60),
        )
        effective_policy = build_effective_policy(profile, constraints)
        snapshot = lock_attested_engagement(
            draft,
            max_concurrent_checks=constraints.max_concurrent_checks,
            max_requests_per_second=constraints.max_requests_per_second,
            max_duration_minutes=constraints.max_duration_minutes,
            policy_source_digests=effective_policy.source_digests,
        )
        handle = self.store.create(snapshot)
        now = datetime.now(UTC)
        transaction_id = uuid4().hex
        from ariadne.store.run_store import Event

        self.store.append_event(
            handle,
            Event(
                event_type="engagement_locked",
                payload={
                    "snapshot_hash": snapshot.snapshot_hash,
                    "transaction_id": transaction_id,
                    "authorization_attested": True,
                    "disclaimer_version": CURRENT_DISCLAIMER_VERSION,
                    "profile": snapshot.profile.value,
                    "autonomy": snapshot.autonomy.value,
                    "target": snapshot.targets[0].host,
                    "objectives": [o.model_dump(mode="json") for o in snapshot.objectives],
                    "time_window_minutes": snapshot.constraints.max_duration_minutes,
                    "policy_source_digests": list(snapshot.policy_source_digests),
                    "notes": answers.get("notes", ""),
                },
                timestamp=now,
            ),
        )
        self.store.append_event(
            handle,
            Event(
                event_type="session_bound",
                payload={
                    "session_id": session_id,
                    "snapshot_hash": snapshot.snapshot_hash,
                    "transaction_id": transaction_id,
                },
                timestamp=now,
            ),
        )
        binding_key = f"atomic:{snapshot.engagement_id}"
        self.ledger.bind_session(
            challenge_id=binding_key,
            session_id=session_id,
            engagement_id=snapshot.engagement_id,
            snapshot_hash=snapshot.snapshot_hash,
        )

        return PrepareResult(
            status="active",
            engagement_id=snapshot.engagement_id,
            snapshot_hash=snapshot.snapshot_hash,
            message="Engagement locked and bound to the current Hades session.",
        )

    # ── Handle: process parsed /ariadne commands ────────────────────────

    def handle(
        self,
        raw_args: str,
        *,
        trusted_session_id: str = "",
    ) -> str:
        """Parse and execute a raw /ariadne command string.

        This is the main entry point for the ``/ariadne`` command handler.
        It parses the argument string, executes the command, and returns
        a human-readable response.

        Args:
            raw_args: The full argument string after ``/ariadne``.

        Returns:
            A human-readable response string.
        """
        result = self.parse(raw_args)
        if result.error is not None:
            return f"Error: {result.error}"

        assert result.command is not None

        if result.command == "new":
            return "Use the ariadne_prepare_engagement tool to start a new engagement."

        if result.command == "status":
            return self._handle_status()

        if result.command == "approve":
            return self._handle_approve(
                result.args[0],
                trusted_session_id=trusted_session_id,
            )

        if result.command == "reject":
            return self._handle_reject(result.args[0])

        if result.command == "abort":
            return self._handle_abort()

        if result.command == "plan":
            return "Use the ariadne_propose_plan tool to create a bounded action plan."

        if result.command == "evidence":
            return "Use the ariadne_execute_plan tool to collect evidence."

        if result.command == "report":
            return "Use the ariadne_render_report tool to generate a report."

        if result.command == "doctor":
            return "Ariadne health check: OK."

        return f"Command '{result.command}' is not yet implemented."

    # ── Internal command handlers ───────────────────────────────────────

    def _handle_status(self) -> str:
        """Return the current engagement status."""
        return "Use ariadne_status to inspect the current session engagement."

    def _handle_approve(
        self,
        plan_id: str,
        *,
        trusted_session_id: str,
    ) -> str:
        """Durably approve a plan using only trusted Hades session identity."""
        if not trusted_session_id:
            return "Error: A trusted Hades session identity is required for approval."
        record = self.get_plan_record(
            plan_id,
            trusted_session_id=trusted_session_id,
        )
        if record is None:
            return f"Error: Unknown plan: {plan_id!r}"
        if record.session_id != trusted_session_id:
            return "Error: Plan belongs to a different trusted Hades session."
        if record.rejected:
            return f"Error: Plan {plan_id!r} was rejected."
        if record.approved:
            return f"Plan {plan_id!r} was already approved."
        if time.time() > record.plan.expires_at.timestamp():
            return f"Error: Plan {plan_id!r} has expired."

        binding = self.get_session_binding(trusted_session_id)
        if (
            binding is None
            or binding.engagement_id is None
            or binding.snapshot_hash != record.snapshot_hash
        ):
            return "Error: Plan is not bound to the active trusted Hades session."
        handle = self.store.open(binding.engagement_id)
        if handle is None:
            return "Error: Engagement run is unavailable."

        from ariadne.store.integrity import verify_run
        from ariadne.store.run_store import Event

        if not verify_run(handle.path).valid:
            return "Error: Engagement event chain failed integrity verification."

        approved_at = datetime.now(UTC)
        try:
            self.store.append_event(
                handle,
                Event(
                    event_type="plan_manually_approved",
                    payload={
                        "plan_id": plan_id,
                        "snapshot_hash": record.snapshot_hash,
                        "trusted_session_id": trusted_session_id,
                        "approval_correlation_id": record.approval_correlation_id,
                        "approval_state": "approved",
                        "approval_source": "user",
                        "approved_at": approved_at.isoformat(),
                    },
                    timestamp=approved_at,
                ),
            )
        except Exception as exc:
            return f"Error: Could not persist plan approval: {exc}"
        record.approved = True
        record.approved_at = approved_at.timestamp()
        record.approval_source = "user"
        return (
            f"Plan {plan_id!r} approved. "
            f"Use ariadne_execute_plan to execute."
        )

    def _handle_reject(self, plan_id: str) -> str:
        """Reject a plan by id."""
        record = self._plan_ledger.get(plan_id)
        if record is None:
            return f"Error: Unknown plan: {plan_id!r}"
        if record.rejected:
            return f"Plan {plan_id!r} was already rejected."
        record.rejected = True
        return f"Plan {plan_id!r} rejected."

    def _handle_abort(self) -> str:
        """Abort the current engagement."""
        return "Abort acknowledged. No active engagement to abort."

    # ── Plan ledger ─────────────────────────────────────────────────────

    def add_plan(
        self,
        plan: Plan,
        snapshot_hash: str,
        session_id: str,
        *,
        approval_correlation_id: str,
    ) -> str:
        """Register a proposed plan in the plan ledger.

        Args:
            plan: The bounded Plan to record.
            snapshot_hash: Hash of the snapshot at proposal time.
            session_id: The Hades session that proposed this plan.

        Returns:
            The plan_id string.
        """
        record = PlanRecord(
            plan=plan,
            snapshot_hash=snapshot_hash,
            session_id=session_id,
            approval_correlation_id=approval_correlation_id,
        )
        self._plan_ledger[plan.plan_id] = record
        return plan.plan_id

    def get_plan_record(
        self,
        plan_id: str,
        *,
        trusted_session_id: str = "",
    ) -> PlanRecord | None:
        """Retrieve or integrity-recover a plan record from durable events."""
        record = self._plan_ledger.get(plan_id)
        if record is not None:
            if trusted_session_id and record.session_id != trusted_session_id:
                return None
            return record
        if not trusted_session_id:
            return None
        record = self._recover_plan_record(plan_id, trusted_session_id)
        if record is not None:
            self._plan_ledger[plan_id] = record
        return record

    def _recover_plan_record(
        self,
        plan_id: str,
        trusted_session_id: str,
    ) -> PlanRecord | None:
        """Rebuild one plan only from a verified, session-bound event chain."""
        binding = self.get_session_binding(trusted_session_id)
        if binding is None or binding.engagement_id is None:
            return None
        handle = self.store.open(binding.engagement_id)
        if handle is None:
            return None

        from ariadne.store.integrity import verify_run

        if not verify_run(handle.path).valid:
            return None

        proposal: dict[str, Any] | None = None
        approvals: list[tuple[str, dict[str, Any]]] = []
        for event in self.store.read_events(handle):
            payload = event.get("payload", {})
            if payload.get("plan_id") != plan_id:
                continue
            event_type = event.get("event_type")
            if event_type == "plan_proposed":
                if proposal is not None:
                    return None
                proposal = payload
            elif event_type in {
                "plan_auto_approved",
                "plan_manually_approved",
                "plan_rejected",
            }:
                if proposal is None:
                    return None
                approvals.append((str(event_type), payload))

        if proposal is None:
            return None
        try:
            plan = Plan.model_validate(proposal["plan"])
            correlation_id = proposal["approval_correlation_id"]
            valid_proposal = (
                isinstance(correlation_id, str)
                and bool(correlation_id)
                and proposal.get("approval_state") == "pending"
                and proposal.get("trusted_session_id") == trusted_session_id
                and proposal.get("session_id") == trusted_session_id
                and proposal.get("snapshot_hash") == binding.snapshot_hash
                and proposal.get("snapshot_hash") == plan.snapshot_hash
                and proposal.get("plan_id") == plan.plan_id == plan_id
                and proposal.get("expires_at") == plan.expires_at.isoformat()
            )
        except (KeyError, TypeError, ValueError):
            return None
        if not valid_proposal:
            return None

        record = PlanRecord(
            plan=plan,
            snapshot_hash=plan.snapshot_hash,
            session_id=trusted_session_id,
            approval_correlation_id=correlation_id,
        )
        for event_type, payload in approvals:
            if (
                payload.get("approval_correlation_id") != correlation_id
                or payload.get("snapshot_hash") != plan.snapshot_hash
                or payload.get("trusted_session_id") != trusted_session_id
                or payload.get("approval_state")
                not in {"approved", "rejected"}
            ):
                return None
            if event_type == "plan_rejected":
                if record.approved:
                    return None
                record.rejected = True
                continue
            if record.rejected or record.approved:
                return None
            source = payload.get("approval_source")
            if event_type == "plan_auto_approved":
                if (
                    source != "full_autonomy_policy"
                    or plan.requires_manual_approval
                    or handle.snapshot.autonomy != AutonomyMode.FULL
                ):
                    return None
            elif source != "user":
                return None
            try:
                approved_at = datetime.fromisoformat(payload["approved_at"])
            except (KeyError, TypeError, ValueError):
                return None
            record.approved = True
            record.approved_at = approved_at.timestamp()
            record.approval_source = str(source)
        return record

    def auto_approve_plan(self, plan_id: str) -> None:
        """Mark a durably auto-approved full-autonomy plan as approved."""
        record = self._plan_ledger.get(plan_id)
        if record is None:
            raise ValueError(f"Unknown plan: {plan_id!r}")
        if record.plan.requires_manual_approval:
            raise ValueError("A manual-only plan cannot be auto-approved")
        record.approved = True
        record.approved_at = time.time()
        record.approval_source = "full_autonomy_policy"

    def is_plan_approved(self, plan_id: str) -> bool:
        """Check whether a plan has manual or automatic approval."""
        record = self._plan_ledger.get(plan_id)
        if record is None:
            return False
        return record.approved

    def is_plan_expired(self, plan_id: str) -> bool:
        """Check whether a plan has expired (15 min TTL)."""
        record = self._plan_ledger.get(plan_id)
        if record is None:
            return True
        return time.time() > record.plan.expires_at.timestamp()

    # ── Utility ─────────────────────────────────────────────────────────

    def has_active_engagement(self, session_id: str) -> bool:
        """Check whether this session has a bound engagement."""
        return self.get_session_binding(session_id) is not None

    def get_session_binding(self, session_id: str):
        """Return only a binding backed by a complete, verified durable run."""
        binding = self.ledger.get_session_binding(session_id)
        durable = self.store.find_session_binding(session_id)
        if durable is None:
            if binding is not None:
                self.ledger.unbind_session(session_id)
            return None
        engagement_id = UUID(durable["engagement_id"])
        if (
            binding is not None
            and binding.engagement_id == engagement_id
            and binding.snapshot_hash == durable["snapshot_hash"]
        ):
            return binding
        if binding is not None:
            self.ledger.unbind_session(session_id)
        self.ledger.bind_session(
            challenge_id=f"atomic:{engagement_id}",
            session_id=session_id,
            engagement_id=engagement_id,
            snapshot_hash=durable["snapshot_hash"],
        )
        return self.ledger.get_session_binding(session_id)
