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
from threading import Lock, RLock
from typing import Any, cast
from uuid import UUID, uuid4

from ariadne.core.engagement import (
    EngagementConstraints,
    EngagementDraft,
    Objective,
    TargetSpec,
    amend_engagement,
    intensity_default_limits,
    lock_attested_engagement,
)
from ariadne.core.enums import AutonomyMode, EnvironmentProfile
from ariadne.core.planner import Plan
from ariadne.core.policy import build_effective_policy
from ariadne.hades_adapter.session import ChallengeLedger
from ariadne.store.run_store import RunStore

CURRENT_DISCLAIMER_VERSION = "2026-07-28"
_DECISION_CHANNELS = frozenset({"hades_elicitation", "slash_command"})
_REJECTION_REASONS = frozenset({
    "explicit_user_rejection",
    "user_cancelled",
    "user_declined",
})

# ── Recognised commands and their argument counts ──────────────────────────


_COMMANDS: dict[str, int] = {
    "new": 0,
    "status": 0,
    "plan": 0,
    "run": 0,
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
        claimed: Whether execution has been durably claimed.
        claimed_at: When the execution claim was persisted.
        executed: Whether a verified legacy/current execution event exists.
    """

    plan: Plan
    snapshot_hash: str
    session_id: str
    approval_correlation_id: str
    approved: bool = False
    approved_at: float | None = None
    approval_source: str | None = None
    rejected: bool = False
    claimed: bool = False
    claimed_at: float | None = None
    executed: bool = False


@dataclass(frozen=True)
class PlanClaimResult:
    """Outcome of an atomic durable execution claim."""

    claimed: bool
    message: str
    record: PlanRecord | None = None


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
        self._plan_locks: dict[str, RLock] = {}
        self._plan_locks_guard = Lock()

    def _plan_lock(self, plan_id: str) -> RLock:
        """Return the process-local serialization lock for one plan."""
        with self._plan_locks_guard:
            lock = self._plan_locks.get(plan_id)
            if lock is None:
                lock = RLock()
                self._plan_locks[plan_id] = lock
            return lock

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
        trusted_confirmation_digest: str = "",
    ) -> PrepareResult:
        """Atomically lock the accepted Q/A and bind its trusted session."""
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("A trusted Hades session_id is required")
        if (
            len(trusted_confirmation_digest) != 64
            or any(char not in "0123456789abcdef" for char in trusted_confirmation_digest)
        ):
            raise ValueError("A trusted Hades contract confirmation is required")
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
            intensity=answers.get("intensity", "normal"),
            exclusions=tuple(answers.get("exclusions", ())),
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
                    "intensity": snapshot.intensity,
                    "exclusions": list(snapshot.exclusions),
                    "time_window_minutes": snapshot.constraints.max_duration_minutes,
                    "policy_source_digests": list(snapshot.policy_source_digests),
                    "trusted_confirmation_digest": trusted_confirmation_digest,
                    "confirmation_surface": "hades_elicitation",
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

    def amend(
        self,
        changes: dict[str, Any],
        *,
        session_id: str,
        trusted_confirmation_digest: str,
        expected_snapshot_hash: str,
        expected_revision: int,
    ) -> PrepareResult:
        """Persist a linked contract version after trusted Hades consent."""
        if (
            len(trusted_confirmation_digest) != 64
            or any(char not in "0123456789abcdef" for char in trusted_confirmation_digest)
        ):
            raise ValueError("A trusted Hades amendment confirmation is required")
        binding = self.get_session_binding(session_id)
        if binding is None or binding.engagement_id is None:
            raise ValueError("No active engagement is bound to this Hades session")
        handle = self.store.open(binding.engagement_id)
        if handle is None or handle.snapshot.snapshot_hash != binding.snapshot_hash:
            raise ValueError("Active engagement snapshot is unavailable or stale")
        if (
            handle.snapshot.snapshot_hash != expected_snapshot_hash
            or handle.snapshot.revision != expected_revision
        ):
            raise ValueError(
                "Active engagement changed after amendment confirmation"
            )

        targets = list(handle.snapshot.targets)
        for raw_target in changes.get("add_targets", ()):
            target = TargetSpec(host=raw_target)
            if target not in targets:
                targets.append(target)
        raw_objectives = changes.get("objectives")
        objectives = (
            handle.snapshot.objectives
            if raw_objectives is None
            else tuple(
                Objective(kind=value)
                if isinstance(value, str)
                else Objective(**value)
                for value in raw_objectives
            )
        )
        intensity = changes.get("intensity")
        constraints = handle.snapshot.constraints
        if intensity is not None:
            rate, concurrency = intensity_default_limits(intensity)
            constraints = constraints.model_copy(
                update={
                    "max_requests_per_second": rate,
                    "max_concurrent_checks": concurrency,
                }
            )
        amended = amend_engagement(
            handle.snapshot,
            targets=tuple(targets),
            objectives=objectives,
            intensity=intensity,
            exclusions=(
                None
                if changes.get("exclusions") is None
                else tuple(changes["exclusions"])
            ),
            constraints=constraints,
        )
        amended_handle = self.store.amend_snapshot(handle, amended)
        transaction_id = uuid4().hex
        now = datetime.now(UTC)
        from ariadne.store.run_store import Event

        try:
            self.store.append_event(
                amended_handle,
                Event(
                    event_type="engagement_amended",
                    payload={
                        "snapshot_hash": amended.snapshot_hash,
                        "previous_snapshot_hash": amended.previous_snapshot_hash,
                        "revision": amended.revision,
                        "transaction_id": transaction_id,
                        "trusted_confirmation_digest": trusted_confirmation_digest,
                        "candidate_id": changes.get("candidate_id", ""),
                        "reason": changes["reason"],
                        "add_targets": [
                            target.host
                            for target in amended.targets
                            if target not in handle.snapshot.targets
                        ],
                        "intensity": amended.intensity,
                        "exclusions": list(amended.exclusions),
                    },
                    timestamp=now,
                ),
            )
            self.store.append_event(
                amended_handle,
                Event(
                    event_type="session_rebound",
                    payload={
                        "session_id": session_id,
                        "snapshot_hash": amended.snapshot_hash,
                        "transaction_id": transaction_id,
                    },
                    timestamp=now,
                ),
            )
        except BaseException:
            self.store.rollback_amendment(amended_handle, handle.snapshot)
            raise
        self.ledger.unbind_session(session_id)
        self.ledger.bind_session(
            challenge_id=f"amendment:{amended.snapshot_hash}",
            session_id=session_id,
            engagement_id=amended.engagement_id,
            snapshot_hash=amended.snapshot_hash,
        )
        return PrepareResult(
            status="active",
            engagement_id=amended.engagement_id,
            snapshot_hash=amended.snapshot_hash,
            message=f"Engagement amended to immutable revision {amended.revision}.",
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
            return self._handle_reject(
                result.args[0],
                trusted_session_id=trusted_session_id,
            )

        if result.command == "abort":
            return self._handle_abort()

        if result.command == "plan":
            return "Use the ariadne_propose_plan tool to create a bounded action plan."

        if result.command == "run":
            return "Use ariadne_run to advance autonomously until complete or blocked."

        if result.command == "amend-scope":
            return (
                "Use ariadne_amend_engagement; Hades will display one targeted "
                "amendment confirmation."
            )

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
        """CLI fallback for a durable trusted-session approval."""
        return self.approve_plan(
            plan_id,
            trusted_session_id=trusted_session_id,
            decision_channel="slash_command",
        )

    def approve_plan(
        self,
        plan_id: str,
        *,
        trusted_session_id: str,
        decision_channel: str,
    ) -> str:
        """Persist a pending-to-approved transition before mutating memory."""
        if decision_channel not in _DECISION_CHANNELS:
            return "Error: Untrusted plan approval decision channel."
        with self._plan_lock(plan_id):
            return self._approve_plan_locked(
                plan_id,
                trusted_session_id=trusted_session_id,
                decision_channel=decision_channel,
            )

    def _approve_plan_locked(
        self,
        plan_id: str,
        *,
        trusted_session_id: str,
        decision_channel: str,
    ) -> str:
        if not trusted_session_id:
            return "Error: A trusted Hades session identity is required for approval."
        record = self._recover_plan_record(plan_id, trusted_session_id)
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
                        "decision_channel": decision_channel,
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
        self._plan_ledger[plan_id] = record
        return (
            f"Plan {plan_id!r} approved. "
            f"Use ariadne_execute_plan to execute."
        )

    def _handle_reject(
        self,
        plan_id: str,
        *,
        trusted_session_id: str,
    ) -> str:
        """CLI fallback for durable rejection/revocation."""
        return self.reject_plan(
            plan_id,
            trusted_session_id=trusted_session_id,
            decision_channel="slash_command",
            reason="explicit_user_rejection",
        )

    def reject_plan(
        self,
        plan_id: str,
        *,
        trusted_session_id: str,
        decision_channel: str,
        reason: str,
    ) -> str:
        """Durably reject or revoke a plan using trusted Hades identity."""
        if (
            decision_channel not in _DECISION_CHANNELS
            or reason not in _REJECTION_REASONS
        ):
            return "Error: Untrusted plan rejection decision."
        with self._plan_lock(plan_id):
            return self._reject_plan_locked(
                plan_id,
                trusted_session_id=trusted_session_id,
                decision_channel=decision_channel,
                reason=reason,
            )

    def _reject_plan_locked(
        self,
        plan_id: str,
        *,
        trusted_session_id: str,
        decision_channel: str,
        reason: str,
    ) -> str:
        if not trusted_session_id:
            return "Error: A trusted Hades session identity is required for rejection."
        record = self._recover_plan_record(plan_id, trusted_session_id)
        if record is None:
            return f"Error: Unknown plan: {plan_id!r}"
        if record.rejected:
            return f"Plan {plan_id!r} was already rejected."
        if record.executed:
            return f"Error: Plan {plan_id!r} was already executed."
        if record.claimed:
            return f"Error: Plan {plan_id!r} is already execution-claimed."

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
        if any(
            event.get("event_type") == "plan_executed"
            and event.get("payload", {}).get("plan_id") == plan_id
            for event in self.store.read_events(handle)
        ):
            return "Error: An executed plan can no longer be revoked."
        rejected_at = datetime.now(UTC)
        try:
            self.store.append_event(
                handle,
                Event(
                    event_type="plan_rejected",
                    payload={
                        "plan_id": plan_id,
                        "snapshot_hash": record.snapshot_hash,
                        "trusted_session_id": trusted_session_id,
                        "approval_correlation_id": record.approval_correlation_id,
                        "approval_state": "rejected",
                        "approval_source": "user",
                        "decision_channel": decision_channel,
                        "reason": reason,
                        "rejected_at": rejected_at.isoformat(),
                    },
                    timestamp=rejected_at,
                ),
            )
        except Exception as exc:
            return f"Error: Could not persist plan rejection: {exc}"
        record.approved = False
        record.rejected = True
        self._plan_ledger[plan_id] = record
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
        legacy_execution_times: list[datetime] = []
        for event in self.store.read_events(handle):
            payload = event.get("payload", {})
            if payload.get("plan_id") != plan_id:
                continue
            event_type = event.get("event_type")
            if event_type == "plan_executed":
                try:
                    legacy_execution_times.append(
                        datetime.fromisoformat(event["timestamp"])
                    )
                except (KeyError, TypeError, ValueError):
                    return None
                continue
            if event_type == "plan_proposed":
                if proposal is not None:
                    return None
                proposal = payload
            elif event_type in {
                "plan_auto_approved",
                "plan_manually_approved",
                "plan_rejected",
                "plan_execution_claimed",
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
            ):
                return None
            if event_type == "plan_execution_claimed":
                if (
                    record.claimed
                    or record.rejected
                    or not record.approved
                    or payload.get("execution_state") != "claimed"
                    or tuple(payload.get("policy_source_digests", ()))
                    != handle.snapshot.policy_source_digests
                ):
                    return None
                try:
                    claimed_at = datetime.fromisoformat(payload["claimed_at"])
                except (KeyError, TypeError, ValueError):
                    return None
                record.claimed = True
                record.claimed_at = claimed_at.timestamp()
                continue
            if payload.get("approval_state") not in {"approved", "rejected"}:
                return None
            if event_type == "plan_rejected":
                if record.rejected or record.claimed:
                    return None
                try:
                    datetime.fromisoformat(payload["rejected_at"])
                except (KeyError, TypeError, ValueError):
                    return None
                if (
                    payload.get("approval_source") != "user"
                    or payload.get("decision_channel") not in _DECISION_CHANNELS
                    or payload.get("reason") not in _REJECTION_REASONS
                ):
                    return None
                record.approved = False
                record.rejected = True
                continue
            if record.rejected or record.approved:
                return None
            source = payload.get("approval_source")
            if event_type == "plan_auto_approved":
                valid_source = source == "curated_in_policy" or (
                    source == "full_autonomy_policy"
                    and handle.snapshot.autonomy == AutonomyMode.FULL
                )
                if (
                    not valid_source
                    or plan.requires_manual_approval
                    or plan.manual_capabilities
                ):
                    return None
            elif (
                source != "user"
                or payload.get("decision_channel")
                not in {None, *_DECISION_CHANNELS}
            ):
                return None
            try:
                approved_at = datetime.fromisoformat(payload["approved_at"])
            except (KeyError, TypeError, ValueError):
                return None
            record.approved = True
            record.approved_at = approved_at.timestamp()
            record.approval_source = str(source)
        if legacy_execution_times:
            record.executed = True
            record.claimed = True
            record.claimed_at = max(
                timestamp.timestamp()
                for timestamp in legacy_execution_times
            )
        return record

    def claim_plan_execution(
        self,
        plan_id: str,
        *,
        trusted_session_id: str,
    ) -> PlanClaimResult:
        """Atomically claim one approved plan before adapter planning.

        Rejection and execution use the same per-plan lock.  Every decision is
        reconstructed from the verified durable chain while holding the lock;
        the in-memory cache is never authoritative for this transition.

        The lock serializes the single Hades service process. The durable claim
        prevents restart replay; multi-process writers would additionally need
        a RunStore-level cross-process compare-and-swap or file lock.
        """
        if not trusted_session_id:
            return PlanClaimResult(
                claimed=False,
                message="Trusted Hades session identity is required.",
            )
        with self._plan_lock(plan_id):
            record = self._recover_plan_record(plan_id, trusted_session_id)
            if record is None:
                return PlanClaimResult(
                    claimed=False,
                    message="Plan is missing or its durable chain is invalid.",
                )
            if record.executed:
                return PlanClaimResult(
                    claimed=False,
                    message="Plan was already executed.",
                    record=record,
                )
            if record.rejected:
                return PlanClaimResult(
                    claimed=False,
                    message="Plan was rejected or revoked.",
                    record=record,
                )
            if record.claimed:
                return PlanClaimResult(
                    claimed=False,
                    message="Plan is already execution-claimed.",
                    record=record,
                )
            if not record.approved:
                return PlanClaimResult(
                    claimed=False,
                    message="Plan is not durably approved.",
                    record=record,
                )
            if time.time() > record.plan.expires_at.timestamp():
                return PlanClaimResult(
                    claimed=False,
                    message="Plan has expired.",
                    record=record,
                )

            binding = self.get_session_binding(trusted_session_id)
            if (
                binding is None
                or binding.engagement_id is None
                or binding.snapshot_hash != record.snapshot_hash
            ):
                return PlanClaimResult(
                    claimed=False,
                    message="Plan is not bound to the active trusted session.",
                )
            handle = self.store.open(binding.engagement_id)
            if handle is None:
                return PlanClaimResult(
                    claimed=False,
                    message="Engagement run is unavailable.",
                )

            from ariadne.core.engagement import calculate_snapshot_hash
            from ariadne.store.integrity import verify_run
            from ariadne.store.run_store import Event

            snapshot = handle.snapshot
            if (
                not verify_run(handle.path).valid
                or calculate_snapshot_hash(snapshot) != snapshot.snapshot_hash
                or snapshot.snapshot_hash != record.snapshot_hash
            ):
                return PlanClaimResult(
                    claimed=False,
                    message="Snapshot or event-chain integrity check failed.",
                )
            try:
                policy = build_effective_policy(
                    snapshot.profile,
                    snapshot.constraints,
                )
            except Exception:
                return PlanClaimResult(
                    claimed=False,
                    message="Effective policy could not be rebuilt.",
                )
            if policy.source_digests != snapshot.policy_source_digests:
                return PlanClaimResult(
                    claimed=False,
                    message="Policy provenance changed after approval.",
                )
            if any(
                capability not in policy.capabilities
                or not policy.capabilities[capability].allowed
                for capability in record.plan.capabilities
            ):
                return PlanClaimResult(
                    claimed=False,
                    message="Plan capabilities are no longer authorized.",
                )

            claimed_at = datetime.now(UTC)
            try:
                self.store.append_event(
                    handle,
                    Event(
                        event_type="plan_execution_claimed",
                        payload={
                            "plan_id": plan_id,
                            "snapshot_hash": record.snapshot_hash,
                            "trusted_session_id": trusted_session_id,
                            "approval_correlation_id": (
                                record.approval_correlation_id
                            ),
                            "execution_state": "claimed",
                            "claimed_at": claimed_at.isoformat(),
                            "policy_source_digests": list(
                                policy.source_digests
                            ),
                        },
                        timestamp=claimed_at,
                    ),
                )
            except Exception as exc:
                return PlanClaimResult(
                    claimed=False,
                    message=f"Could not persist execution claim: {exc}",
                )
            record.claimed = True
            record.claimed_at = claimed_at.timestamp()
            self._plan_ledger[plan_id] = record
            return PlanClaimResult(
                claimed=True,
                message="Plan execution claimed.",
                record=record,
            )

    def auto_approve_plan(self, plan_id: str) -> None:
        """Mark a durably auto-approved curated in-policy plan as approved."""
        record = self._plan_ledger.get(plan_id)
        if record is None:
            raise ValueError(f"Unknown plan: {plan_id!r}")
        if (
            record.plan.requires_manual_approval
            or record.plan.manual_capabilities
        ):
            raise ValueError("A manual-only plan cannot be auto-approved")
        record.approved = True
        record.approved_at = time.time()
        record.approval_source = "curated_in_policy"

    def is_plan_approved(self, plan_id: str) -> bool:
        """Check whether a plan has manual or automatic approval."""
        record = self._plan_ledger.get(plan_id)
        if record is None:
            return False
        return record.approved and not record.rejected

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
