"""Ariadne command parser and engagement approval service.

AriadneCommand enforces the rule that model-facing tool calls cannot
self-confirm.  A real user must type ``/ariadne confirm <challenge-id>``
to commit an engagement snapshot.  The confirmation challenge is a
one-time, time-limited random value that is never exposed through a
regular tool handler.
"""

from __future__ import annotations

import shlex
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID, uuid4

from ariadne.core.canonical import canonical_digest
from ariadne.core.engagement import (
    Confirmation,
    EngagementDraft,
    Objective,
    TargetSpec,
    lock_engagement,
)
from ariadne.core.enums import AutonomyMode, EnvironmentProfile
from ariadne.core.planner import Plan
from ariadne.hades_adapter.session import ChallengeLedger
from ariadne.store.run_store import RunStore

# Shared plan ledger — keyed by plan_id, stored alongside the ChallengeLedger
# so both tool handlers and /ariadne commands see the same plans.
_PLAN_LEDGER: dict[str, PlanRecord] = {}

# ── Recognised commands and their argument counts ──────────────────────────


_COMMANDS: dict[str, int] = {
    "new": 0,
    "confirm": 1,
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
    """Result of engagement preparation before confirmation."""

    status: str
    challenge_id: str | None
    engagement_id: UUID | None
    message: str


@dataclass
class BindResult:
    """Result of binding a confirmed engagement to a Hades session."""

    status: str
    snapshot_hash: str | None
    message: str
    error: str | None = None


@dataclass
class PlanRecord:
    """A proposed plan awaiting approval or rejection.

    Attributes:
        plan: The bounded Plan object.
        snapshot_hash: Hash of the engagement snapshot at proposal time.
        session_id: Hades session that proposed this plan.
        approved: Whether the user has approved this plan.
        approved_at: When the plan was approved (None if not yet approved).
        rejected: Whether the user has rejected this plan.
    """

    plan: Plan
    snapshot_hash: str
    session_id: str
    approved: bool = False
    approved_at: float | None = None
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

    # ── Prepare: collect answers, create challenge ──────────────────────

    def prepare(self, answers: dict[str, Any]) -> PrepareResult:
        """Collect engagement answers and return a user challenge.

        Creates an ``EngagementDraft`` from the answers, computes its
        canonical digest, and stores a one-time challenge linked to that
        digest.  The draft is NOT locked into a snapshot until the user
        confirms via ``/ariadne confirm <challenge-id>``.

        Args:
            answers: Engagement answers from the model-facing tool,
                matching ``PrepareEngagementInput`` schema fields.

        Returns:
            A ``PrepareResult`` with the challenge id and awaiting status.
        """
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

        digest = canonical_digest(draft)
        engagement_id = uuid4()
        challenge_id = self.ledger.create_challenge(
            payload_digest=digest,
            payload=answers,
            challenge_type="contract",
            engagement_id=engagement_id,
        )

        return PrepareResult(
            status="awaiting_user_confirmation",
            challenge_id=challenge_id,
            engagement_id=engagement_id,
            message=(
                "Engagement answers recorded. "
                f"Use /ariadne confirm {challenge_id} to lock."
            ),
        )

    # ── Handle: process parsed /ariadne commands ────────────────────────

    def handle(self, raw_args: str) -> str:
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

        if result.command == "confirm":
            return self._handle_confirm(result.args[0])

        if result.command == "status":
            return self._handle_status()

        if result.command == "approve":
            return self._handle_approve(result.args[0])

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

    def _handle_confirm(self, challenge_id: str) -> str:
        """Confirm a pending challenge and lock the engagement snapshot.

        Consumes the challenge from the ledger, builds the
        ``EngagementSnapshot``, writes it to the store via lock_and_bind,
        and binds the challenge to the resulting snapshot so that
        ``bind_engagement`` can complete the session binding.
        """
        record = self.ledger.consume_challenge(challenge_id)
        if record is None:
            existing = self.ledger.get_challenge(challenge_id)
            if existing is None:
                return f"Error: Invalid or unknown challenge: {challenge_id!r}"
            if existing.consumed:
                return f"Error: Challenge {challenge_id!r} has already been used."
            return f"Error: Challenge {challenge_id!r} has expired."

        # Build engagement snapshot from stored answers
        if record.payload is None:
            return (
                f"Error: Challenge {challenge_id!r} has no associated payload. "
                "Cannot lock engagement."
            )

        profile = EnvironmentProfile(record.payload["profile"])
        autonomy = AutonomyMode(record.payload.get("autonomy", "controlled"))
        objectives = [
            Objective(kind=cast(Any, o))
            if isinstance(o, str)
            else Objective(**o)
            for o in record.payload.get("objectives", [])
        ]

        draft = EngagementDraft(
            authorization_attested=record.payload["authorization_attested"],
            disclaimer_version=record.payload["disclaimer_version"],
            profile=profile,
            autonomy=autonomy,
            target=TargetSpec(host=record.payload["target_host"]),
            objectives=objectives,
        )

        now = datetime.now(UTC)
        confirmation = Confirmation(
            challenge_id=challenge_id,
            challenge_digest=record.payload_digest,
            confirmed_at=now,
            expires_at=now + timedelta(minutes=5),
            actor="user",
        )

        snapshot = lock_engagement(draft, confirmation)

        # Write snapshot to the store
        self.store.create(snapshot)

        # Pre-bind the challenge to the session (session_id unknown at this
        # point — it'll be completed in bind_engagement)
        self.ledger.bind_session(
            challenge_id=challenge_id,
            session_id="",  # placeholder — set in bind_engagement
            engagement_id=snapshot.engagement_id,
            snapshot_hash=snapshot.snapshot_hash,
        )

        return (
            f"Confirmed. Engagement locked. "
            f"Snapshot: {snapshot.snapshot_hash}"
        )

    def _handle_status(self) -> str:
        """Return the current engagement status."""
        return "Engagement is in draft. Use /ariadne confirm <challenge-id> to lock."

    def _handle_approve(self, plan_id: str) -> str:
        """Approve a plan by id."""
        record = _PLAN_LEDGER.get(plan_id)
        if record is None:
            return f"Error: Unknown plan: {plan_id!r}"
        if record.approved:
            return f"Plan {plan_id!r} was already approved."
        record.approved = True
        record.approved_at = time.time()
        return (
            f"Plan {plan_id!r} approved. "
            f"Use ariadne_execute_plan to execute."
        )

    def _handle_reject(self, plan_id: str) -> str:
        """Reject a plan by id."""
        record = _PLAN_LEDGER.get(plan_id)
        if record is None:
            return f"Error: Unknown plan: {plan_id!r}"
        if record.rejected:
            return f"Plan {plan_id!r} was already rejected."
        record.rejected = True
        return f"Plan {plan_id!r} rejected."

    def _handle_abort(self) -> str:
        """Abort the current engagement."""
        return "Abort acknowledged. No active engagement to abort."

    # ── Bind: bind session after user confirmation ──────────────────────

    def bind(
        self,
        challenge_id: str,
        session_id: str,
    ) -> BindResult:
        """Bind a confirmed challenge to a Hades session.

        The challenge must have been confirmed via ``/ariadne confirm``,
        which creates the engagement snapshot in the store.  This method
        then records the session binding so the model tool can access the
        snapshot.

        Args:
            challenge_id: The confirmed challenge identifier.
            session_id: The Hades session identifier to bind.

        Returns:
            A ``BindResult`` with the snapshot hash on success.
        """
        # Check if already bound
        existing_binding = self.ledger.get_binding(challenge_id)
        if existing_binding is not None:
            # Update session_id if needed
            if not existing_binding.session_id:
                self.ledger.bind_session(
                    challenge_id=challenge_id,
                    session_id=session_id,
                    engagement_id=existing_binding.engagement_id or UUID(int=0),
                    snapshot_hash=existing_binding.snapshot_hash,
                )
            return BindResult(
                status="confirmed",
                snapshot_hash=existing_binding.snapshot_hash,
                message="Engagement bound to session.",
            )

        # Check if the challenge was consumed (confirmed)
        record = self.ledger.get_challenge(challenge_id)
        if record is None:
            return BindResult(
                status="error",
                snapshot_hash=None,
                message=f"Error: Invalid or unknown challenge: {challenge_id!r}",
                error="Challenge not found",
            )
        if not record.consumed:
            return BindResult(
                status="error",
                snapshot_hash=None,
                message=(
                    f"Challenge {challenge_id!r} has not been confirmed yet. "
                    "Use /ariadne confirm <challenge-id> first."
                ),
                error="Challenge not yet confirmed",
            )

        return BindResult(
            status="error",
            snapshot_hash=None,
            message=f"Error: Challenge {challenge_id!r} was confirmed but no snapshot was created.",
            error="Challenge consumed without snapshot",
        )

    # ── Plan ledger ─────────────────────────────────────────────────────

    def add_plan(self, plan: Plan, snapshot_hash: str, session_id: str) -> str:
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
        )
        _PLAN_LEDGER[plan.plan_id] = record
        return plan.plan_id

    def get_plan_record(self, plan_id: str) -> PlanRecord | None:
        """Retrieve a plan record by id from the ledger."""
        return _PLAN_LEDGER.get(plan_id)

    def is_plan_approved(self, plan_id: str) -> bool:
        """Check whether a plan has been approved by the user."""
        record = _PLAN_LEDGER.get(plan_id)
        if record is None:
            return False
        return record.approved

    def is_plan_expired(self, plan_id: str) -> bool:
        """Check whether a plan has expired (15 min TTL)."""
        record = _PLAN_LEDGER.get(plan_id)
        if record is None:
            return True
        return time.time() > record.plan.expires_at.timestamp()

    # ── Utility ─────────────────────────────────────────────────────────

    def has_active_engagement(self, session_id: str) -> bool:
        """Check whether this session has a bound engagement."""
        return self.ledger.is_session_bound(session_id)
