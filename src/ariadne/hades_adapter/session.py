"""Hades session-to-engagement binding and challenge ledger.

ChallengeLedger manages one-time use, time-limited challenges that a
real user must confirm via the /ariadne command before an engagement
snapshot can be bound to a Hades session.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any
from uuid import UUID

_CHALLENGE_TYPES = frozenset({"contract", "scope", "host_install", "uncurated_poc"})


@dataclass
class ChallengeRecord:
    """A single pending challenge waiting for user confirmation.

    Attributes:
        challenge_id: URL-safe random identifier (128 bits).
        payload_digest: Canonical digest of the associated payload.
        payload: The original serialisable payload (engagement answers).
        challenge_type: Kind of approval required.
        created_at: UTC epoch-seconds when this challenge was created.
        expires_at: UTC epoch-seconds after which the challenge is stale.
        consumed: Whether the challenge has already been used.
        engagement_id: UUID of the engagement draft associated with this
            challenge.
    """

    challenge_id: str = ""
    payload_digest: str = ""
    payload: dict[str, Any] | None = None
    challenge_type: str = ""
    created_at: float = 0.0
    expires_at: float = 0.0
    consumed: bool = False
    engagement_id: UUID | None = None


@dataclass
class SessionBindingInfo:
    """Information returned after a successful session binding."""

    challenge_id: str = ""
    session_id: str = ""
    engagement_id: UUID | None = None
    snapshot_hash: str = ""


@dataclass
class SessionBinding:
    """A confirmed session binding stored in ChallengeLedger."""

    challenge_id: str = ""
    session_id: str = ""
    engagement_id: UUID | None = None
    snapshot_hash: str = ""


class ChallengeLedger:
    """In-memory ledger of pending challenges and confirmed session bindings.

    Challenges are one-time-use, expire after 5 minutes, and are consumed
    by the first successful confirmation.

    This is intentionally in-memory: after a process restart, pending
    challenges are gone and must be re-created.
    """

    def __init__(self) -> None:
        self._challenges: dict[str, ChallengeRecord] = {}
        self._bindings: dict[str, SessionBinding] = {}
        self._engagement_bindings: dict[str, list[SessionBinding]] = {}

    # ── Challenge lifecycle ────────────────────────────────────────────

    @staticmethod
    def _generate_id() -> str:
        """Generate a 128-bit URL-safe random challenge identifier."""
        return secrets.token_urlsafe(16)

    @staticmethod
    def _ttl_seconds() -> float:
        """Challenge time-to-live in seconds (5 minutes)."""
        return 300.0

    def create_challenge(
        self,
        payload_digest: str,
        payload: dict[str, Any] | None = None,
        challenge_type: str = "contract",
        engagement_id: UUID | None = None,
    ) -> str:
        """Create a new pending challenge and return its identifier.

        Args:
            payload_digest: Canonical SHA-256 digest of the payload being
                confirmed.
            payload: The original serialisable payload (engagement answers).
            challenge_type: One of ``contract``, ``scope``, ``host_install``,
                or ``uncurated_poc``.
            engagement_id: UUID of the associated engagement draft.

        Returns:
            The URL-safe challenge identifier string.

        Raises:
            ValueError: If *challenge_type* is not recognised.
        """
        if challenge_type not in _CHALLENGE_TYPES:
            raise ValueError(
                f"Unknown challenge type {challenge_type!r}. "
                f"Must be one of {sorted(_CHALLENGE_TYPES)}"
            )

        challenge_id = self._generate_id()
        now = time.time()
        record = ChallengeRecord(
            challenge_id=challenge_id,
            payload_digest=payload_digest,
            payload=payload,
            challenge_type=challenge_type,
            created_at=now,
            expires_at=now + self._ttl_seconds(),
            consumed=False,
            engagement_id=engagement_id,
        )
        self._challenges[challenge_id] = record
        return challenge_id

    def consume_challenge(self, challenge_id: str) -> ChallengeRecord | None:
        """Consume and return a challenge if it is valid.

        A challenge is valid if it exists, has not been consumed, and
        has not expired.  On success the challenge is marked consumed.

        Returns:
            The ``ChallengeRecord`` if valid, or ``None`` if the challenge
            does not exist, is already consumed, or has expired.
        """
        record = self._challenges.get(challenge_id)
        if record is None:
            return None
        if record.consumed:
            return None
        if time.time() > record.expires_at:
            return None
        record.consumed = True
        return record

    def peek_challenge(self, challenge_id: str) -> ChallengeRecord | None:
        """Peek at a challenge record without consuming it.

        Returns ``None`` if the challenge does not exist, has been
        consumed, or has expired.
        """
        record = self._challenges.get(challenge_id)
        if record is None:
            return None
        if record.consumed:
            return None
        if time.time() > record.expires_at:
            return None
        return record

    def get_challenge(self, challenge_id: str) -> ChallengeRecord | None:
        """Retrieve a challenge record regardless of state.

        Unlike ``peek_challenge``, this returns the record even if
        consumed or expired.
        """
        return self._challenges.get(challenge_id)

    def _expire_challenge(self, challenge_id: str) -> None:
        """Force-expire a challenge (used in tests to simulate 5-minute TTL)."""
        record = self._challenges.get(challenge_id)
        if record is not None:
            record.expires_at = 0.0

    # ── Session binding ─────────────────────────────────────────────────

    def bind_session(
        self,
        challenge_id: str,
        session_id: str,
        engagement_id: UUID,
        snapshot_hash: str,
    ) -> SessionBindingInfo:
        """Bind a confirmed challenge to a Hades session.

        Args:
            challenge_id: The confirmed challenge identifier.
            session_id: The Hades session identifier.
            engagement_id: UUID of the locked engagement.
            snapshot_hash: Hash of the immutable engagement snapshot.

        Returns:
            A ``SessionBindingInfo`` on success.
        """
        binding = SessionBinding(
            challenge_id=challenge_id,
            session_id=session_id,
            engagement_id=engagement_id,
            snapshot_hash=snapshot_hash,
        )
        self._bindings[challenge_id] = binding
        eng_key = str(engagement_id)
        if eng_key not in self._engagement_bindings:
            self._engagement_bindings[eng_key] = []
        self._engagement_bindings[eng_key].append(binding)

        return SessionBindingInfo(
            challenge_id=challenge_id,
            session_id=session_id,
            engagement_id=engagement_id,
            snapshot_hash=snapshot_hash,
        )

    def get_binding(self, challenge_id: str) -> SessionBinding | None:
        """Retrieve the binding for a challenge, if any."""
        return self._bindings.get(challenge_id)

    def get_engagement_binding(
        self, engagement_id: UUID
    ) -> SessionBinding | None:
        """Retrieve the first binding for an engagement, if any."""
        bindings = self._engagement_bindings.get(str(engagement_id))
        if bindings:
            return bindings[0]
        return None

    def is_session_bound(self, session_id: str) -> bool:
        """Check if a Hades session is already bound to any engagement."""
        return any(
            b.session_id == session_id for b in self._bindings.values()
        )
