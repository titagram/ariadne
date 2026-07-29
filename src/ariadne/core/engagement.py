"""Engagement draft, snapshot, target, and objective models."""

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from ariadne.core.enums import AutonomyMode, EnvironmentProfile
from ariadne.core.errors import ConfirmationError, ScopeError

# FQDN: labels separated by dots, trailing dot optional, case-insensitive.
_FQDN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$",
)


def _is_valid_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _is_valid_fqdn(host: str) -> bool:
    """Accept a valid IDNA FQDN, rejecting URLs, wildcards, and embedded ports.

    Must not contain scheme separators (://, :\\), port separators with
    digits, or glob-style wildcards.
    """
    stripped = host.rstrip(".")
    if len(stripped) > 253:
        return False
    if "://" in host or ":\\" in host:
        return False  # URL / UNC
    if "*" in host or "?" in host:
        return False  # wildcard
    # Embedded port: colon followed by digits at end, but not IPv6
    if re.search(r":\d+$", stripped):
        return False
    return bool(_FQDN_RE.match(stripped))


def _normalize_host(host: str) -> str:
    """Normalize an IP or FQDN string."""
    if _is_valid_ip(host):
        return host
    # FQDN: lowercase and strip trailing dot
    return host.lower().rstrip(".")


class TargetSpec(BaseModel):
    """A validated and normalized engagement target.

    Accepts only a valid IP literal or normalized IDNA FQDN.
    Rejects URLs, CIDRs, wildcards, and embedded ports.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    host: str

    @field_validator("host", mode="before")
    @classmethod
    def _validate_host(cls, v: str) -> str:
        if not isinstance(v, str) or not v.strip():
            raise ValueError("host must be a non-empty string")
        v = v.strip()
        # If it looks like an IP (4 dot-separated numeric segments), validate
        # strictly as an IP; otherwise it could slip through as a syntactically
        # valid (but non-routable) all-numeric FQDN label sequence.
        looks_like_ip = bool(re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", v))
        if _is_valid_ip(v):
            return v
        if looks_like_ip or not _is_valid_fqdn(v):
            raise ValueError(
                f"Invalid target: {v!r}. Must be a valid IP literal or FQDN "
                f"(no URLs, CIDRs, wildcards, or embedded ports)."
            )
        return _normalize_host(v)


_OBJECTIVE_KINDS = frozenset({"user_flag", "root_flag", "domain_admin", "proof", "custom"})


class Objective(BaseModel):
    """An explicit engagement objective."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: Literal["user_flag", "root_flag", "domain_admin", "proof", "custom"]
    description: str = ""

    @field_validator("description")
    @classmethod
    def _validate_custom_description(cls, v: str, info: ValidationInfo) -> str:
        if info.data.get("kind") == "custom" and not v.strip():
            raise ValueError("description is required when kind is 'custom'")
        return v


class EngagementDraft(BaseModel):
    """A draft engagement contract before confirmation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    authorization_attested: bool
    disclaimer_version: str
    profile: EnvironmentProfile
    autonomy: AutonomyMode
    target: TargetSpec
    objectives: list[Objective]

    @field_validator("objectives")
    @classmethod
    def _require_at_least_one(cls, v: list[Objective]) -> list[Objective]:
        if len(v) < 1:
            raise ValueError("At least one objective is required")
        return v


class Confirmation(BaseModel):
    """A user confirmation that locks an engagement draft.

    The challenge_digest must match the canonical digest of the draft being
    confirmed. Confirmations older than five minutes are rejected.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    challenge_id: str
    challenge_digest: str
    confirmed_at: datetime
    expires_at: datetime
    actor: Literal["user"]


class EngagementConstraints(BaseModel):
    """Engagement-specific constraints on execution behaviour."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_concurrent_checks: int = 5
    max_requests_per_second: int = 10
    max_duration_minutes: int = 480


class EngagementSnapshot(BaseModel):
    """An immutable, locked engagement snapshot."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    engagement_id: UUID
    revision: int
    previous_snapshot_hash: str | None
    snapshot_hash: str
    confirmed_at: datetime
    authorization_attested: bool
    disclaimer_version: str
    profile: EnvironmentProfile
    autonomy: AutonomyMode
    targets: tuple[TargetSpec, ...]
    objectives: tuple[Objective, ...]
    constraints: EngagementConstraints = Field(default_factory=EngagementConstraints)


def _make_content_hash(data: dict) -> str:
    """Deterministic SHA-256 hex digest of a JSON-serialisable dict."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def lock_engagement(
    draft: EngagementDraft,
    confirmation: Confirmation,
) -> EngagementSnapshot:
    """Lock an engagement draft into an immutable snapshot.

    Validates the confirmation against the draft and returns a revision-1
    ``EngagementSnapshot`` whose ``snapshot_hash`` is computed from every
    field except itself.

    Raises ``ConfirmationError`` if the digest does not match the draft or
    the confirmation has expired.
    """
    # Validate challenge digest using the canonical digest
    from ariadne.core.canonical import canonical_digest

    expected_digest = canonical_digest(draft)
    if confirmation.challenge_digest != expected_digest:
        raise ConfirmationError(
            f"Challenge digest mismatch: expected {expected_digest}, "
            f"got {confirmation.challenge_digest}"
        )

    # Validate freshness (confirmations older than five minutes are rejected)
    now = datetime.now(UTC)
    if now - confirmation.confirmed_at > timedelta(minutes=5):
        raise ConfirmationError(
            f"Confirmation is older than 5 minutes (confirmed_at: "
            f"{confirmation.confirmed_at.isoformat()}, now: {now.isoformat()})"
        )

    # Validate expiry
    if confirmation.expires_at < now:
        raise ConfirmationError(
            f"Confirmation expired at {confirmation.expires_at.isoformat()} "
            f"(now: {now.isoformat()})"
        )

    engagement_id = uuid4()
    constraints = EngagementConstraints()

    # Build data dict without snapshot_hash so we can compute it
    data = {
        "engagement_id": str(engagement_id),
        "revision": 1,
        "previous_snapshot_hash": None,
        "confirmed_at": confirmation.confirmed_at.isoformat(),
        "authorization_attested": draft.authorization_attested,
        "disclaimer_version": draft.disclaimer_version,
        "profile": draft.profile.value,
        "autonomy": draft.autonomy.value,
        "targets": [t.model_dump(mode="json") for t in (draft.target,)],
        "objectives": [o.model_dump(mode="json") for o in draft.objectives],
        "constraints": constraints.model_dump(mode="json"),
    }
    snapshot_hash = _make_content_hash(data)

    return EngagementSnapshot(
        engagement_id=engagement_id,
        revision=1,
        previous_snapshot_hash=None,
        snapshot_hash=snapshot_hash,
        confirmed_at=confirmation.confirmed_at,
        authorization_attested=draft.authorization_attested,
        disclaimer_version=draft.disclaimer_version,
        profile=draft.profile,
        autonomy=draft.autonomy,
        targets=(draft.target,),
        objectives=tuple(draft.objectives),
        constraints=constraints,
    )


def lock_attested_engagement(
    draft: EngagementDraft,
    *,
    confirmed_at: datetime | None = None,
    max_duration_minutes: int = 480,
) -> EngagementSnapshot:
    """Lock a Q/A-attested draft without a second confirmation challenge.

    The caller is responsible for establishing that the answers came from the
    interactive Hades session.  This entry point deliberately has no token or
    expiry: accepting the server-controlled disclaimer is the initial
    authorization act.
    """
    if not draft.authorization_attested:
        raise ConfirmationError("Authorization attestation is required")
    if max_duration_minutes < 1:
        raise ValueError("max_duration_minutes must be positive")

    engagement_id = uuid4()
    locked_at = confirmed_at or datetime.now(UTC)
    constraints = EngagementConstraints(
        max_duration_minutes=max_duration_minutes,
    )
    data = {
        "engagement_id": str(engagement_id),
        "revision": 1,
        "previous_snapshot_hash": None,
        "confirmed_at": locked_at.isoformat(),
        "authorization_attested": draft.authorization_attested,
        "disclaimer_version": draft.disclaimer_version,
        "profile": draft.profile.value,
        "autonomy": draft.autonomy.value,
        "targets": [draft.target.model_dump(mode="json")],
        "objectives": [o.model_dump(mode="json") for o in draft.objectives],
        "constraints": constraints.model_dump(mode="json"),
    }
    snapshot_hash = _make_content_hash(data)
    return EngagementSnapshot(
        engagement_id=engagement_id,
        revision=1,
        previous_snapshot_hash=None,
        snapshot_hash=snapshot_hash,
        confirmed_at=locked_at,
        authorization_attested=True,
        disclaimer_version=draft.disclaimer_version,
        profile=draft.profile,
        autonomy=draft.autonomy,
        targets=(draft.target,),
        objectives=tuple(draft.objectives),
        constraints=constraints,
    )


def amend_scope(
    snapshot: EngagementSnapshot,
    targets: tuple[TargetSpec, ...],
    confirmation: Confirmation,
) -> EngagementSnapshot:
    """Create a new snapshot with an amended scope.

    Returns a new ``EngagementSnapshot`` with ``revision`` incremented,
    ``previous_snapshot_hash`` pointing to the current snapshot, and a
    freshly computed ``snapshot_hash``.

    Raises ``ConfirmationError`` if the confirmation is invalid, or
    ``ScopeError`` if the targets tuple is empty.
    """
    if len(targets) < 1:
        raise ScopeError("Amendment requires at least one target")

    now = datetime.now(UTC)
    if now - confirmation.confirmed_at > timedelta(minutes=5):
        raise ConfirmationError(
            f"Confirmation is older than 5 minutes (confirmed_at: "
            f"{confirmation.confirmed_at.isoformat()}, now: {now.isoformat()})"
        )

    if confirmation.expires_at < now:
        raise ConfirmationError("Confirmation has expired")

    engagement_id = snapshot.engagement_id
    constraints = snapshot.constraints

    data = {
        "engagement_id": str(engagement_id),
        "revision": snapshot.revision + 1,
        "previous_snapshot_hash": snapshot.snapshot_hash,
        "confirmed_at": confirmation.confirmed_at.isoformat(),
        "authorization_attested": snapshot.authorization_attested,
        "disclaimer_version": snapshot.disclaimer_version,
        "profile": snapshot.profile.value,
        "autonomy": snapshot.autonomy.value,
        "targets": [t.model_dump(mode="json") for t in targets],
        "objectives": [o.model_dump(mode="json") for o in snapshot.objectives],
        "constraints": constraints.model_dump(mode="json"),
    }
    snapshot_hash = _make_content_hash(data)

    return EngagementSnapshot(
        engagement_id=engagement_id,
        revision=snapshot.revision + 1,
        previous_snapshot_hash=snapshot.snapshot_hash,
        snapshot_hash=snapshot_hash,
        confirmed_at=confirmation.confirmed_at,
        authorization_attested=snapshot.authorization_attested,
        disclaimer_version=snapshot.disclaimer_version,
        profile=snapshot.profile,
        autonomy=snapshot.autonomy,
        targets=targets,
        objectives=snapshot.objectives,
        constraints=constraints,
    )
