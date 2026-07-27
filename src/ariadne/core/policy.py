"""Policy models, monotonic intersection, and authorization.

Typed capability rules, policy documents, and the intersection algebra
that enforces fail-closed, monotonic authorization across base policy,
environment profile, and engagement layers.

Effective permission is an intersection:

    base policy ∩ environment profile ∩ engagement snapshot ∩ action plan

A lower layer may restrict a capability but may never expand a higher layer.
"""

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict

from ariadne.core.errors import PolicyConfigurationError

# ── Models ────────────────────────────────────────────────────────────────────


class CapabilityRule(BaseModel):
    """A typed rule governing a single capability in the policy model.

    ``allowed`` defaults to ``False`` so every capability is fail-closed.
    ``null`` numeric fields mean that layer places no restriction on that
    dimension; the intersection preserves ``null`` when all layers agree
    on no restriction.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed: bool = False
    always_manual: bool = False

    max_rate: int | None = None
    max_concurrency: int | None = None
    max_attempts: int | None = None
    max_duration_seconds: int | None = None
    max_output_bytes: int | None = None

    allowed_tools: frozenset[str] = frozenset()


class PolicyDocument(BaseModel):
    """A versioned policy document declaring capability rules.

    Every document is frozen and forbids extra fields so intersection
    results are deterministic.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    version: int
    capabilities: Mapping[str, CapabilityRule]


class EffectivePolicy(PolicyDocument):
    """An immutable intersected policy carrying source digests for audit.

    ``source_digests`` records the canonical digests of every document
    that contributed to this effective policy, enabling downstream
    audit and snapshot linkage.
    """

    source_digests: tuple[str, ...]

    def rule(self, capability: str) -> CapabilityRule:
        """Look up a capability rule by name.

        Raises ``KeyError`` if the capability is not present in the
        effective policy.
        """
        if capability not in self.capabilities:
            raise KeyError(
                f"Capability {capability!r} is not present in effective policy "
                f"'{self.name}'"
            )
        return self.capabilities[capability]


class ActionRequest(BaseModel):
    """A request to perform a capability-related action.

    All requested dimensions must be validated against the effective
    policy's ``CapabilityRule`` bounds.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    capability: str
    target: str
    tool: str
    requested_rate: int
    requested_concurrency: int
    requested_attempts: int
    requested_duration_seconds: int
    requested_output_bytes: int


class PolicyDecision(BaseModel):
    """The result of an authorization check against an effective policy.

    ``allowed`` is ``True`` only when every dimension passes. When
    denied, ``reason_code`` provides a structured explanation.
    ``effective_rule`` is ``None`` when the capability is unknown.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed: bool
    requires_manual_approval: bool
    reason_code: str
    effective_rule: CapabilityRule | None


# ── Helpers ───────────────────────────────────────────────────────────────────


def _canonical_policy_digest(doc: PolicyDocument) -> str:
    """Deterministic SHA-256 hex digest of a policy document."""
    raw = doc.model_dump(mode="json")
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# Pattern to detect CIDR-notation targets.
_CIDR_RE = re.compile(r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/\d{1,2}$")

# Scannable capability prefixes — CIDR targets are meaningful here.
_SCAN_PREFIXES = ("scan.", "service.enum", "web.", "resource.")


def _target_is_cidr(target: str) -> bool:
    """Return True if the target string looks like a CIDR subnet notation."""
    return bool(_CIDR_RE.match(target))


def _is_scan_capability(capability: str) -> bool:
    """Return True if the capability involves network scanning or stress."""
    return any(capability.startswith(p) for p in _SCAN_PREFIXES)


# ── Intersection algebra ──────────────────────────────────────────────────────


def _intersect_rule(left: CapabilityRule, right: CapabilityRule) -> CapabilityRule:
    """Intersect two capability rules using monotonic algebra.

    * ``allowed``: boolean AND (most restrictive wins).
    * ``always_manual``: boolean OR (any layer requiring manual wins).
    * Numeric fields: ``min`` of non-``None`` values. If both are
      ``None``, the intersected field is ``None`` (no restriction).
    * ``allowed_tools``: set intersection.
    """
    return CapabilityRule(
        allowed=left.allowed and right.allowed,
        always_manual=left.always_manual or right.always_manual,
        max_rate=_min_or_none(left.max_rate, right.max_rate),
        max_concurrency=_min_or_none(left.max_concurrency, right.max_concurrency),
        max_attempts=_min_or_none(left.max_attempts, right.max_attempts),
        max_duration_seconds=_min_or_none(left.max_duration_seconds, right.max_duration_seconds),
        max_output_bytes=_min_or_none(left.max_output_bytes, right.max_output_bytes),
        allowed_tools=left.allowed_tools & right.allowed_tools,
    )


def _min_or_none(a: int | None, b: int | None) -> int | None:
    """Return the minimum of two nullable ints. ``None`` means "no limit"."""
    if a is None and b is None:
        return None
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)


# ── Public API ────────────────────────────────────────────────────────────────


def load_policy(path: Path) -> PolicyDocument:
    """Load a YAML policy file and return a validated ``PolicyDocument``.

    Args:
        path: Filesystem path to a YAML policy document.

    Returns:
        A validated ``PolicyDocument``.

    Raises:
        PolicyConfigurationError: If the file cannot be read, YAML is
            malformed, or the document fails Pydantic validation.
    """
    try:
        raw = path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyConfigurationError(
            f"Failed to load policy from {path}: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise PolicyConfigurationError(
            f"Policy file {path} must contain a mapping, got {type(data).__name__}"
        )

    try:
        return PolicyDocument.model_validate(data)
    except Exception as exc:
        raise PolicyConfigurationError(
            f"Policy validation failed for {path}: {exc}"
        ) from exc


def intersect_policies(*documents: PolicyDocument) -> EffectivePolicy:
    """Compute the monotonic intersection of two or more policy documents.

    The intersection algebra ensures that a lower layer (later argument)
    may only restrict a capability — it may never expand one.

    Only capabilities present in **every** input document survive into the
    effective policy.

    Args:
        *documents: Two or more ``PolicyDocument`` instances. The first
            is typically the base policy.

    Returns:
        An ``EffectivePolicy`` carrying the intersected rules and the
        canonical digests of every input document.

    Raises:
        ValueError: If fewer than one document is supplied.
    """
    if not documents:
        raise ValueError("At least one policy document is required")

    # Collect digests for audit trail
    digests = tuple(_canonical_policy_digest(d) for d in documents)

    # Compute intersection of capability keys (present in ALL documents)
    all_cap_keys: set[str] | None = None
    for doc in documents:
        keys = set(doc.capabilities)
        if all_cap_keys is None:
            all_cap_keys = keys
        else:
            all_cap_keys &= keys

    if all_cap_keys is None:
        all_cap_keys = set()

    # Intersect rules for every surviving capability
    intersected: dict[str, CapabilityRule] = {}
    for key in sorted(all_cap_keys):
        rule = documents[0].capabilities[key]
        for doc in documents[1:]:
            rule = _intersect_rule(rule, doc.capabilities[key])
        intersected[key] = rule

    return EffectivePolicy(
        name=_intersected_name(documents),
        version=max(d.version for d in documents),
        capabilities=intersected,
        source_digests=digests,
    )


def _intersected_name(documents: tuple[PolicyDocument, ...]) -> str:
    """Produce a composite name from the input document names."""
    if len(documents) == 1:
        return documents[0].name
    return " ∩ ".join(d.name for d in documents)


def authorize(
    policy: EffectivePolicy,
    request: ActionRequest,
) -> PolicyDecision:
    """Check whether an action request is authorized under an effective policy.

    The check proceeds fail-closed:

    1. Capability must exist in the effective policy.
    2. The capability must be ``allowed``.
    3. Every requested dimension must be at or below the rule's bound.
    4. The requested tool must be in ``allowed_tools`` (if non-empty).
    5. CIDR targets are denied for scan-like capabilities (fail-closed).

    Args:
        policy: The effective (intersected) policy.
        request: The action request to authorize.

    Returns:
        A ``PolicyDecision`` with the verdict and reason code.
    """
    # Step 1: capability exists
    if request.capability not in policy.capabilities:
        return PolicyDecision(
            allowed=False,
            requires_manual_approval=False,
            reason_code="unknown_capability",
            effective_rule=None,
        )

    rule = policy.capabilities[request.capability]

    # Step 2: allowed flag
    if not rule.allowed:
        return PolicyDecision(
            allowed=False,
            requires_manual_approval=False,
            reason_code="denied",
            effective_rule=rule,
        )

    # Step 3: CIDR target check for scan capabilities
    if _target_is_cidr(request.target) and _is_scan_capability(request.capability):
        return PolicyDecision(
            allowed=False,
            requires_manual_approval=False,
            reason_code="invalid_target",
            effective_rule=rule,
        )

    # Step 4: numeric bounds
    if rule.max_rate is not None and request.requested_rate > rule.max_rate:
        return PolicyDecision(
            allowed=False,
            requires_manual_approval=False,
            reason_code="rate_exceeded",
            effective_rule=rule,
        )

    if rule.max_concurrency is not None and request.requested_concurrency > rule.max_concurrency:
        return PolicyDecision(
            allowed=False,
            requires_manual_approval=False,
            reason_code="concurrency_exceeded",
            effective_rule=rule,
        )

    if rule.max_attempts is not None and request.requested_attempts > rule.max_attempts:
        return PolicyDecision(
            allowed=False,
            requires_manual_approval=False,
            reason_code="attempts_exceeded",
            effective_rule=rule,
        )

    if (
        rule.max_duration_seconds is not None
        and request.requested_duration_seconds > rule.max_duration_seconds
    ):
        return PolicyDecision(
            allowed=False,
            requires_manual_approval=False,
            reason_code="duration_exceeded",
            effective_rule=rule,
        )

    if (
        rule.max_output_bytes is not None
        and request.requested_output_bytes > rule.max_output_bytes
    ):
        return PolicyDecision(
            allowed=False,
            requires_manual_approval=False,
            reason_code="output_exceeded",
            effective_rule=rule,
        )

    # Step 5: tool validation
    if rule.allowed_tools and request.tool not in rule.allowed_tools:
        return PolicyDecision(
            allowed=False,
            requires_manual_approval=False,
            reason_code="tool_not_allowed",
            effective_rule=rule,
        )

    # All checks passed — allowed
    return PolicyDecision(
        allowed=True,
        requires_manual_approval=rule.always_manual,
        reason_code="allowed",
        effective_rule=rule,
    )
