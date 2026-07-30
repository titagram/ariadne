"""Task 4: monotonic policy intersection property and contract tests."""

import os
import subprocess
import sys

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from ariadne.core.errors import PolicyConfigurationError
from ariadne.core.policy import (
    ActionRequest,
    CapabilityRule,
    PolicyDocument,
    authorize,
    intersect_policies,
    load_policy,
)

# ── Helpers ─────────────────────────────────────────────────────────────────


def policy_with_rate(rate: int) -> PolicyDocument:
    """Create a minimal policy with a single scan.tcp capability."""
    return PolicyDocument(
        name="test-policy",
        version=1,
        capabilities={
            "scan.tcp": CapabilityRule(
                allowed=True,
                max_rate=rate,
            ),
        },
    )


def policy_with_concurrency(concurrency: int) -> PolicyDocument:
    """Create a minimal policy with a single scan.tcp capability."""
    return PolicyDocument(
        name="test-policy",
        version=1,
        capabilities={
            "scan.tcp": CapabilityRule(
                allowed=True,
                max_concurrency=concurrency,
            ),
        },
    )


def make_request(
    capability: str = "scan.tcp",
    target: str = "10.10.10.1",
    tool: str = "nmap",
    rate: int = 100,
    concurrency: int = 5,
    attempts: int = 3,
    duration: int = 300,
    output_bytes: int = 1_000_000,
) -> ActionRequest:
    """Create a standard action request for testing."""
    return ActionRequest(
        capability=capability,
        target=target,
        tool=tool,
        requested_rate=rate,
        requested_concurrency=concurrency,
        requested_attempts=attempts,
        requested_duration_seconds=duration,
        requested_output_bytes=output_bytes,
    )


# ── Monotonic intersection properties ───────────────────────────────────────


@given(st.integers(1, 1000), st.integers(1, 1000))
def test_intersection_rate_is_never_higher(left: int, right: int) -> None:
    """Intersection of two max_rate values must be <= the minimum."""
    effective = intersect_policies(
        policy_with_rate(left),
        policy_with_rate(right),
    )
    rule = effective.rule("scan.tcp")
    assert rule.max_rate is not None
    assert rule.max_rate <= min(left, right)


@given(st.integers(1, 1000), st.integers(1, 1000))
def test_intersection_concurrency_is_never_higher(left: int, right: int) -> None:
    """Intersection of two max_concurrency values must be <= the minimum."""
    effective = intersect_policies(
        policy_with_concurrency(left),
        policy_with_concurrency(right),
    )
    rule = effective.rule("scan.tcp")
    assert rule.max_concurrency is not None
    assert rule.max_concurrency <= min(left, right)


@given(
    st.integers(1, 100),
    st.integers(1, 100),
    st.integers(1, 100),
)
def test_intersection_rate_is_monotonic(a: int, b: int, c: int) -> None:
    """Adding a third restrictive policy can only reduce the max_rate further."""
    effective = intersect_policies(
        policy_with_rate(a),
        policy_with_rate(b),
    )
    effective_three = intersect_policies(
        policy_with_rate(a),
        policy_with_rate(b),
        policy_with_rate(c),
    )
    rule_one = effective.rule("scan.tcp")
    rule_two = effective_three.rule("scan.tcp")
    assert rule_one.max_rate is not None
    assert rule_two.max_rate is not None
    assert rule_two.max_rate <= rule_one.max_rate


# ── always_manual OR logic ──────────────────────────────────────────────────


def test_always_manual_is_or_union() -> None:
    """always_manual is True if any layer sets it True."""
    permissive = PolicyDocument(
        name="permissive",
        version=1,
        capabilities={
            "exploit": CapabilityRule(allowed=True, always_manual=False),
        },
    )
    restrictive = PolicyDocument(
        name="restrictive",
        version=1,
        capabilities={
            "exploit": CapabilityRule(allowed=True, always_manual=True),
        },
    )
    # Order should not matter
    effective_a = intersect_policies(permissive, restrictive)
    effective_b = intersect_policies(restrictive, permissive)
    assert effective_a.rule("exploit").always_manual is True
    assert effective_b.rule("exploit").always_manual is True


def test_always_manual_false_when_all_false() -> None:
    """always_manual is False only when every layer sets it False."""
    a = PolicyDocument(
        name="a",
        version=1,
        capabilities={"scan": CapabilityRule(allowed=True, always_manual=False)},
    )
    b = PolicyDocument(
        name="b",
        version=1,
        capabilities={"scan": CapabilityRule(allowed=True, always_manual=False)},
    )
    effective = intersect_policies(a, b)
    assert effective.rule("scan").always_manual is False


# ── Tool-set intersection ───────────────────────────────────────────────────


def test_allowed_tools_are_intersected() -> None:
    """allowed_tools is the intersection of all layers."""
    a = PolicyDocument(
        name="a",
        version=1,
        capabilities={
            "scan.tcp": CapabilityRule(
                allowed=True,
                allowed_tools={"nmap", "masscan", "naabu"},
            ),
        },
    )
    b = PolicyDocument(
        name="b",
        version=1,
        capabilities={
            "scan.tcp": CapabilityRule(
                allowed=True,
                allowed_tools={"nmap", "unicornscan"},
            ),
        },
    )
    effective = intersect_policies(a, b)
    assert effective.rule("scan.tcp").allowed_tools == {"nmap"}


def test_allowed_tools_unrestricted_lower_layer_does_not_empty_restriction() -> None:
    """A lower layer that omits allowed_tools (empty = unrestricted) must NOT
    erase an upper layer's explicit tool allow-list.

    Empty allowed_tools means 'no restriction on this layer' — analogous to
    None for numeric bounds. Intersection of {'nmap'} with unrestricted
    should stay {'nmap'}, not become empty.

    Regression test for finding F1: masscan must be denied even when the
    lower layer does not specify any tool restriction.
    """
    base = PolicyDocument(
        name="base",
        version=1,
        capabilities={
            "scan.tcp": CapabilityRule(
                allowed=True,
                allowed_tools=frozenset({"nmap"}),
            ),
        },
    )
    # Lower layer with default (empty) allowed_tools — means unrestricted
    lower = PolicyDocument(
        name="lower",
        version=1,
        capabilities={
            "scan.tcp": CapabilityRule(allowed=True),
        },
    )
    effective = intersect_policies(base, lower)

    # The tool restriction must survive: {'nmap'} ∩ unrestricted = {'nmap'}
    rule = effective.rule("scan.tcp")
    assert rule.allowed_tools == {"nmap"}, (
        f"Expected {{'nmap'}} but got {rule.allowed_tools}"
    )

    # authorize() must deny masscan, which is not nmap
    decision = authorize(effective, make_request(tool="masscan"))
    assert decision.allowed is False, (
        f"masscan should be denied by monotonic intersection, "
        f"got allowed={decision.allowed} reason={decision.reason_code}"
    )
    assert decision.reason_code == "tool_not_allowed"


def test_allowed_tools_fully_unrestricted_stays_unrestricted() -> None:
    """When every layer leaves allowed_tools empty (unrestricted),
    the effective policy should also have no tool restriction."""
    a = PolicyDocument(
        name="a",
        version=1,
        capabilities={
            "scan.tcp": CapabilityRule(allowed=True),
        },
    )
    b = PolicyDocument(
        name="b",
        version=1,
        capabilities={
            "scan.tcp": CapabilityRule(allowed=True),
        },
    )
    effective = intersect_policies(a, b)
    rule = effective.rule("scan.tcp")
    # Empty = unrestricted
    assert rule.allowed_tools == frozenset(), (
        f"Expected unrestricted (empty frozenset), got {rule.allowed_tools}"
    )
    # authorize() must allow any tool through
    decision = authorize(effective, make_request(tool="masscan"))
    assert decision.allowed is True, (
        f"Any tool should be allowed when no layer restricts tools, "
        f"got allowed={decision.allowed} reason={decision.reason_code}"
    )


# ── Missing capability is denied ────────────────────────────────────────────


def test_missing_capability_denies_by_default() -> None:
    """A capability not present in any layer must raise KeyError through the
    intersection or be missing from the effective policy."""
    policy = PolicyDocument(
        name="minimal",
        version=1,
        capabilities={
            "scan.tcp": CapabilityRule(allowed=True),
        },
    )
    effective = intersect_policies(policy)
    # Only explicitly declared capabilities survive intersection
    caps = set(effective.capabilities)
    assert "scan.tcp" in caps
    assert "resource.stress" not in caps


# ── allowed boolean AND ─────────────────────────────────────────────────────


def test_allowed_is_and_across_layers() -> None:
    """A capability is allowed only if every layer allows it."""
    base = PolicyDocument(
        name="base",
        version=1,
        capabilities={
            "scan.tcp": CapabilityRule(allowed=True),
        },
    )
    restricted = PolicyDocument(
        name="restricted",
        version=1,
        capabilities={
            "scan.tcp": CapabilityRule(allowed=False),
        },
    )
    effective = intersect_policies(base, restricted)
    authorize_result = authorize(effective, make_request())
    assert authorize_result.allowed is False
    assert authorize_result.reason_code == "denied"


# ── authorize function ──────────────────────────────────────────────────────


def test_authorize_allows_explicitly_allowed_action() -> None:
    """A request that matches an allowed capability returns allowed=True."""
    policy = PolicyDocument(
        name="dev",
        version=1,
        capabilities={
            "scan.tcp": CapabilityRule(
                allowed=True,
                max_rate=500,
                max_concurrency=10,
                max_attempts=5,
                max_duration_seconds=3600,
                max_output_bytes=10_000_000,
                allowed_tools={"nmap"},
            ),
        },
    )
    effective = intersect_policies(policy)
    decision = authorize(
        effective,
        make_request(rate=100, concurrency=5, attempts=3, duration=300, output_bytes=1_000_000),
    )
    assert decision.allowed is True
    assert decision.requires_manual_approval is False
    assert decision.effective_rule is not None


def test_authorize_denies_unknown_capability() -> None:
    """A request for a capability not in the effective policy must be denied."""
    policy = PolicyDocument(
        name="dev",
        version=1,
        capabilities={
            "scan.tcp": CapabilityRule(allowed=True),
        },
    )
    effective = intersect_policies(policy)
    decision = authorize(effective, make_request(capability="exploit"))
    assert decision.allowed is False
    assert decision.reason_code == "unknown_capability"


def test_authorize_reports_requires_manual() -> None:
    """When always_manual is set, requires_manual_approval must be True."""
    policy = PolicyDocument(
        name="dev",
        version=1,
        capabilities={
            "exploit": CapabilityRule(allowed=True, always_manual=True, max_rate=10),
        },
    )
    effective = intersect_policies(policy)
    decision = authorize(effective, make_request(capability="exploit", rate=5))
    assert decision.allowed is True
    assert decision.requires_manual_approval is True


def test_authorize_denies_rate_exceeds_max() -> None:
    """When requested rate exceeds the policy max, deny with rate_exceeded."""
    policy = PolicyDocument(
        name="dev",
        version=1,
        capabilities={
            "scan.tcp": CapabilityRule(allowed=True, max_rate=10),
        },
    )
    effective = intersect_policies(policy)
    decision = authorize(effective, make_request(rate=50))
    assert decision.allowed is False
    assert decision.reason_code == "rate_exceeded"


def test_authorize_denies_concurrency_exceeds_max() -> None:
    """When requested concurrency exceeds the policy max, deny."""
    policy = PolicyDocument(
        name="dev",
        version=1,
        capabilities={
            "scan.tcp": CapabilityRule(allowed=True, max_concurrency=2),
        },
    )
    effective = intersect_policies(policy)
    decision = authorize(effective, make_request(concurrency=10))
    assert decision.allowed is False
    assert decision.reason_code == "concurrency_exceeded"


def test_authorize_denies_tool_not_allowed() -> None:
    """When the requested tool is not in allowed_tools, deny."""
    policy = PolicyDocument(
        name="dev",
        version=1,
        capabilities={
            "scan.tcp": CapabilityRule(allowed=True, allowed_tools={"nmap"}),
        },
    )
    effective = intersect_policies(policy)
    decision = authorize(effective, make_request(tool="masscan"))
    assert decision.allowed is False
    assert decision.reason_code == "tool_not_allowed"


def test_authorize_denies_attempts_exceed_max() -> None:
    """When requested attempts exceed the policy max, deny."""
    policy = PolicyDocument(
        name="dev",
        version=1,
        capabilities={
            "scan.tcp": CapabilityRule(allowed=True, max_attempts=2),
        },
    )
    effective = intersect_policies(policy)
    decision = authorize(effective, make_request(attempts=10))
    assert decision.allowed is False
    assert decision.reason_code == "attempts_exceeded"


# ── load_policy ─────────────────────────────────────────────────────────────


def test_load_policy_accepts_valid_yaml(tmp_path) -> None:
    """A valid YAML policy file should load into a PolicyDocument."""
    p = tmp_path / "test.yaml"
    p.write_text(
        "name: test\n"
        "version: 1\n"
        "capabilities:\n"
        "  scan.tcp:\n"
        '    allowed: true\n'
    )
    doc = load_policy(p)
    assert doc.name == "test"
    assert doc.version == 1
    assert doc.capabilities["scan.tcp"].allowed is True


def test_load_policy_rejects_invalid_yaml(tmp_path) -> None:
    """An invalid YAML policy must raise PolicyConfigurationError."""
    p = tmp_path / "bad.yaml"
    p.write_text("not: valid: yaml: {{ broken")
    with pytest.raises(PolicyConfigurationError):
        load_policy(p)


# ── Validation ──────────────────────────────────────────────────────────────


def test_capability_rule_defaults_to_deny() -> None:
    """A CapabilityRule defaults to allowed=False — fail closed."""
    rule = CapabilityRule()
    assert rule.allowed is False


def test_policy_document_rejects_extra_fields() -> None:
    """PolicyDocument must reject arbitrary extra fields."""
    with pytest.raises(ValidationError):
        PolicyDocument(
            name="test",
            version=1,
            capabilities={},
            extra_field="nope",  # type: ignore[call-arg]
        )


def test_effective_policy_carries_source_digests() -> None:
    """EffectivePolicy stores the digests of its source policies."""
    a = policy_with_rate(100)
    b = policy_with_rate(50)
    effective = intersect_policies(a, b)
    assert len(effective.source_digests) == 2
    assert all(isinstance(d, str) for d in effective.source_digests)
    assert len(effective.source_digests[0]) == 64  # SHA-256 hex


def test_policy_digest_is_stable_across_python_hash_seeds() -> None:
    script = """
from ariadne.core.policy import CapabilityRule, PolicyDocument, intersect_policies
document = PolicyDocument(
    name="stable",
    version=1,
    capabilities={
        "scan.tcp": CapabilityRule(
            allowed=True,
            allowed_tools=frozenset({"curl", "katana", "nmap", "zaproxy"}),
        )
    },
)
print(intersect_policies(document).source_digests[0])
"""
    digests = {
        subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        ).stdout.strip()
        for seed in ("1", "2")
    }

    assert len(digests) == 1


# ── PolicyDecision carries effective_rule ────────────────────────────────────


def test_policy_decision_has_effective_rule_on_allowed() -> None:
    """When allowed, the effective rule must be returned."""
    policy = PolicyDocument(
        name="dev",
        version=1,
        capabilities={
            "scan.tcp": CapabilityRule(allowed=True, max_rate=100),
        },
    )
    effective = intersect_policies(policy)
    decision = authorize(effective, make_request(rate=50))
    assert decision.allowed is True
    assert decision.effective_rule is not None
    assert decision.effective_rule.max_rate == 100


def test_policy_decision_has_none_rule_on_unknown_capability() -> None:
    """When the capability is unknown, effective_rule is None."""
    policy = PolicyDocument(
        name="dev",
        version=1,
        capabilities={},
    )
    effective = intersect_policies(policy)
    decision = authorize(effective, make_request(capability="scan.tcp"))
    assert decision.allowed is False
    assert decision.effective_rule is None
