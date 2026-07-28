"""Task 2: domain model and canonical digest contract tests."""

import re
from uuid import UUID

import pytest
from pydantic import ValidationError

from ariadne.core.canonical import canonical_digest
from ariadne.core.engagement import EngagementDraft, Objective, TargetSpec
from ariadne.core.enums import (
    AssetStatus,
    AutonomyMode,
    EnvironmentProfile,
    FindingStatus,
)

# ── Enums ──────────────────────────────────────────────────────────────────

def test_autonomy_mode_values() -> None:
    assert AutonomyMode.CONTROLLED == "controlled"
    assert AutonomyMode.FULL == "full"
    assert set(AutonomyMode) == {"controlled", "full"}


def test_environment_profile_values() -> None:
    assert EnvironmentProfile.PRIVATE_LAB == "private-lab"
    assert EnvironmentProfile.HTB == "htb"
    assert set(EnvironmentProfile) == {"private-lab", "htb"}


def test_asset_status_values() -> None:
    assert AssetStatus.IN_SCOPE == "in_scope"
    assert AssetStatus.OBSERVED_ONLY == "observed_only"
    assert set(AssetStatus) == {"in_scope", "observed_only"}


def test_finding_status_values() -> None:
    assert FindingStatus.CANDIDATE == "candidate"
    assert FindingStatus.VALIDATED == "validated"
    assert FindingStatus.EXPLOITED == "exploited"
    assert FindingStatus.FALSE_POSITIVE == "false_positive"
    assert FindingStatus.INFORMATIONAL == "informational"
    assert FindingStatus.POLICY_BLOCKED == "not_tested_due_to_policy"
    assert set(FindingStatus) == {
        "candidate",
        "validated",
        "exploited",
        "false_positive",
        "informational",
        "not_tested_due_to_policy",
    }


# ── TargetSpec ─────────────────────────────────────────────────────────────


def test_targetspec_accepts_ip_literal() -> None:
    ts = TargetSpec(host="10.10.10.1")
    assert ts.host == "10.10.10.1"


def test_targetspec_accepts_fqdn_and_normalizes_case() -> None:
    ts = TargetSpec(host="BOX.HTB.")
    assert ts.host == "box.htb"


def test_targetspec_rejects_url() -> None:
    with pytest.raises(ValidationError):
        TargetSpec(host="http://example.com")


def test_targetspec_rejects_cidr() -> None:
    with pytest.raises(ValidationError):
        TargetSpec(host="10.10.10.0/24")


def test_targetspec_rejects_wildcard() -> None:
    with pytest.raises(ValidationError):
        TargetSpec(host="*.example.com")


def test_targetspec_rejects_embedded_port() -> None:
    with pytest.raises(ValidationError):
        TargetSpec(host="10.10.10.1:8080")


def test_targetspec_rejects_empty_string() -> None:
    with pytest.raises(ValidationError):
        TargetSpec(host="")


def test_targetspec_rejects_invalid_ip() -> None:
    with pytest.raises(ValidationError):
        TargetSpec(host="999.999.999.999")


# ── Objective ──────────────────────────────────────────────────────────────


def test_objective_kind_user_flag() -> None:
    obj = Objective(kind="user_flag", description="Get user flag")
    assert obj.kind == "user_flag"


def test_objective_kind_root_flag() -> None:
    obj = Objective(kind="root_flag", description="Get root flag")
    assert obj.kind == "root_flag"


def test_objective_kind_domain_admin() -> None:
    obj = Objective(kind="domain_admin", description="Get DA")
    assert obj.kind == "domain_admin"


def test_objective_kind_proof() -> None:
    obj = Objective(kind="proof", description="Proof of access")
    assert obj.kind == "proof"


def test_objective_custom_requires_description() -> None:
    obj = Objective(kind="custom", description="Find hidden endpoint")
    assert obj.kind == "custom"
    assert obj.description == "Find hidden endpoint"


def test_objective_custom_rejects_empty_description() -> None:
    with pytest.raises(ValidationError):
        Objective(kind="custom", description="")


def test_objective_rejects_invalid_kind() -> None:
    with pytest.raises(ValidationError):
        Objective(kind="invalid_kind", description="x")


def test_objective_non_custom_empty_description_ok() -> None:
    """Description is optional for non-custom kinds."""
    obj = Objective(kind="user_flag", description="")
    assert obj.kind == "user_flag"


# ── EngagementDraft ────────────────────────────────────────────────────────


def test_draft_normalizes_fqdn_and_digest_is_stable() -> None:
    draft = EngagementDraft(
        authorization_attested=True,
        disclaimer_version="2026-07-27",
        profile=EnvironmentProfile.HTB,
        autonomy=AutonomyMode.CONTROLLED,
        target=TargetSpec(host="BOX.HTB."),
        objectives=[Objective(kind="user_flag", description="Obtain user flag")],
    )
    assert draft.target.host == "box.htb"
    assert canonical_digest(draft) == canonical_digest(
        EngagementDraft.model_validate(draft.model_dump())
    )


def test_draft_is_frozen() -> None:
    draft = EngagementDraft(
        authorization_attested=True,
        disclaimer_version="2026-07-27",
        profile=EnvironmentProfile.HTB,
        autonomy=AutonomyMode.CONTROLLED,
        target=TargetSpec(host="10.10.10.1"),
        objectives=[Objective(kind="user_flag", description="Get flag")],
    )
    with pytest.raises(ValidationError):
        draft.authorization_attested = False  # type: ignore[misc]


def test_draft_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        EngagementDraft(
            authorization_attested=True,
            disclaimer_version="2026-07-27",
            profile=EnvironmentProfile.HTB,
            autonomy=AutonomyMode.CONTROLLED,
            target=TargetSpec(host="10.10.10.1"),
            objectives=[Objective(kind="user_flag", description="x")],
            extra_field="should_fail",  # type: ignore[call-arg]
        )


def test_draft_requires_at_least_one_objective() -> None:
    with pytest.raises(ValidationError):
        EngagementDraft(
            authorization_attested=True,
            disclaimer_version="2026-07-27",
            profile=EnvironmentProfile.HTB,
            autonomy=AutonomyMode.CONTROLLED,
            target=TargetSpec(host="10.10.10.1"),
            objectives=[],
        )


# ── canonical_digest ───────────────────────────────────────────────────────


def test_canonical_digest_is_deterministic() -> None:
    a = TargetSpec(host="10.10.10.1")
    b = TargetSpec(host="10.10.10.1")
    assert canonical_digest(a) == canonical_digest(b)


def test_canonical_digest_differs_for_different_values() -> None:
    a = TargetSpec(host="10.10.10.1")
    b = TargetSpec(host="10.10.10.2")
    assert canonical_digest(a) != canonical_digest(b)


def test_canonical_digest_is_sha256_hex() -> None:
    digest = canonical_digest(TargetSpec(host="10.10.10.1"))
    assert re.fullmatch(r"[0-9a-f]{64}", digest), f"Not a 64-char hex digest: {digest}"


# ── Remaining Task 2 model existence ───────────────────────────────────────

from ariadne.core.engagement import EngagementSnapshot  # noqa: E402
from ariadne.core.findings import Finding  # noqa: E402
from ariadne.core.observations import Asset, Hypothesis, Observation  # noqa: E402
from ariadne.core.planning import ActionPlan  # noqa: E402


def test_engagement_snapshot_structure() -> None:
    """Verify EngagementSnapshot has the required fields."""
    snap = EngagementSnapshot(
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        revision=1,
        previous_snapshot_hash=None,
        snapshot_hash="abc123",
        confirmed_at="2026-07-27T00:00:00Z",
        authorization_attested=True,
        disclaimer_version="2026-07-27",
        profile=EnvironmentProfile.HTB,
        autonomy=AutonomyMode.CONTROLLED,
        targets=(TargetSpec(host="10.10.10.1"),),
        objectives=(Objective(kind="user_flag", description="Flag"),),
    )
    assert snap.revision == 1
    assert snap.targets[0].host == "10.10.10.1"


def test_action_plan_structure() -> None:
    """Verify ActionPlan has the required fields."""
    plan = ActionPlan(
        plan_id=UUID("00000000-0000-0000-0000-000000000002"),
        snapshot_hash="abc123",
        target=TargetSpec(host="10.10.10.1"),
        hypothesis="Open SSH port",
        actions=[],
        expected_evidence=[],
        stop_conditions=[],
        expires_at="2026-07-27T01:00:00Z",
    )
    assert plan.plan_id is not None
    assert plan.snapshot_hash == "abc123"


def test_observation_structure() -> None:
    obs = Observation(
        observation_id=UUID("00000000-0000-0000-0000-000000000003"),
        target=TargetSpec(host="10.10.10.1"),
        source="nmap",
        data={"port": 22, "service": "ssh"},
    )
    assert obs.source == "nmap"
    assert obs.data["port"] == 22


def test_asset_structure() -> None:
    asset = Asset(
        asset_id=UUID("00000000-0000-0000-0000-000000000004"),
        target=TargetSpec(host="10.10.10.1"),
        status=AssetStatus.IN_SCOPE,
    )
    assert asset.status == AssetStatus.IN_SCOPE


def test_hypothesis_structure() -> None:
    hyp = Hypothesis(
        hypothesis_id=UUID("00000000-0000-0000-0000-000000000005"),
        target=TargetSpec(host="10.10.10.1"),
        statement="SSH is running with default credentials",
        confidence=0.8,
    )
    assert hyp.statement == "SSH is running with default credentials"
    assert hyp.confidence == 0.8


def test_finding_structure() -> None:
    finding = Finding(
        finding_id=UUID("00000000-0000-0000-0000-000000000006"),
        target=TargetSpec(host="10.10.10.1"),
        title="Default SSH credentials",
        severity="high",
        status=FindingStatus.VALIDATED,
        description="SSH accepts root:toor",
        evidence=[],
    )
    assert finding.severity == "high"
    assert finding.status == FindingStatus.VALIDATED
