"""Runtime policy loading and workflow coverage contracts."""

from pathlib import Path

import yaml

from ariadne.core.engagement import EngagementConstraints
from ariadne.core.enums import EnvironmentProfile
from ariadne.core.policy import (
    build_effective_policy,
    load_policy,
    materialize_profile,
)

ROOT = Path(__file__).parents[2]


def _workflow_capabilities() -> set[str]:
    capabilities: set[str] = set()
    for path in sorted((ROOT / "workflows").glob("*.yaml")):
        playbooks = yaml.safe_load(path.read_text(encoding="utf-8"))
        for playbook in playbooks:
            capabilities.update(playbook["capabilities"])
    return capabilities


def test_base_policy_declares_every_workflow_capability() -> None:
    """Adding a playbook capability without a base rule must fail coverage."""
    base = load_policy(ROOT / "policies" / "base.yaml")

    assert _workflow_capabilities() <= set(base.capabilities)


def test_profile_overlay_is_materialized_without_amplifying_base() -> None:
    """A permissive partial overlay must not raise the base scan bound."""
    base = load_policy(ROOT / "policies" / "base.yaml")
    overlay = load_policy(ROOT / "policies" / "private-lab.yaml")

    materialized = materialize_profile(base, overlay)
    effective = build_effective_policy(
        EnvironmentProfile.PRIVATE_LAB,
        EngagementConstraints(
            max_requests_per_second=30,
            max_concurrent_checks=4,
            max_duration_minutes=20,
        ),
        policy_dir=ROOT / "policies",
    )

    assert set(materialized.capabilities) == set(base.capabilities)
    assert effective.rule("scan.tcp").max_rate == 30
    assert effective.rule("scan.tcp").max_concurrency == 4
    assert effective.rule("scan.tcp").max_duration_seconds == 1200
    assert len(effective.source_digests) == 3
    assert all(effective.source_digests)


def test_htb_explicitly_denies_host_install_and_uncurated_poc() -> None:
    """Materialization must not turn omitted HTB exceptional capabilities on."""
    effective = build_effective_policy(
        EnvironmentProfile.HTB,
        EngagementConstraints(),
        policy_dir=ROOT / "policies",
    )

    assert effective.rule("host.install").allowed is False
    assert effective.rule("poc.uncurated").allowed is False


def test_high_impact_and_pivot_capabilities_are_always_manual() -> None:
    """Removing a manual marker would enable a full-mode authorization bypass."""
    effective = build_effective_policy(
        EnvironmentProfile.PRIVATE_LAB,
        EngagementConstraints(),
        policy_dir=ROOT / "policies",
    )
    manual = {
        "pivot.route",
        "pivot.scan",
        "pivot.tunnel",
        "ad.password_spray",
        "ad.ticket_manipulation",
        "ad.credential_dump",
        "ad.ntlm_poisoning",
        "ad.ntlm_relay",
        "ad.object_modification",
        "ad.adcs_abuse",
    }

    assert all(effective.rule(capability).always_manual for capability in manual)
