"""Task 4: HTB-specific policy denial contract tests."""

from pathlib import Path

import pytest
import yaml

from ariadne.core.policy import (
    ActionRequest,
    EffectivePolicy,
    PolicyDocument,
    authorize,
    intersect_policies,
    load_policy,
)

# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def htb_yaml() -> dict:
    """Load the HTB policy YAML once per module."""
    p = Path(__file__).parents[2] / "policies" / "htb.yaml"
    with open(p) as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="module")
def base_yaml() -> dict:
    """Load the base policy YAML once per module."""
    p = Path(__file__).parents[2] / "policies" / "base.yaml"
    with open(p) as f:
        return yaml.safe_load(f)


@pytest.fixture
def htb_policy() -> PolicyDocument:
    """Load the HTB policy as a PolicyDocument."""
    p = Path(__file__).parents[2] / "policies" / "htb.yaml"
    return load_policy(p)


@pytest.fixture
def base_policy() -> PolicyDocument:
    """Load the base policy as a PolicyDocument."""
    p = Path(__file__).parents[2] / "policies" / "base.yaml"
    return load_policy(p)


@pytest.fixture
def effective_htb(htb_policy: PolicyDocument, base_policy: PolicyDocument) -> EffectivePolicy:
    """Intersection of base and HTB policies (the effective HTB policy)."""
    result = intersect_policies(base_policy, htb_policy)
    assert isinstance(result, EffectivePolicy)
    return result


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


# ── HTB denies resource stress ──────────────────────────────────────────────


class TestHtbDeniesResourceStress:
    """HTB policy must deny all forms of resource stress and DoS."""

    def test_htb_denies_resource_stress(self, effective_htb) -> None:
        """resource.stress is explicitly forbidden under HTB."""
        decision = authorize(effective_htb, make_request(capability="resource.stress"))
        assert not decision.allowed, "HTB must deny resource.stress"

    def test_htb_denies_resource_exhaustion(self, effective_htb) -> None:
        """Related DoS capabilities must also be denied."""
        decision = authorize(effective_htb, make_request(capability="resource.exhaustion"))
        assert not decision.allowed, "HTB must deny resource.exhaustion"

    def test_htb_denies_resource_stress_regardless_of_request(self, effective_htb) -> None:
        """Even a minimal resource.stress request must be denied."""
        decision = authorize(
            effective_htb,
            make_request(capability="resource.stress", rate=1, concurrency=1),
        )
        assert not decision.allowed


# ── HTB denies subnet / CIDR scans ──────────────────────────────────────────


class TestHtbDeniesCidrScans:
    """HTB policy must deny scanning CIDR-style target ranges."""

    def test_htb_denies_cidr_targets(self, effective_htb) -> None:
        """scan.tcp against a /24 target must be denied."""
        decision = authorize(
            effective_htb,
            make_request(capability="scan.tcp", target="10.10.10.0/24"),
        )
        assert not decision.allowed, "HTB must deny subnet scanning"

    def test_htb_denies_scan_udp_cidr(self, effective_htb) -> None:
        """scan.udp against a CIDR target must be denied."""
        decision = authorize(
            effective_htb,
            make_request(capability="scan.udp", target="10.10.10.0/24"),
        )
        assert not decision.allowed

    def test_htb_allows_single_host_tcp_scan(self, effective_htb) -> None:
        """scan.tcp against a single explicit host should be allowed."""
        decision = authorize(
            effective_htb,
            make_request(capability="scan.tcp", target="10.10.10.1", attempts=1),
        )
        # This is expected to be allowed because the base allows it and HTB
        # doesn't explicitly restrict single-host scans
        assert decision.allowed


# ── Base invariants must persist through intersection ────────────────────────


class TestBaseInvariantsSurviveHtb:
    """Base invariants (persistence, C2, propagation) must remain denied."""

    @pytest.mark.parametrize(
        "bad_capability",
        [
            "persistence",
            "c2",
            "propagation",
            "host.install",
            "poc.uncurated",
        ],
    )
    def test_base_invariants_are_not_relaxed_by_htb(
        self, effective_htb, bad_capability: str
    ) -> None:
        """Capabilities forbidden by the base must remain forbidden."""
        decision = authorize(effective_htb, make_request(capability=bad_capability))
        assert not decision.allowed, (
            f"Base invariant '{bad_capability}' must remain denied under HTB"
        )


# ── YAML structure checks ───────────────────────────────────────────────────


class TestHtbYamlStructure:
    """Structural validation of the HTB policy YAML file."""

    def test_htb_yaml_has_required_fields(self, htb_yaml: dict) -> None:
        """The HTB policy must declare name, version, and capabilities."""
        assert "name" in htb_yaml
        assert "version" in htb_yaml
        assert "capabilities" in htb_yaml
        assert htb_yaml["name"] == "htb"

    def test_htb_yaml_resource_stress_is_forbidden(self, htb_yaml: dict) -> None:
        """resource.stress must be explicitly denied in HTB policy."""
        caps = htb_yaml.get("capabilities", {})
        stress = caps.get("resource.stress", {})
        assert stress.get("allowed") is False, "HTB must set resource.stress.allowed=false"

    def test_htb_yaml_resource_exhaustion_is_forbidden(self, htb_yaml: dict) -> None:
        """resource.exhaustion must be explicitly denied."""
        caps = htb_yaml.get("capabilities", {})
        exhaustion = caps.get("resource.exhaustion", {})
        assert exhaustion.get("allowed") is False


# ── Base YAML structure checks ──────────────────────────────────────────────


class TestBaseYamlStructure:
    """Structural validation of the base policy YAML file."""

    def test_base_yaml_has_required_fields(self, base_yaml: dict) -> None:
        assert "name" in base_yaml
        assert "version" in base_yaml
        assert "capabilities" in base_yaml
        assert base_yaml["name"] == "base"

    def test_base_yaml_persistence_is_forbidden(self, base_yaml: dict) -> None:
        caps = base_yaml.get("capabilities", {})
        cap = caps.get("persistence", {})
        assert cap.get("allowed") is False

    def test_base_yaml_c2_is_forbidden(self, base_yaml: dict) -> None:
        caps = base_yaml.get("capabilities", {})
        assert caps.get("c2", {}).get("allowed") is False

    def test_base_yaml_propagation_is_forbidden(self, base_yaml: dict) -> None:
        caps = base_yaml.get("capabilities", {})
        assert caps.get("propagation", {}).get("allowed") is False

    def test_base_yaml_host_install_requires_manual(self, base_yaml: dict) -> None:
        caps = base_yaml.get("capabilities", {})
        assert caps.get("host.install", {}).get("allowed") is True
        assert caps.get("host.install", {}).get("always_manual") is True

    def test_base_yaml_poc_uncurated_requires_manual(self, base_yaml: dict) -> None:
        caps = base_yaml.get("capabilities", {})
        assert caps.get("poc.uncurated", {}).get("allowed") is True
        assert caps.get("poc.uncurated", {}).get("always_manual") is True
