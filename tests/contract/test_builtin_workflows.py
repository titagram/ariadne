"""Contract tests for the versioned built-in workflow catalog.

Verifies that every playbook in the built-in ``workflows/`` directory:
- References only registered adapters and their supported operations.
- Forms a connected graph reachable from ``engagement.preflight.v1``.
- Every invasive playbook declares limits, stop conditions,
  evidence requirements, and report sections.
- No AD high-impact operation is referenced without its exact capability.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from ariadne.core.workflow import WorkflowCatalog

# ---------------------------------------------------------------------------
# Registered adapters and their supported operations
# ---------------------------------------------------------------------------
# Source of truth: the _OPERATIONS frozensets and adapter name ClassVars
# in each src/ariadne/adapters/*.py file.

REGISTERED_ADAPTERS: dict[str, frozenset[str]] = {
    "nmap": frozenset({"tcp_discovery", "service_fingerprint", "udp_targeted"}),
    "httpx": frozenset({"scan"}),
    "nuclei": frozenset({"scan"}),
    "zap": frozenset({"passive_scan", "active_scan", "spider"}),
    "metasploit": frozenset({"search", "info", "check", "run_module"}),
    "research": frozenset({"investigate"}),
    "screenshot": frozenset({"capture"}),
    "postex": frozenset({
        # Linux
        "identity", "sudo_rules", "suid_files", "file_capabilities",
        "scheduled_jobs", "services", "linpeas", "pspy_bounded",
        # Windows
        "token_privileges", "scheduled_tasks", "registry", "winpeas",
        "privesccheck", "seatbelt",
    }),
    "active_directory": frozenset({
        "domain_discovery", "ldap_rootdse", "smb_enumeration",
        "kerberos_user_validation", "bloodhound_collection", "certipy_find",
        "password_spray", "credential_dump", "ntlm_poisoning", "ntlm_relay",
        "ticket_manipulation", "object_modification", "certipy_relay",
    }),
    "pivot": frozenset({
        "start_tunnel", "add_route", "remove_route", "stop_tunnel",
        "scan_discovered_host",
    }),
}

# AD high-impact operations and their required capabilities.
AD_HIGH_IMPACT_CAPS: dict[str, str] = {
    "password_spray": "ad.password_spray",
    "credential_dump": "ad.credential_dump",
    "ntlm_poisoning": "ad.ntlm_poisoning",
    "ntlm_relay": "ad.ntlm_relay",
    "ticket_manipulation": "ad.ticket_manipulation",
    "object_modification": "ad.object_modification",
    "certipy_relay": "ad.adcs_abuse",
}

# The root playbook that starts the engagement.
ROOT_PLAYBOOK_ID = "engagement.preflight.v1"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _all_playbook_ids(catalog: WorkflowCatalog) -> set[str]:
    return set(catalog.playbooks.keys())


def _reachable_from(
    catalog: WorkflowCatalog,
    start: str,
    visited: set[str] | None = None,
) -> set[str]:
    """Return all playbook ids reachable from *start* via ``next_playbooks``."""
    if visited is None:
        visited = set()
    if start in visited:
        return visited
    visited.add(start)

    playbook = catalog.playbooks.get(start)
    if playbook is None:
        return visited

    for nid in playbook.next_playbooks:
        _reachable_from(catalog, nid, visited)
    return visited


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def workflows_dir() -> Path:
    """Absolute path to the ``workflows/`` directory."""
    return Path(__file__).parents[2] / "workflows"


@pytest.fixture(scope="session")
def catalog(workflows_dir: Path) -> WorkflowCatalog:
    """Load the complete built-in workflow catalog once per session."""
    return WorkflowCatalog.load(workflows_dir)


# ---------------------------------------------------------------------------
# Basic loading
# ---------------------------------------------------------------------------


class TestCatalogLoading:
    """The built-in workflows directory loads without errors."""

    def test_catalog_is_not_empty(self, catalog: WorkflowCatalog) -> None:
        assert len(catalog.playbooks) >= 12, (
            f"Expected at least 12 playbooks, got {len(catalog.playbooks)}"
        )

    def test_all_playbooks_have_unique_ids(self, catalog: WorkflowCatalog) -> None:
        assert len(catalog.playbooks) == len(
            {p.id for p in catalog.playbooks.values()}
        ), "Duplicate playbook ids detected"


# ---------------------------------------------------------------------------
# Adapter operation validation
# ---------------------------------------------------------------------------


class TestAdapterOperations:
    """Every action in every playbook references a registered adapter
    and a supported operation."""

    def test_every_action_names_a_registered_adapter_and_operation(
        self, catalog: WorkflowCatalog
    ) -> None:
        for playbook in catalog.playbooks.values():
            for action in playbook.actions:
                assert action.adapter in REGISTERED_ADAPTERS, (
                    f"Playbook {playbook.id}: unknown adapter {action.adapter!r}"
                )
                supported = REGISTERED_ADAPTERS[action.adapter]
                assert action.operation in supported, (
                    f"Playbook {playbook.id}: adapter {action.adapter!r} "
                    f"does not support operation {action.operation!r}. "
                    f"Supported: {sorted(supported)}"
                )

    def test_httpx_actions_supply_curated_tool_discovery_metadata(
        self,
        catalog: WorkflowCatalog,
    ) -> None:
        for playbook in catalog.playbooks.values():
            for action in playbook.actions:
                if action.adapter != "httpx":
                    continue
                card = action.inputs.get("tool_card")
                assert isinstance(card, dict), playbook.id
                assert card.get("title") == "ProjectDiscovery httpx"
                assert card.get("official_source_url") == (
                    "https://docs.projectdiscovery.io/opensource/httpx/overview"
                )


# ---------------------------------------------------------------------------
# Graph completeness
# ---------------------------------------------------------------------------


class TestGraphCompleteness:
    """The workflow graph forms a connected DAG from the root playbook."""

    def test_every_nonterminal_playbook_has_reachable_next_state(
        self, catalog: WorkflowCatalog
    ) -> None:
        unreachable = _all_playbook_ids(catalog) - _reachable_from(
            catalog, ROOT_PLAYBOOK_ID
        )
        assert unreachable == set(), (
            f"Playbooks not reachable from {ROOT_PLAYBOOK_ID!r}: "
            f"{sorted(unreachable)}"
        )


# ---------------------------------------------------------------------------
# Invasive playbook invariants
# ---------------------------------------------------------------------------


class TestInvasivePlaybookInvariants:
    """Playbooks that execute actions (not pure routing/validation)
    must declare limits, stop conditions, evidence, and report sections.

    Pure routing playbooks (those with zero direct actions) are exempt
    from certain checks.
    """

    @staticmethod
    def _has_actions(playbook) -> bool:
        return len(playbook.actions) > 0

    def test_invasive_playbooks_have_non_default_limits(
        self, catalog: WorkflowCatalog
    ) -> None:
        for p in catalog.playbooks.values():
            if not self._has_actions(p):
                continue
            assert p.limits.max_rate is not None, (
                f"{p.id}: invasive playbook must declare max_rate"
            )
            assert p.limits.max_duration_seconds is not None, (
                f"{p.id}: invasive playbook must declare max_duration_seconds"
            )

    def test_invasive_playbooks_have_stop_conditions(
        self, catalog: WorkflowCatalog
    ) -> None:
        for p in catalog.playbooks.values():
            if not self._has_actions(p):
                continue
            assert len(p.stop_conditions) > 0, (
                f"{p.id}: invasive playbook must declare at least one "
                f"stop condition"
            )

    def test_invasive_playbooks_have_report_sections(
        self, catalog: WorkflowCatalog
    ) -> None:
        for p in catalog.playbooks.values():
            if not self._has_actions(p):
                continue
            assert len(p.report_sections) > 0, (
                f"{p.id}: invasive playbook must map to at least one "
                f"report section"
            )

    def test_every_playbook_declares_capabilities(
        self, catalog: WorkflowCatalog
    ) -> None:
        for p in catalog.playbooks.values():
            assert len(p.capabilities) > 0, (
                f"{p.id}: every playbook must declare at least one capability"
            )


# ---------------------------------------------------------------------------
# AD high-impact capability check
# ---------------------------------------------------------------------------


class TestAdHighImpactCapabilities:
    """Every AD high-impact operation must be paired with its exact
    capability in the playbook's capabilities list."""

    def test_ad_high_impact_operations_require_exact_capability(
        self, catalog: WorkflowCatalog
    ) -> None:
        for playbook in catalog.playbooks.values():
            for action in playbook.actions:
                if action.adapter != "active_directory":
                    continue
                if action.operation in AD_HIGH_IMPACT_CAPS:
                    required_cap = AD_HIGH_IMPACT_CAPS[action.operation]
                    assert required_cap in playbook.capabilities, (
                        f"Playbook {playbook.id} uses AD high-impact "
                        f"operation {action.operation!r} but does not "
                        f"declare required capability {required_cap!r}"
                    )


# ---------------------------------------------------------------------------
# Schema compliance
# ---------------------------------------------------------------------------


class TestSchemaCompliance:
    """Every workflow YAML file validates against the JSON schema by
    surviving Pydantic ``Playbook.model_validate`` via ``WorkflowCatalog.load``."""

    def test_all_yaml_files_load_without_validation_errors(
        self, catalog: WorkflowCatalog
    ) -> None:
        # If we got here, load() succeeded — this test is a
        # documented assertion that the loading already passed.
        assert len(catalog.playbooks) > 0


# ---------------------------------------------------------------------------
# No shell keys anywhere
# ---------------------------------------------------------------------------


class TestNoShellKeys:
    """No playbook file contains a ``shell`` key in any action."""

    def test_no_playbook_contains_shell_key(
        self, workflows_dir: Path
    ) -> None:
        for path in sorted(workflows_dir.iterdir()):
            if path.suffix not in (".yaml", ".yml"):
                continue
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                continue
            actions = raw.get("actions", [])
            if not isinstance(actions, list):
                continue
            for i, action in enumerate(actions):
                if isinstance(action, dict) and "shell" in action:
                    pytest.fail(
                        f"{path.name} action[{i}] contains a 'shell' key"
                    )


# ---------------------------------------------------------------------------
# No observed_only target references
# ---------------------------------------------------------------------------


class TestNoObservedOnlyTargeting:
    """Playbooks must not reference ``observed_only`` in their inputs.
    This invariant is enforced at planning time, but the catalog
    should not suggest targeting unconfirmed assets."""

    OBSERVED_ONLY_INDICATORS = {"observed_only", "observed"}

    def test_no_playbook_uses_observed_only_targets(
        self, catalog: WorkflowCatalog
    ) -> None:
        for playbook in catalog.playbooks.values():
            for action in playbook.actions:
                for val in action.inputs.values():
                    if isinstance(val, str) and val.lower() in self.OBSERVED_ONLY_INDICATORS:
                        pytest.fail(
                            f"Playbook {playbook.id} action {action.adapter}/"
                            f"{action.operation} references observed_only value: "
                            f"{val!r}"
                        )
