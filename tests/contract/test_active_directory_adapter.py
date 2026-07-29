"""Contract tests for the ActiveDirectoryAdapter AD operations.

Verifies operation dispatch, command construction, output parsing, and
classification for Active Directory discovery operations: domain_discovery,
ldap_rootdse, smb_enumeration, kerberos_user_validation, bloodhound_collection,
and certipy_find.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from ariadne.adapters.active_directory import ActiveDirectoryAdapter
from ariadne.adapters.base import AdapterContext, PlannedAction
from ariadne.core.engagement import TargetSpec
from ariadne.core.errors import AdapterError, AdapterPolicyError
from ariadne.runtime.process import ProcessResult, ProcessStatus

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def adapter() -> ActiveDirectoryAdapter:
    return ActiveDirectoryAdapter()


def _ad_context(
    host: str = "192.168.1.10",
    extra_env: dict[str, str] | None = None,
) -> AdapterContext:
    env: dict[str, str] = {"TARGET_OS": "windows", "DOMAIN": "contoso.local"}
    if extra_env:
        env.update(extra_env)
    return AdapterContext(
        target=TargetSpec(host=host),
        snapshot_hash="abc123",
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name="active_directory",
        environment=env,
    )


@pytest.fixture
def ad_context() -> AdapterContext:
    return _ad_context()


def action(operation: str, **inputs: object) -> PlannedAction:
    return PlannedAction(operation=operation, inputs=inputs)


def load_fixture(name: str) -> str:
    """Load a fixture file from tests/fixtures/active_directory/."""
    path = Path(__file__).parent.parent / "fixtures" / "active_directory" / name
    return path.read_text()


# ── Plan (command building) ───────────────────────────────────────────────────


class TestActiveDirectoryPlan:
    """Verify that ActiveDirectoryAdapter.plan() builds correct ProcessSpec args."""

    def test_domain_discovery_plan(
        self, adapter: ActiveDirectoryAdapter, ad_context: AdapterContext
    ) -> None:
        spec = adapter.plan(action("domain_discovery"), ad_context)
        assert spec.argv == (
            "impacket-lookupsid",
            "-no-pass",
            "192.168.1.10",
            "500",
        )
        assert spec.timeout_seconds <= 60

    def test_ldap_rootdse_plan(
        self, adapter: ActiveDirectoryAdapter, ad_context: AdapterContext
    ) -> None:
        spec = adapter.plan(action("ldap_rootdse"), ad_context)
        argv_str = " ".join(spec.argv).lower()
        assert "ldapsearch" in argv_str or "rootdse" in argv_str
        assert spec.timeout_seconds <= 60

    def test_smb_enumeration_plan(
        self, adapter: ActiveDirectoryAdapter, ad_context: AdapterContext
    ) -> None:
        spec = adapter.plan(action("smb_enumeration"), ad_context)
        argv_str = " ".join(spec.argv).lower()
        assert "smbclient" in argv_str or "smb" in argv_str
        assert spec.timeout_seconds <= 60

    def test_kerberos_user_validation_plan(
        self, adapter: ActiveDirectoryAdapter, ad_context: AdapterContext
    ) -> None:
        spec = adapter.plan(action("kerberos_user_validation"), ad_context)
        assert spec.argv == (
            "impacket-GetNPUsers",
            "-no-pass",
            "-dc-ip",
            "192.168.1.10",
            "-usersfile",
            "/opt/tools/userlist.txt",
            "contoso.local/",
        )
        assert spec.timeout_seconds <= 300

    def test_bloodhound_collection_plan(
        self, adapter: ActiveDirectoryAdapter, ad_context: AdapterContext
    ) -> None:
        spec = adapter.plan(action("bloodhound_collection"), ad_context)
        argv_str = " ".join(spec.argv).lower()
        assert "bloodhound" in argv_str or "sharphound" in argv_str
        assert spec.timeout_seconds <= 600

    def test_certipy_find_plan(
        self, adapter: ActiveDirectoryAdapter, ad_context: AdapterContext
    ) -> None:
        spec = adapter.plan(action("certipy_find"), ad_context)
        assert spec.argv[:2] == ("certipy-ad", "find")
        assert spec.timeout_seconds <= 120

    def test_certipy_find_is_separate_from_abuse(
        self, adapter: ActiveDirectoryAdapter, ad_context: AdapterContext
    ) -> None:
        """Discovery-only certipy_find succeeds; high-impact certipy_relay is blocked."""
        find = adapter.plan(action("certipy_find"), ad_context)
        assert "find" in find.argv
        with pytest.raises(AdapterPolicyError, match="capability|abuse|adcs_abuse"):
            adapter.plan(action("certipy_relay"), ad_context)

    def test_unknown_operation_raises(
        self, adapter: ActiveDirectoryAdapter, ad_context: AdapterContext
    ) -> None:
        with pytest.raises(AdapterError, match="unknown|invalid|supported"):
            adapter.plan(action("invalid_operation"), ad_context)

    def test_discovery_operations_set_bounded_limits(
        self, adapter: ActiveDirectoryAdapter, ad_context: AdapterContext
    ) -> None:
        for op in ("domain_discovery", "ldap_rootdse", "smb_enumeration"):
            spec = adapter.plan(action(op), ad_context)
            assert 1 <= spec.timeout_seconds <= 3600
            assert spec.max_output_bytes >= 1024


# ── Parse ─────────────────────────────────────────────────────────────────────


class TestActiveDirectoryParse:
    """Verify that ActiveDirectoryAdapter.parse() extracts observations."""

    def test_parse_empty_output(self, adapter: ActiveDirectoryAdapter) -> None:
        result = ProcessResult(exit_code=0, stdout="", stderr="")
        obs = adapter.parse(result)
        assert obs == ()

    def test_parse_domain_discovery(self, adapter: ActiveDirectoryAdapter) -> None:
        result = ProcessResult(
            exit_code=0, stdout=load_fixture("domain_discovery_output.txt"), stderr=""
        )
        obs = adapter.parse(result)
        assert len(obs) >= 1
        assert obs[0].source == "active_directory"

    def test_parse_ldap_rootdse(self, adapter: ActiveDirectoryAdapter) -> None:
        result = ProcessResult(
            exit_code=0, stdout=load_fixture("ldap_rootdse_output.txt"), stderr=""
        )
        obs = adapter.parse(result)
        assert len(obs) >= 1

    def test_parse_smb_enumeration(self, adapter: ActiveDirectoryAdapter) -> None:
        result = ProcessResult(
            exit_code=0, stdout=load_fixture("smb_enumeration_output.txt"), stderr=""
        )
        obs = adapter.parse(result)
        assert len(obs) >= 1

    def test_parse_kerberos_user_validation(
        self, adapter: ActiveDirectoryAdapter
    ) -> None:
        result = ProcessResult(
            exit_code=0,
            stdout=load_fixture("kerberos_user_validation_output.txt"),
            stderr="",
        )
        obs = adapter.parse(result)
        assert len(obs) >= 1

    def test_parse_bloodhound_collection(
        self, adapter: ActiveDirectoryAdapter
    ) -> None:
        result = ProcessResult(
            exit_code=0,
            stdout=load_fixture("bloodhound_collection_output.txt"),
            stderr="",
        )
        obs = adapter.parse(result)
        assert len(obs) >= 1

    def test_parse_certipy_find(self, adapter: ActiveDirectoryAdapter) -> None:
        result = ProcessResult(
            exit_code=0,
            stdout=load_fixture("certipy_find_output.txt"),
            stderr="",
        )
        obs = adapter.parse(result)
        assert len(obs) >= 1


# ── Classify ──────────────────────────────────────────────────────────────────


class TestActiveDirectoryClassify:
    """Verify ActiveDirectoryAdapter.classify() returns appropriate results."""

    def test_completed_classification(
        self, adapter: ActiveDirectoryAdapter
    ) -> None:
        result = ProcessResult(exit_code=0, stdout="domain info\n", stderr="")
        obs = adapter.parse(result)
        classification = adapter.classify(result, obs)
        assert classification.kind in ("success", "unknown")

    def test_timeout_classification(
        self, adapter: ActiveDirectoryAdapter
    ) -> None:
        result = ProcessResult(
            exit_code=-1,
            stdout="",
            stderr="",
            status=ProcessStatus.TIMED_OUT,
            timed_out=True,
        )
        classification = adapter.classify(result, ())
        assert classification.kind == "partial"

    def test_failed_execution(self, adapter: ActiveDirectoryAdapter) -> None:
        result = ProcessResult(exit_code=1, stdout="", stderr="access denied")
        classification = adapter.classify(result, ())
        assert classification.kind == "failure"


# ── Protocol shape ────────────────────────────────────────────────────────────


class TestActiveDirectoryProtocol:
    """Verify ActiveDirectoryAdapter satisfies the ToolAdapter protocol."""

    def test_has_name(self, adapter: ActiveDirectoryAdapter) -> None:
        assert ActiveDirectoryAdapter.name == "active_directory"

    def test_is_tool_adapter(self, adapter: ActiveDirectoryAdapter) -> None:
        from ariadne.adapters.base import ToolAdapter

        assert isinstance(adapter, ToolAdapter)

    def test_probe_returns_available(
        self, adapter: ActiveDirectoryAdapter
    ) -> None:
        from ariadne.adapters.base import Runtime

        class _MinimalRuntime(Runtime):
            async def run(self, spec: object) -> ProcessResult:
                return ProcessResult(exit_code=0, stdout="", stderr="")

        import asyncio

        result = asyncio.run(adapter.probe(_MinimalRuntime()))
        assert result.available

    def test_cleanup_returns_success(
        self, adapter: ActiveDirectoryAdapter
    ) -> None:
        import asyncio

        ctx = _ad_context()
        cleanup = asyncio.run(adapter.cleanup(ctx))
        assert cleanup.success
