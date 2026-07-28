"""Contract tests for the MetasploitAdapter.

Verifies operation dispatch, resource-file generation, shell-injection
rejection, module validation, and output parsing for the Metasploit
framework adapter.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from ariadne.adapters.base import (
    AdapterContext,
    PlannedAction,
)
from ariadne.adapters.metasploit import MetasploitAdapter
from ariadne.core.engagement import TargetSpec
from ariadne.core.errors import AdapterError
from ariadne.runtime.process import ProcessResult, ProcessStatus

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def context() -> AdapterContext:
    return AdapterContext(
        target=TargetSpec(host="10.10.10.10"),
        snapshot_hash="abc123",
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name="metasploit",
    )


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    d = tmp_path / "run"
    d.mkdir(parents=True)
    return d


def action(operation: str, **inputs: object) -> PlannedAction:
    return PlannedAction(operation=operation, inputs=inputs)


# ── Plan (command building) ───────────────────────────────────────────────────


class TestMetasploitPlan:
    """Verify that MetasploitAdapter.plan() builds correct ProcessSpec args."""

    def test_search_plan_includes_query(self, context: AdapterContext) -> None:
        spec = MetasploitAdapter().plan(
            action("search", query="apache 2.4.41"),
            context,
        )
        argv_str = " ".join(spec.argv)
        assert "msfconsole" in argv_str
        assert "search" in argv_str.lower()

    def test_info_plan_includes_module(self, context: AdapterContext) -> None:
        spec = MetasploitAdapter().plan(
            action("info", module="exploit/multi/http/apache_mod_cgi_bash_env_exec"),
            context,
        )
        argv_str = " ".join(spec.argv)
        assert "info" in argv_str.lower()

    def test_check_plan_uses_resource_file(
        self, context: AdapterContext, run_dir: Path
    ) -> None:
        spec = MetasploitAdapter().plan(
            action(
                "check",
                module="exploit/multi/http/apache_mod_cgi_bash_env_exec",
                rhost="10.10.10.10",
                rport=80,
                run_dir=str(run_dir),
            ),
            context,
        )
        assert "-r" in spec.argv or "-q" in spec.argv
        # Resource file path should be inside run_dir
        resource_arg = spec.argv[spec.argv.index("-r") + 1] if "-r" in spec.argv else ""
        assert resource_arg
        assert resource_arg.startswith(str(run_dir))

    def test_run_module_requires_run_dir(
        self, context: AdapterContext
    ) -> None:
        """run_module without a run_dir raises."""
        with pytest.raises(AdapterError, match="run_dir"):
            MetasploitAdapter().plan(
                action(
                    "run_module",
                    module="exploit/multi/http/apache_mod_cgi_bash_env_exec",
                    rhost="10.10.10.10",
                    rport=80,
                ),
                context,
            )

    def test_run_module_rejects_semicolons_in_options(
        self, context: AdapterContext, run_dir: Path
    ) -> None:
        """Shell injection via semicolons in option values is rejected."""
        with pytest.raises(AdapterError, match="semicolon|newline|invalid"):
            MetasploitAdapter().plan(
                action(
                    "run_module",
                    module="exploit/multi/http/apache_mod_cgi_bash_env_exec",
                    rhost="10.10.10.10;id",
                    run_dir=str(run_dir),
                ),
                context,
            )

    def test_run_module_rejects_newlines_in_options(
        self, context: AdapterContext, run_dir: Path
    ) -> None:
        with pytest.raises(AdapterError, match="newline|invalid"):
            MetasploitAdapter().plan(
                action(
                    "run_module",
                    module="exploit/multi/http/apache_mod_cgi_bash_env_exec",
                    rhost="10.10.10.10\nid",
                    run_dir=str(run_dir),
                ),
                context,
            )

    def test_run_module_rejects_outside_run_dir(
        self, context: AdapterContext, tmp_path: Path
    ) -> None:
        """A resource-file path outside the allowed run directory is rejected."""
        with pytest.raises(AdapterError, match="outside|run_dir"):
            MetasploitAdapter().plan(
                action(
                    "run_module",
                    module="exploit/multi/http/apache_mod_cgi_bash_env_exec",
                    rhost="10.10.10.10",
                    rport=80,
                    run_dir=str(tmp_path / "other"),
                ),
                context,
            )

    def test_unknown_operation_raises(
        self, context: AdapterContext
    ) -> None:
        with pytest.raises(AdapterError):
            MetasploitAdapter().plan(action("invalid_op"), context)

    def test_all_operations_set_bounded_limits(
        self, context: AdapterContext
    ) -> None:
        spec = MetasploitAdapter().plan(
            action("search", query="apache"),
            context,
        )
        assert 1 <= spec.timeout_seconds <= 3600
        assert spec.max_output_bytes >= 1024

        spec = MetasploitAdapter().plan(
            action("info", module="exploit/multi/http/apache_mod_cgi_bash_env_exec"),
            context,
        )
        assert 1 <= spec.timeout_seconds <= 3600
        assert spec.max_output_bytes >= 1024


# ── Parse ─────────────────────────────────────────────────────────────────────


class TestMetasploitParse:
    """Verify that MetasploitAdapter.parse() extracts typed observations."""

    def test_parse_empty_output(self) -> None:
        result = ProcessResult(exit_code=0, stdout="", stderr="")
        obs = MetasploitAdapter().parse(result)
        assert obs == ()

    def test_parse_search_results(self) -> None:
        stdout = (
            "\n"
            "   #  Name                                              "
            "Disclosure Date  Rank   Check  Description\n"
            "   -  ----                                              "
            "---------------  -----  -----  -----------\n"
            "   0  exploit/multi/http/struts2_multi                    "
            "2017-03-07       good   Yes    Apache Struts2 RCE\n"
            "   1  exploit/multi/http/struts2_content_type            "
            "                 normal Yes    Apache Struts2 Content-Type RCE\n"
            "\n"
        )
        result = ProcessResult(exit_code=0, stdout=stdout, stderr="")
        obs = MetasploitAdapter().parse(result)
        assert len(obs) >= 2
        assert obs[0].source == "metasploit"
        assert "struts2" in str(obs[0].data.get("module_path", "")).lower()

    def test_parse_info_output(self) -> None:
        stdout = (
            "       Name: Apache Struts 2 RCE\n"
            "     Module: exploit/multi/http/struts2_multi\n"
            "   Rank: excellent\n"
            "  Disclosure: 2017-03-07\n"
            " Provided by:\n"
            "   Some Researcher\n"
            " Available targets:\n"
            "   Id  Name\n"
            "   --  ----\n"
            "   0   Automatic\n"
        )
        result = ProcessResult(exit_code=0, stdout=stdout, stderr="")
        obs = MetasploitAdapter().parse(result)
        assert len(obs) >= 1
        assert obs[0].source == "metasploit"
        assert "struts" in str(obs[0].data.get("name", "")).lower()

    def test_parse_malformed_output_skips_gracefully(self) -> None:
        result = ProcessResult(exit_code=0, stdout="not useful at all\n", stderr="")
        obs = MetasploitAdapter().parse(result)
        # Should produce at most a single generic observation
        assert isinstance(obs, tuple)


# ── Classify ──────────────────────────────────────────────────────────────────


class TestMetasploitClassify:
    """Verify MetasploitAdapter.classify() returns appropriate classifications."""

    def test_completed_search(self) -> None:
        result = ProcessResult(exit_code=0, stdout="Matching Modules\n  0  exploit/\n", stderr="")
        obs = MetasploitAdapter().parse(result)
        classification = MetasploitAdapter().classify(result, obs)
        assert classification.kind in ("success", "unknown")

    def test_timeout_classification(self) -> None:
        result = ProcessResult(
            exit_code=-1,
            stdout="",
            stderr="",
            status=ProcessStatus.TIMED_OUT,
            timed_out=True,
        )
        classification = MetasploitAdapter().classify(result, ())
        assert classification.kind == "partial"

    def test_failed_execution(self) -> None:
        result = ProcessResult(exit_code=1, stdout="", stderr="error: module not found")
        classification = MetasploitAdapter().classify(result, ())
        assert classification.kind == "failure"


# ── Protocol shape ────────────────────────────────────────────────────────────


class TestMetasploitProtocol:
    """Verify MetasploitAdapter satisfies the ToolAdapter protocol."""

    def test_has_name(self) -> None:
        assert MetasploitAdapter.name == "metasploit"

    def test_is_tool_adapter(self) -> None:
        from ariadne.adapters.base import ToolAdapter

        assert isinstance(MetasploitAdapter(), ToolAdapter)

    def test_probe_returns_available(self) -> None:
        from ariadne.adapters.base import Runtime

        class _MinimalRuntime(Runtime):
            async def run(self, spec: object) -> ProcessResult:
                return ProcessResult(exit_code=0, stdout="", stderr="")

        probe = MetasploitAdapter().probe(_MinimalRuntime())
        import asyncio

        result = asyncio.run(probe)
        assert result.available
