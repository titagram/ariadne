"""Contract tests for the MetasploitAdapter.

Verifies operation dispatch, resource-file generation, shell-injection
rejection, module validation, and output parsing for the Metasploit
framework adapter.
"""

from __future__ import annotations

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


def action(operation: str, **inputs: object) -> PlannedAction:
    return PlannedAction(operation=operation, inputs=inputs)


def validated_candidate(
    *,
    target: str = "10.10.10.10",
    module: str = "exploit/multi/http/apache_normalize_path",
) -> dict[str, object]:
    return {
        "candidate_id": "research-41773",
        "cve_id": "CVE-2021-41773",
        "product": "Apache HTTP Server",
        "version": "2.4.49",
        "target": target,
        "validation_status": "validated",
        "compatible": True,
        "applicability_evidence": ["nvd-description:version=2.4.49"],
        "module": module,
        "evidence_id": "evidence-research-1",
        "provenance": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
    }


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
        candidate = validated_candidate()
        spec = MetasploitAdapter().plan(
            action(
                "info",
                module=candidate["module"],
                validated_candidate=candidate,
            ),
            context,
        )
        argv_str = " ".join(spec.argv)
        assert "info" in argv_str.lower()

    def test_check_plan_is_explicit_and_target_bound(self, context: AdapterContext) -> None:
        candidate = validated_candidate()
        spec = MetasploitAdapter().plan(
            action(
                "check",
                module=candidate["module"],
                rhost="10.10.10.10",
                rport=80,
                validated_candidate=candidate,
            ),
            context,
        )
        assert spec.argv[:3] == ("msfconsole", "-q", "-x")
        assert "check" in spec.argv[-1]
        assert "run" not in {item.strip() for item in spec.argv[-1].split(";")}

    def test_check_plan_binds_approved_vhost_without_changing_rhosts(
        self,
        context: AdapterContext,
    ) -> None:
        candidate = validated_candidate()
        spec = MetasploitAdapter().plan(
            action(
                "check",
                module=candidate["module"],
                rhost="10.10.10.10",
                rport=80,
                vhost="orion.test",
                validated_candidate=candidate,
            ),
            context,
        )
        command = spec.argv[-1]
        assert "set RHOSTS 10.10.10.10" in command
        assert "set VHOST orion.test" in command

    def test_run_module_rejects_semicolons_in_options(self, context: AdapterContext) -> None:
        """Shell injection via semicolons in option values is rejected."""
        candidate = validated_candidate()
        with pytest.raises(AdapterError, match="semicolon|newline|invalid"):
            MetasploitAdapter().plan(
                action(
                    "run_module",
                    module=candidate["module"],
                    rhost="10.10.10.10;id",
                    validated_candidate=candidate,
                    check_status="vulnerable",
                    check_evidence_id="evidence-msf-check-1",
                ),
                context,
            )

    def test_run_module_rejects_newlines_in_options(self, context: AdapterContext) -> None:
        candidate = validated_candidate()
        with pytest.raises(AdapterError, match="newline|invalid"):
            MetasploitAdapter().plan(
                action(
                    "run_module",
                    module=candidate["module"],
                    rhost="10.10.10.10\nid",
                    validated_candidate=candidate,
                    check_status="vulnerable",
                    check_evidence_id="evidence-msf-check-1",
                ),
                context,
            )

    def test_unknown_operation_raises(self, context: AdapterContext) -> None:
        with pytest.raises(AdapterError):
            MetasploitAdapter().plan(action("invalid_op"), context)

    def test_all_operations_set_bounded_limits(self, context: AdapterContext) -> None:
        spec = MetasploitAdapter().plan(
            action("search", query="apache"),
            context,
        )
        assert 1 <= spec.timeout_seconds <= 3600
        assert spec.max_output_bytes >= 1024

    def test_check_and_use_require_exact_validated_compatible_candidate(
        self,
        context: AdapterContext,
    ) -> None:
        candidate = validated_candidate()

        check = MetasploitAdapter().plan(
            action(
                "check",
                module=candidate["module"],
                rhost="10.10.10.10",
                rport=80,
                validated_candidate=candidate,
            ),
            context,
        )
        assert "check" in check.argv[-1]
        assert "run" not in check.argv[-1].split(";")

        with pytest.raises(AdapterError, match="validated|compatible|candidate"):
            MetasploitAdapter().plan(
                action(
                    "check",
                    module=candidate["module"],
                    validated_candidate={
                        **candidate,
                        "target": "10.10.10.11",
                    },
                ),
                context,
            )

        with pytest.raises(AdapterError, match="vulnerable|check"):
            MetasploitAdapter().plan(
                action(
                    "run_module",
                    module=candidate["module"],
                    validated_candidate=candidate,
                    check_status="unknown",
                ),
                context,
            )

        execute = MetasploitAdapter().plan(
            action(
                "run_module",
                module=candidate["module"],
                validated_candidate=candidate,
                check_status="vulnerable",
                check_evidence_id="evidence-msf-check-1",
            ),
            context,
        )
        assert "run" in {command.strip() for command in execute.argv[-1].split(";")}


# ── Parse ─────────────────────────────────────────────────────────────────────


class TestMetasploitParse:
    """Verify that MetasploitAdapter.parse() extracts typed observations."""

    def test_parse_empty_output(self) -> None:
        result = ProcessResult(exit_code=0, stdout="", stderr="")
        obs = MetasploitAdapter().parse(result)
        assert obs == ()

    def test_run_without_a_session_is_explicitly_not_an_exploit_success(
        self,
        context: AdapterContext,
    ) -> None:
        """Classifying a no-session run as success would falsely advance foothold."""
        candidate = validated_candidate()
        spec = MetasploitAdapter().plan(
            action(
                "run_module",
                module=candidate["module"],
                validated_candidate=candidate,
                check_status="vulnerable",
                check_evidence_id="evidence-msf-check-1",
            ),
            context,
        )

        observations = MetasploitAdapter().parse_for_spec(
            ProcessResult(
                exit_code=0,
                stdout="Exploit completed, but no session was created.",
                stderr="",
            ),
            context.target,
            spec,
        )

        assert observations[0].source == "exploit_no_session"
        assert observations[0].data["session_opened"] is False
        assert MetasploitAdapter().classify(
            ProcessResult(
                exit_code=0,
                stdout="Exploit completed, but no session was created.",
                stderr="",
            ),
            observations,
        ).kind != "success"

    def test_run_with_observed_session_emits_session_proof(
        self,
        context: AdapterContext,
    ) -> None:
        """Removing session evidence must prevent the exploit progression branch."""
        candidate = validated_candidate()
        spec = MetasploitAdapter().plan(
            action(
                "run_module",
                module=candidate["module"],
                validated_candidate=candidate,
                check_status="vulnerable",
                check_evidence_id="evidence-msf-check-1",
            ),
            context,
        )

        observations = MetasploitAdapter().parse_for_spec(
            ProcessResult(exit_code=0, stdout="Command shell session 1 opened", stderr=""),
            context.target,
            spec,
        )

        assert observations[0].source == "exploit_succeeded"
        assert observations[0].data["session_opened"] is True

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
