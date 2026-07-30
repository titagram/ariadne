from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from ariadne.adapters.base import AdapterContext, PlannedAction
from ariadne.adapters.research import ResearchAdapter
from ariadne.core.engagement import TargetSpec
from ariadne.core.errors import AdapterPolicyError
from ariadne.core.workflow import PlaybookLimits
from ariadne.runtime.process import ProcessResult, ProcessStatus


class MissingRuntime:
    async def run(self, spec: object) -> ProcessResult:
        del spec
        raise FileNotFoundError("searchsploit")


class NoIcmpReplyRuntime:
    async def run(self, spec: object) -> ProcessResult:
        del spec
        return ProcessResult(
            exit_code=1,
            stdout=(
                "PING 10.10.10.10 (10.10.10.10): 56 data bytes\n\n"
                "--- 10.10.10.10 ping statistics ---\n"
                "1 packets transmitted, 0 packets received, 100.0% packet loss\n"
            ),
            stderr="",
        )


def _context() -> AdapterContext:
    return AdapterContext(
        target=TargetSpec(host="10.10.10.10"),
        snapshot_hash="a" * 64,
        engagement_id=uuid4(),
        adapter_name="research",
        run_root=Path("/tmp/ariadne-test"),
        cwd=Path("/tmp/ariadne-test"),
        limits=PlaybookLimits(
            max_rate=1,
            max_concurrency=1,
            max_attempts=1,
            max_duration_seconds=5,
            max_output_bytes=4096,
        ),
        capabilities=("preflight.check",),
        action_digest="b" * 64,
    )


def test_plan_consumes_context_limits_and_exact_ping_target() -> None:
    context = _context()
    spec = ResearchAdapter().plan(
        PlannedAction(
            operation="investigate",
            inputs={"product": "preflight"},
        ),
        context,
    )

    assert spec.argv == (
        "ping",
        "-c",
        "1",
        "-W",
        "3",
        "10.10.10.10",
    )
    assert spec.timeout_seconds == 5
    assert spec.max_output_bytes == 4096


def test_full_chain_requires_structured_service_evidence() -> None:
    with pytest.raises(AdapterPolicyError, match="missing evidence"):
        ResearchAdapter().plan(
            PlannedAction(operation="investigate", inputs={"full_chain": True}),
            _context(),
        )


@pytest.mark.asyncio
async def test_missing_searchsploit_is_failure_without_fake_evidence() -> None:
    adapter = ResearchAdapter()
    result = await adapter.execute(
        adapter.plan(
            PlannedAction(
                operation="investigate",
                inputs={"product": "OpenSSH 8.2"},
            ),
            _context(),
        ),
        MissingRuntime(),
    )

    observations = adapter.parse_for_target(
        result,
        TargetSpec(host="10.10.10.10"),
    )
    classification = adapter.classify(result, observations)

    assert result.exit_code != 0
    assert result.status == ProcessStatus.FAILED
    assert observations == ()
    assert classification.kind == "failure"


def test_parsed_observation_uses_explicit_context_target() -> None:
    adapter = ResearchAdapter()
    result = ProcessResult(
        exit_code=0,
        stdout="PING 10.10.10.10: round-trip min/avg/max = 1/1/1 ms",
        stderr="",
    )

    observations = adapter.parse_for_target(
        result,
        TargetSpec(host="10.10.10.10"),
    )

    assert len(observations) == 1
    assert observations[0].target.host == "10.10.10.10"


@pytest.mark.asyncio
async def test_preflight_icmp_no_reply_defers_reachability_to_tcp_discovery() -> None:
    adapter = ResearchAdapter()
    result = await adapter.execute(
        adapter.plan(
            PlannedAction(
                operation="investigate",
                inputs={"product": "preflight"},
            ),
            _context(),
        ),
        NoIcmpReplyRuntime(),
    )
    observations = adapter.parse_for_target(
        result,
        TargetSpec(host="10.10.10.10"),
    )

    assert result.exit_code == 0
    assert adapter.classify(result, observations).kind == "success"
    assert observations[0].source == "preflight_passed"
    assert observations[0].data["reachability"] == "icmp_inconclusive"
