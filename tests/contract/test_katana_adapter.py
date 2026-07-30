from __future__ import annotations

from uuid import UUID

import pytest

from ariadne.adapters.base import (
    AdapterContext,
    AdapterError,
    PlannedAction,
    ProcessResult,
)
from ariadne.adapters.katana import KatanaAdapter
from ariadne.core.engagement import TargetSpec


def _context() -> AdapterContext:
    return AdapterContext(
        target=TargetSpec(host="192.0.2.10"),
        snapshot_hash="a" * 64,
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name="katana",
    )


def test_katana_builds_a_bounded_target_scoped_crawl_and_parses_endpoints() -> None:
    adapter = KatanaAdapter()
    spec = adapter.plan(
        PlannedAction(
            operation="crawl",
            inputs={
                "urls": ["http://192.0.2.10:80/"],
                "depth": 3,
                "duration_seconds": 60,
                "max_pages": 100,
            },
        ),
        _context(),
    )

    assert spec.argv[0] == "katana"
    assert spec.argv[spec.argv.index("-u") + 1] == "http://192.0.2.10:80/"
    assert spec.argv[spec.argv.index("-d") + 1] == "3"
    assert spec.argv[spec.argv.index("-ct") + 1] == "60s"
    assert spec.argv[spec.argv.index("-mdp") + 1] == "100"
    assert spec.argv[spec.argv.index("-kf") + 1] == "all"
    assert "-jsonl" in spec.argv
    assert "-duc" in spec.argv
    assert spec.timeout_seconds == 75

    observations = adapter.parse_for_target(
        ProcessResult(
            exit_code=0,
            stdout=(
                '{"request":{"method":"GET",'
                '"endpoint":"http://192.0.2.10:80/admin?tab=users"},'
                '"response":{"status_code":200}}\n'
                '{"request":{"method":"GET",'
                '"endpoint":"https://example.invalid/out-of-scope"}}\n'
            ),
            stderr="",
        ),
        TargetSpec(host="192.0.2.10"),
    )

    assert len(observations) == 1
    assert observations[0].source == "katana"
    assert observations[0].data["url"] == (
        "http://192.0.2.10:80/admin?tab=users"
    )
    assert observations[0].data["parameters"] == ("tab",)


def test_katana_rejects_an_out_of_scope_seed() -> None:
    with pytest.raises(AdapterError, match="scope"):
        KatanaAdapter().plan(
            PlannedAction(
                operation="crawl",
                inputs={"urls": ["https://example.invalid/"]},
            ),
            _context(),
        )


def test_katana_timeout_without_evidence_fails_instead_of_retrying() -> None:
    adapter = KatanaAdapter()

    empty = adapter.classify(
        ProcessResult(
            exit_code=-1,
            stdout="",
            stderr="",
            timed_out=True,
        ),
        (),
    )
    partial = adapter.classify(
        ProcessResult(
            exit_code=-1,
            stdout="",
            stderr="",
            timed_out=True,
        ),
        (
            adapter.parse_for_target(
                ProcessResult(
                    exit_code=0,
                    stdout=(
                        '{"request":{"method":"GET",'
                        '"endpoint":"http://192.0.2.10:80/capture"}}\n'
                    ),
                    stderr="",
                ),
                TargetSpec(host="192.0.2.10"),
            )[0],
        ),
    )

    assert empty.kind == "failure"
    assert partial.kind == "partial"
