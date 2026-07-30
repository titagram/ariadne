from __future__ import annotations

from uuid import UUID

import pytest

from ariadne.adapters.base import (
    AdapterContext,
    AdapterError,
    PlannedAction,
    ProcessResult,
)
from ariadne.adapters.curl import CurlAdapter
from ariadne.core.engagement import TargetSpec


def _context() -> AdapterContext:
    return AdapterContext(
        target=TargetSpec(host="192.0.2.10"),
        snapshot_hash="b" * 64,
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name="curl",
    )


def test_curl_fetch_is_target_bound_and_extracts_same_host_links() -> None:
    adapter = CurlAdapter()
    spec = adapter.plan(
        PlannedAction(
            operation="fetch",
            inputs={"url": "http://192.0.2.10:80/"},
        ),
        _context(),
    )
    assert spec.argv[0] == "curl"
    assert spec.argv[-2:] == ("--url", "http://192.0.2.10:80/")
    assert "--location" not in spec.argv

    observations = adapter.parse_for_spec(
        ProcessResult(
            exit_code=0,
            stdout=(
                '<html><a href="/admin?tab=users">Admin</a>'
                '<script src="/static/app.js"></script>'
                '<a href="https://example.invalid/">External</a></html>'
            ),
            stderr="",
        ),
        TargetSpec(host="192.0.2.10"),
        spec,
    )

    assert {item.data["url"] for item in observations} == {
        "http://192.0.2.10:80/",
        "http://192.0.2.10:80/admin?tab=users",
        "http://192.0.2.10:80/static/app.js",
    }


def test_curl_fetch_rejects_an_out_of_scope_url() -> None:
    with pytest.raises(AdapterError, match="scope"):
        CurlAdapter().plan(
            PlannedAction(
                operation="fetch",
                inputs={"url": "https://example.invalid/"},
            ),
            _context(),
        )
