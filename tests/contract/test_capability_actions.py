"""Contract tests for Ariadne's playbook-independent capability bridge."""

from __future__ import annotations

import pytest

from ariadne.adapters import build_default_registry
from ariadne.hades_adapter.guard_hook import ARIADNE_TOOLS as GUARDED_ARIADNE_TOOLS
from ariadne.hades_adapter.handlers import handle_execute_action, handle_list_capabilities
from ariadne.hades_adapter.schemas import ARIADNE_TOOLS


@pytest.mark.asyncio
async def test_list_capabilities_exposes_registered_curated_operations() -> None:
    """The capability inventory is derived from real adapters and contracts."""
    result = await handle_list_capabilities(
        {},
        adapter_registry=build_default_registry(),
    )

    assert result["status"] == "ok"
    tcp_discovery = next(
        item
        for item in result["capabilities"]
        if item["capability"] == "scan.tcp"
        and item["adapter"] == "nmap"
        and item["operation"] == "tcp_discovery"
    )
    assert tcp_discovery["runtime"] == "local_or_kali"
    assert tcp_discovery["tool_card_id"] == "tool.nmap"
    assert tcp_discovery["runtime_verified"] is True
    assert tcp_discovery["required_inputs"] == ["ports"]
    assert "port_open" in tcp_discovery["expected_evidence"]
    assert "target_must_match_snapshot" in tcp_discovery["hard_constraints"]
    assert "ariadne_list_capabilities" in ARIADNE_TOOLS
    assert "ariadne_execute_action" in ARIADNE_TOOLS


@pytest.mark.asyncio
async def test_execute_action_rejects_raw_shell_before_engagement_lookup() -> None:
    result = await handle_execute_action({"shell": "echo unsafe"})

    assert result["status"] == "error"
    assert "Raw execution fields" in result["message"]
    assert "ariadne_list_capabilities" in GUARDED_ARIADNE_TOOLS
    assert "ariadne_execute_action" in GUARDED_ARIADNE_TOOLS
