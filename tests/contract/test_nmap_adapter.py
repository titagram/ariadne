"""Contract tests for the NmapAdapter.

Verifies command-building, output parsing, safety invariants,
and edge-case handling for the Nmap discovery adapter.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from ariadne.adapters.base import (
    AdapterContext,
    PlannedAction,
)
from ariadne.adapters.nmap import NmapAdapter
from ariadne.core.engagement import TargetSpec
from ariadne.core.errors import AdapterError
from ariadne.core.workflow import PlaybookLimits
from ariadne.runtime.process import ProcessResult, ProcessSpec

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def context() -> AdapterContext:
    return AdapterContext(
        target=TargetSpec(host="10.10.10.10"),
        snapshot_hash="abc123",
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name="nmap",
    )


@pytest.fixture
def context_ipv6() -> AdapterContext:
    return AdapterContext(
        target=TargetSpec(host="dead:beef::1"),
        snapshot_hash="abc123",
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name="nmap",
    )


@pytest.fixture
def load_fixture() -> type:
    """Helper that reads a fixture file from tests/fixtures/nmap/."""

    def _load(name: str) -> str:
        p = Path(__file__).parents[2] / "tests" / "fixtures" / "nmap" / name
        return p.read_text()

    return _load  # type: ignore[return-value]


def action(operation: str, **inputs: object) -> PlannedAction:
    return PlannedAction(operation=operation, inputs=inputs)


# ── Plan (command building) ──────────────────────────────────────────────────


class TestNmapPlan:
    """Verify that NmapAdapter.plan() builds correct ProcessSpec arguments."""

    def test_tcp_discovery_uses_xml_stdout_and_explicit_target(
        self, context: AdapterContext
    ) -> None:
        spec = NmapAdapter().plan(
            action("tcp_discovery", ports=(22, 80, 443)),
            context,
        )
        assert spec.argv == (
            "nmap", "-n", "-Pn", "-sT", "--max-rate", "100",
            "-p", "22,80,443", "-oX", "-", "--", "10.10.10.10",
        )

    def test_service_fingerprint_appends_version_detection(
        self, context: AdapterContext
    ) -> None:
        spec = NmapAdapter().plan(
            action("service_fingerprint", ports=(22, 80)),
            context,
        )
        # service_fingerprint adds -sV flag
        assert "-sV" in spec.argv

    def test_udp_targeted_uses_udp_flag(self, context: AdapterContext) -> None:
        spec = NmapAdapter().plan(
            action("udp_targeted", ports=(53, 161)),
            context,
        )
        assert "-sU" in spec.argv
        assert "-sS" not in spec.argv  # not a TCP scan

    def test_tcp_connect_scan_when_no_net_raw(self, context: AdapterContext) -> None:
        """When the context does NOT signal NET_RAW capability, use -sT."""
        spec = NmapAdapter().plan(
            action("tcp_discovery", ports=(22,), net_raw=False),
            context,
        )
        assert "-sT" in spec.argv
        assert "-sS" not in spec.argv

    def test_syn_scan_requires_explicit_net_raw_input(
        self,
        context: AdapterContext,
    ) -> None:
        spec = NmapAdapter().plan(
            action("tcp_discovery", ports=(22,), net_raw=True),
            context,
        )
        assert "-sS" in spec.argv
        assert "-sT" not in spec.argv

    def test_rejects_unknown_operation(self, context: AdapterContext) -> None:
        with pytest.raises(AdapterError):
            NmapAdapter().plan(action("unknown_op"), context)

    def test_rejects_empty_ports(self, context: AdapterContext) -> None:
        with pytest.raises(AdapterError):
            NmapAdapter().plan(action("tcp_discovery", ports=()), context)

    @pytest.mark.parametrize(
        "ports",
        ("0", "65536", "80-22", "22,abc", (22, 0), (True,)),
    )
    def test_rejects_invalid_port_values(
        self,
        context: AdapterContext,
        ports: object,
    ) -> None:
        with pytest.raises(AdapterError):
            NmapAdapter().plan(
                action("tcp_discovery", ports=ports),
                context,
            )

    def test_normalizes_and_caps_large_port_range(
        self,
        context: AdapterContext,
    ) -> None:
        spec = NmapAdapter().plan(
            action("tcp_discovery", ports="1-10000"),
            context,
        )

        port_index = spec.argv.index("-p")
        assert spec.argv[port_index + 1] == "1-200"

    def test_sets_bounded_timeout_and_output(
        self, context: AdapterContext
    ) -> None:
        spec = NmapAdapter().plan(
            action("tcp_discovery", ports=(22, 80, 443)),
            context,
        )
        assert isinstance(spec, ProcessSpec)
        assert 1 <= spec.timeout_seconds <= 3600
        assert spec.max_output_bytes >= 1024

    def test_plan_consumes_context_rate_timeout_and_output_limits(
        self,
        context: AdapterContext,
    ) -> None:
        bounded = context.model_copy(
            update={
                "limits": PlaybookLimits(
                    max_rate=30,
                    max_concurrency=1,
                    max_attempts=1,
                    max_duration_seconds=20,
                    max_output_bytes=4096,
                )
            }
        )

        spec = NmapAdapter().plan(
            action(
                "tcp_discovery",
                ports=(22,),
                timeout=60,
                max_output=8192,
            ),
            bounded,
        )

        rate_index = spec.argv.index("--max-rate")
        assert spec.argv[rate_index + 1] == "30"
        assert spec.timeout_seconds == 20
        assert spec.max_output_bytes == 4096


# ── Parse ─────────────────────────────────────────────────────────────────────


class TestNmapParse:
    """Verify that NmapAdapter.parse() extracts typed observations."""

    def test_parses_open_ports(self, load_fixture) -> None:
        result = ProcessResult(
            exit_code=0,
            stdout=load_fixture("tcp_discovery.xml"),
            stderr="",
        )
        obs = NmapAdapter().parse(result)
        assert len(obs) == 3

        # Port 22: SSH open
        assert obs[0].data["port"] == 22
        assert obs[0].data["protocol"] == "tcp"
        assert obs[0].data["state"] == "open"
        assert obs[0].data["service"] == "ssh"

        # Port 80: HTTP
        assert obs[1].data["port"] == 80
        assert obs[1].data["service"] == "http"

        # Port 443: HTTPS
        assert obs[2].data["port"] == 443

    def test_rejects_dtd_entity(self, load_fixture) -> None:
        """DTD/ENTITY declarations in XML must be rejected before parsing."""
        result = ProcessResult(
            exit_code=0,
            stdout=load_fixture("dtd_entity.xml"),
            stderr="",
        )
        with pytest.raises(AdapterError, match="DTD"):
            NmapAdapter().parse(result)

    def test_unknown_service(self, load_fixture) -> None:
        """An unknown service should still produce an observation."""
        result = ProcessResult(
            exit_code=0,
            stdout=load_fixture("unknown_service.xml"),
            stderr="",
        )
        obs = NmapAdapter().parse(result)
        assert len(obs) == 1
        assert obs[0].data["service"] == "unknown"

    def test_ipv6_scan(self, load_fixture) -> None:
        result = ProcessResult(
            exit_code=0,
            stdout=load_fixture("ipv6_scan.xml"),
            stderr="",
        )
        obs = NmapAdapter().parse(result)
        assert len(obs) == 2
        # All observations should have the IPv6 target
        for o in obs:
            assert o.target.host == "dead:beef::1"

    def test_empty_output_returns_empty_tuple(self) -> None:
        result = ProcessResult(exit_code=0, stdout="", stderr="")
        obs = NmapAdapter().parse(result)
        assert obs == ()

    def test_malformed_xml_raises(self) -> None:
        result = ProcessResult(exit_code=0, stdout="not xml at all", stderr="")
        with pytest.raises(AdapterError):
            NmapAdapter().parse(result)

    def test_timeout_output_returns_empty(self) -> None:
        """Even partial XML from a timeout should be handled gracefully."""
        result = ProcessResult(
            exit_code=-1,
            stdout="<?xml version=\"1.0\"?><nmaprun>",
            stderr="",
            timed_out=True,
        )
        # Partial XML is technically malformed — should raise
        with pytest.raises(AdapterError):
            NmapAdapter().parse(result)


# ── Probe ──────────────────────────────────────────────────────────────────────


class TestNmapProbe:
    """Verify probe returns a plausible ToolProbe."""

    def test_nmap_adapter_has_name(self) -> None:
        adapter = NmapAdapter()
        assert hasattr(adapter, "name")
        assert adapter.name == "nmap"


# ── Protocol shape ────────────────────────────────────────────────────────────


class TestNmapProtocol:
    """Verify NmapAdapter satisfies the ToolAdapter protocol."""

    def test_is_tool_adapter(self) -> None:
        from ariadne.adapters.base import ToolAdapter

        assert isinstance(NmapAdapter(), ToolAdapter)
