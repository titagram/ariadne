"""Nmap discovery adapter.

Builds safe, bounded Nmap command-lines and parses Nmap XML output
into structured ``Observation`` objects.

Safety invariants
-----------------
- All output is captured from ``-oX -`` (stdout XML); no temp files.
- XML containing ``<!DOCTYPE`` or ``<!ENTITY`` is rejected before parsing
  to prevent XXE attacks.
- ``xml.etree.ElementTree`` is used for safe parsing (no external entity
  resolution by default).
- No shell interpolation: every argument is in the argv tuple.
- Timeout and output size are bounded by ``ProcessSpec``.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import ClassVar
from uuid import uuid4

from ariadne.adapters.base import (
    AdapterContext,
    AdapterError,
    CleanupResult,
    ExecutionClassification,
    PlannedAction,
    ProcessResult,
    ProcessSpec,
    Runtime,
    ToolProbe,
)
from ariadne.core.observations import Observation

_OPERATIONS: frozenset = frozenset({"tcp_discovery", "service_fingerprint", "udp_targeted"})


def _check_dtd(stdout: str) -> None:
    """Reject XML that contains DTD declarations to prevent XXE."""
    upper = stdout.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise AdapterError("XML contains DTD/ENTITY declarations — rejected for safety")


def _parse_nmap_xml(stdout: str) -> list[Observation]:
    """Parse Nmap XML output into a list of Observation objects.

    Returns one observation per open TCP/UDP port on each host.
    """
    _check_dtd(stdout)

    try:
        root = ET.fromstring(stdout)
    except ET.ParseError as e:
        raise AdapterError(f"Failed to parse Nmap XML: {e}") from e

    observations: list[Observation] = []

    for host_elem in root.findall("host"):
        # Determine host address
        addr_elem = host_elem.find("address")
        if addr_elem is None:
            continue
        host_addr = addr_elem.get("addr", "")
        host_str = host_addr

        ports_elem = host_elem.find("ports")
        if ports_elem is None:
            continue

        for port_elem in ports_elem.findall("port"):
            protocol = port_elem.get("protocol", "")
            port_id_str = port_elem.get("portid", "")

            state_elem = port_elem.find("state")
            if state_elem is None:
                continue
            state = state_elem.get("state", "")

            # Only produce observations for "open" ports
            if state != "open":
                continue

            try:
                port = int(port_id_str)
            except (ValueError, TypeError):
                continue

            service_elem = port_elem.find("service")
            service_name: str
            if service_elem is not None:
                service_name = service_elem.get("name", "unknown")
                product = service_elem.get("product", "")
                version = service_elem.get("version", "")
            else:
                service_name = "unknown"
                product = ""
                version = ""

            obs_data: dict[str, object] = {
                "port": port,
                "protocol": protocol,
                "state": state,
                "service": service_name,
            }
            if product:
                obs_data["product"] = product
            if version:
                obs_data["version"] = version

            from ariadne.core.engagement import TargetSpec

            target = TargetSpec(host=host_str)
            obs = Observation(
                observation_id=uuid4(),
                target=target,
                source="nmap",
                data=obs_data,
            )
            observations.append(obs)

    return observations


class NmapAdapter:
    """ToolAdapter for Nmap network scanning.

    Supports ``tcp_discovery``, ``service_fingerprint``, and
    ``udp_targeted`` operations.
    """

    name: ClassVar[str] = "nmap"

    # ── ToolAdapter protocol ─────────────────────────────────────────────

    async def probe(self, runtime: Runtime) -> ToolProbe:
        return ToolProbe(available=True)

    def plan(
        self,
        action: PlannedAction,
        context: AdapterContext,
    ) -> ProcessSpec:
        op = action.operation
        if op not in _OPERATIONS:
            raise AdapterError(
                f"Unknown Nmap operation: {op!r}. "
                f"Supported: {', '.join(sorted(_OPERATIONS))}"
            )

        inputs = action.inputs
        ports = inputs.get("ports", ())
        if not ports or not isinstance(ports, (list, tuple)):
            raise AdapterError("ports must be a non-empty list or tuple")

        port_str = ",".join(str(p) for p in ports)
        target = str(context.target.host)

        # Common base arguments
        argv: list[str] = ["nmap", "-n", "-Pn"]

        if op == "tcp_discovery":
            net_raw = inputs.get("net_raw", True)
            if net_raw:
                argv.append("-sS")
            else:
                argv.append("-sT")
            argv.extend(["--max-rate", "100"])
        elif op == "service_fingerprint":
            argv.extend(["-sS", "-sV", "--max-rate", "100"])
        elif op == "udp_targeted":
            argv.append("-sU")
            argv.extend(["--max-rate", "50"])

        argv.extend(["-p", port_str, "-oX", "-", "--", target])

        return ProcessSpec(
            argv=tuple(argv),
            timeout_seconds=int(inputs.get("timeout", 300)),  # type: ignore[arg-type]
            max_output_bytes=int(inputs.get("max_output", 10 * 1024 * 1024)),  # type: ignore[arg-type]
        )

    async def execute(
        self,
        spec: ProcessSpec,
        runtime: Runtime,
    ) -> ProcessResult:
        return await runtime.run(spec)

    def parse(
        self,
        result: ProcessResult,
    ) -> tuple[Observation, ...]:
        stdout = result.stdout
        if not stdout.strip():
            return ()
        return tuple(_parse_nmap_xml(stdout))

    def classify(
        self,
        result: ProcessResult,
        observations: tuple[Observation, ...],
    ) -> ExecutionClassification:
        if result.timed_out:
            return ExecutionClassification(
                kind="partial",
                confidence=0.3,
                summary="Nmap timed out; partial results may be available",
            )
        if result.exit_code != 0:
            return ExecutionClassification(
                kind="failure",
                confidence=0.5,
                summary=f"Nmap exited with code {result.exit_code}",
            )
        if len(observations) > 0:
            return ExecutionClassification(
                kind="success",
                confidence=0.9,
                summary=f"Discovered {len(observations)} open ports",
            )
        return ExecutionClassification(
            kind="unknown",
            confidence=0.5,
            summary="Nmap completed but no open ports found",
        )

    async def collect(
        self,
        result: ProcessResult,
        collector: object,
    ) -> tuple[str, ...]:
        return ()

    async def cleanup(
        self,
        context: AdapterContext,
    ) -> CleanupResult:
        return CleanupResult(success=True, details="No temporary resources to clean up")
