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
    """Reject XML that contains dangerous DTD/ENTITY declarations.

    ``<!DOCTYPE nmaprun>`` (Nmap's standard XML header) is harmless
    and is accepted.  All other DOCTYPE / ENTITY declarations are
    rejected to prevent XXE.
    """
    upper = stdout.upper()
    if "<!ENTITY" in upper:
        raise AdapterError("XML contains ENTITY declarations — rejected for safety")
    # Accept nmap's standard DOCTYPE (case-insensitive), reject any other
    if "<!DOCTYPE" in upper and "<!DOCTYPE NMAPRUN" not in upper:
        raise AdapterError("XML contains unknown DTD — rejected for safety")


def _parse_nmap_xml(stdout: str, source: str = "nmap") -> list[Observation]:
    """Parse Nmap XML output into a list of Observation objects.

    Returns one observation per open TCP/UDP port on each host.

    *source* is the evidence type stored on each observation
    (e.g. ``tcp_discovery`` or ``service_fingerprint``).
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
                source=source,
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

    def __init__(self) -> None:
        self._current_operation: str = ""

    # ── ToolAdapter protocol ─────────────────────────────────────────────

    async def probe(self, runtime: Runtime) -> ToolProbe:
        return ToolProbe(available=True)

    def plan(
        self,
        action: PlannedAction,
        context: AdapterContext,
    ) -> ProcessSpec:
        op = action.operation
        self._current_operation = op  # track for parse()
        if op not in _OPERATIONS:
            raise AdapterError(
                f"Unknown Nmap operation: {op!r}. "
                f"Supported: {', '.join(sorted(_OPERATIONS))}"
            )

        inputs = action.inputs
        ports = inputs.get("ports", ())
        if not ports:
            # Fall back to common ports when none specified (service_fingerprint
            # after tcp_discovery knows which ports were found)
            ports = ("22,80,443,445,3389,8080,8443",) if op == "service_fingerprint" else ()
        if not ports:
            raise AdapterError("ports must be non-empty")
        if isinstance(ports, str):
            port_str = ports
        elif isinstance(ports, (list, tuple)):
            port_str = ",".join(str(p) for p in ports)
        else:
            raise AdapterError("ports must be a string, list, or tuple")
        # Cap large port ranges to prevent excessive scan times.
        # A full 1-65535 TCP connect scan can take hours; 1-1000 is a
        # reasonable default for discovery.  Use a specific port list or
        # "--top-ports N" if you need more granularity.
        if "-" in port_str:
            parts = port_str.split("-")
            if len(parts) == 2:
                try:
                    lo, hi = int(parts[0]), int(parts[1])
                    if hi - lo > 200:
                        port_str = f"{lo}-{lo + 199}"
                except (ValueError, TypeError):
                    pass  # non-numeric range, pass through as-is
        target = str(context.target.host)

        # Common base arguments
        argv: list[str] = ["nmap", "-n", "-Pn"]

        if op == "tcp_discovery":
            net_raw = inputs.get("net_raw", True)
            if net_raw:
                argv.append("-sS")
            else:
                argv.append("-sT")
            argv.extend(["--max-rate", "500"])
        elif op == "service_fingerprint":
            argv.extend(["-sS", "-sV", "--max-rate", "300"])


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
        result = await runtime.run(spec)
        # Auto-fallback: -sS (SYN scan) needs root. If it fails with "requires root",
        # retry with -sT (TCP connect scan).
        if (
            result.exit_code != 0
            and "-sS" in spec.argv
            and "requires root" in (result.stderr or "").lower()
        ):
            fallback_argv = tuple(
                "-sT" if a == "-sS" else a for a in spec.argv
            )
            fallback_spec = ProcessSpec(
                argv=fallback_argv,
                timeout_seconds=spec.timeout_seconds,
                max_output_bytes=spec.max_output_bytes,
            )
            return await runtime.run(fallback_spec)
        return result

    def parse(
        self,
        result: ProcessResult,
    ) -> tuple[Observation, ...]:
        stdout = result.stdout
        if not stdout.strip():
            return ()
        # Map operation to the evidence type expected by downstream playbooks
        op = self._current_operation
        source = {"tcp_discovery": "port_open", "service_fingerprint": "service_fingerprinted"}.get(op, op or "nmap")
        return tuple(_parse_nmap_xml(stdout, source=source))

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
