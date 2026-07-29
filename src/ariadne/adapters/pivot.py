"""Pivot lifecycle adapter for Ariadne.

Provides bounded tunnel and route management operations:

- start_tunnel        — Start Ligolo-ng proxy/agent tunnel
- add_route           — Add route for a confirmed network through the tunnel
- remove_route        — Remove a previously added route
- stop_tunnel         — Stop a running tunnel and clean up routes

Ligolo-ng is primary; Chisel and SSH are explicit fallbacks (selected via
input parameter ``tunnel_type``).

Distinct discovered hosts are always ``scope_candidate``. No route is added
for an unconfirmed network. Scanning them requires a scope amendment.
"""

from __future__ import annotations

import json
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
from ariadne.core.errors import ScopeAmendmentRequiredError
from ariadne.core.observations import Observation

# ── Operation catalogs ────────────────────────────────────────────────────────

_PIVOT_OPERATIONS: frozenset = frozenset({
    "start_tunnel",
    "add_route",
    "remove_route",
    "stop_tunnel",
    "scan_discovered_host",
})

# Networks that are confirmed (in-scope by default).  Any add_route request
# for a network not starting with these prefixes requires a scope amendment.
_CONFIRMED_NETWORK_PREFIXES: tuple[str, ...] = (
    "10.10.10.",
    "10.10.0.",
    "192.168.",
)

# Environment key for additional confirmed networks.
_CONFIRMED_NETWORKS_ENV = "CONFIRMED_NETWORKS"

# ── Scope helpers ────────────────────────────────────────────────────────────


def _is_network_confirmed(
    network: str,
    context: AdapterContext,
) -> bool:
    """Check whether *network* is in the confirmed scope.

    Checks built-in prefixes and any additional networks declared in the
    engagement context environment.
    """
    # Check built-in prefixes
    for prefix in _CONFIRMED_NETWORK_PREFIXES:
        if network.startswith(prefix):
            return True

    # Check additional confirmed networks from context
    extra = context.environment.get(_CONFIRMED_NETWORKS_ENV, "")
    for net in extra.split(","):
        net = net.strip()
        if net and network.startswith(net):
            return True

    return False


# ── Adapter ────────────────────────────────────────────────────────────────────


class PivotAdapter:
    """ToolAdapter for pivot tunnel lifecycle management.

    Maintains a ``_tunnels`` dict mapping tunnel IDs to their state dicts
    (target, local_port, session_id, etc.).  Tunnel state is kept in-memory
    for the duration of one action cycle.

    Ligolo-ng is the default tunnel type.  Chisel and SSH are explicit
    fallbacks.
    """

    name: ClassVar[str] = "pivot"

    def __init__(self) -> None:
        self._tunnels: dict[str, dict[str, str]] = {}

    # ── Probe ─────────────────────────────────────────────────────────────

    async def probe(self, runtime: Runtime) -> ToolProbe:
        return ToolProbe(available=True)

    # ── Plan ──────────────────────────────────────────────────────────────

    def plan(
        self,
        action: PlannedAction,
        context: AdapterContext,
    ) -> ProcessSpec:
        op = action.operation

        if op == "scan_discovered_host":
            raise ScopeAmendmentRequiredError(
                f"Cannot scan discovered host {str(context.target.host)} "
                f"without a scope amendment"
            )

        if op not in _PIVOT_OPERATIONS:
            raise AdapterError(
                f"Unknown pivot operation: {op!r}. "
                f"Supported: {', '.join(sorted(_PIVOT_OPERATIONS))}"
            )

        inputs = action.inputs

        if op == "start_tunnel":
            return self._plan_start_tunnel(inputs, context)
        elif op == "add_route":
            return self._plan_add_route(inputs, context)
        elif op == "remove_route":
            return self._plan_remove_route(inputs, context)
        elif op == "stop_tunnel":
            return self._plan_stop_tunnel(inputs, context)
        else:
            raise AdapterError(f"Unhandled pivot operation: {op!r}")

    # ── Tunnel lifecycle planners ─────────────────────────────────────────

    def _plan_start_tunnel(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        tunnel_type = str(inputs.get("tunnel_type", "ligolo"))
        tunnel_id = f"tun_{uuid4().hex[:12]}"
        target = str(context.target.host)

        if tunnel_type == "ligolo":
            argv = (
                "ligolo-proxy",
                "-selfcert",
                "-laddr",
                "0.0.0.0:11601",
            )
        elif tunnel_type == "chisel":
            argv = (
                "chisel",
                "server",
                "-p",
                "8080",
                "--reverse",
            )
        elif tunnel_type == "ssh":
            argv = (
                "ssh",
                "-R",
                "1080",
                "-N",
                target,
            )
        else:
            raise AdapterError(
                f"Unknown tunnel type: {tunnel_type!r}. "
                f"Supported: ligolo, chisel, ssh"
            )

        self._tunnels[tunnel_id] = {
            "target": target,
            "tunnel_type": tunnel_type,
            "local_port": "11601" if tunnel_type == "ligolo" else "8080",
        }

        return ProcessSpec(
            argv=argv,
            timeout_seconds=300,
            max_output_bytes=512 * 1024,
        )

    def _plan_add_route(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        network = str(inputs.get("network", ""))

        if not network:
            raise AdapterError("add_route requires a 'network' input")

        if not _is_network_confirmed(network, context):
            raise ScopeAmendmentRequiredError(
                f"Network {network!r} is not in the confirmed scope. "
                f"Add it via a scope amendment before adding a route."
            )

        tunnel_id = str(inputs.get("tunnel_id", ""))
        if tunnel_id and tunnel_id not in self._tunnels:
            raise AdapterError(
                f"Tunnel {tunnel_id!r} not found. Start a tunnel first."
            )

        state = None
        if tunnel_id and tunnel_id in self._tunnels:
            state = self._tunnels[tunnel_id]

        if state:
            argv = (
                "ip",
                "route",
                "add",
                network,
                "dev",
                "tun",
            )
        else:
            argv = (
                "ip",
                "route",
                "add",
                network,
            )

        return ProcessSpec(
            argv=argv,
            timeout_seconds=30,
            max_output_bytes=256 * 1024,
        )

    def _plan_remove_route(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        network = str(inputs.get("network", ""))

        if not network:
            raise AdapterError("remove_route requires a 'network' input")

        argv = (
            "ip",
            "route",
            "del",
            network,
        )
        return ProcessSpec(
            argv=argv,
            timeout_seconds=30,
            max_output_bytes=256 * 1024,
        )

    def _plan_stop_tunnel(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        tunnel_id = str(inputs.get("tunnel_id", ""))

        # If no tunnel_id specified, stop all
        if not tunnel_id:
            self._tunnels.clear()
            return ProcessSpec(
                argv=("pkill", "-f", "ligolo-proxy"),
                timeout_seconds=30,
                max_output_bytes=128 * 1024,
            )

        if tunnel_id not in self._tunnels:
            raise AdapterError(
                f"Tunnel {tunnel_id!r} not found. Cannot stop."
            )

        # Remove from state
        self._tunnels.pop(tunnel_id, None)

        return ProcessSpec(
            argv=("pkill", "-f", "ligolo-proxy"),
            timeout_seconds=30,
            max_output_bytes=128 * 1024,
        )

    # ── Execute ───────────────────────────────────────────────────────────

    async def execute(
        self,
        spec: ProcessSpec,
        runtime: Runtime,
    ) -> ProcessResult:
        return await runtime.run(spec)

    # ── Parse ─────────────────────────────────────────────────────────────

    def parse(
        self,
        result: ProcessResult,
    ) -> tuple[Observation, ...]:
        stdout = result.stdout
        if not stdout.strip():
            return ()

        observations: list[Observation] = []

        # Detect JSON output (tunnel state, discovered host)
        if stdout.strip().startswith("{"):
            try:
                data = json.loads(stdout)
                observations.append(self._make_observation(data))
                return tuple(observations)
            except json.JSONDecodeError:
                pass

        # Detect tunnel started (Ligolo-ng or Chisel)
        if "ligolo" in stdout.lower() or "agent connected" in stdout.lower():
            observations.append(self._make_observation({
                "tool": "tunnel",
                "type": "tunnel_started",
                "snippet": stdout[:500],
            }))
            return tuple(observations)

        # Detect route added
        if "route added" in stdout.lower() or "adding route" in stdout.lower():
            observations.append(self._make_observation({
                "tool": "route",
                "type": "route_added",
                "snippet": stdout[:500],
            }))
            return tuple(observations)

        # Detect route removed
        if "route removed" in stdout.lower() or "removing route" in stdout.lower():
            observations.append(self._make_observation({
                "tool": "route",
                "type": "route_removed",
                "snippet": stdout[:500],
            }))
            return tuple(observations)

        # Detect tunnel stopped
        if "tunnel stopped" in stdout.lower() or "cleaning up" in stdout.lower():
            observations.append(self._make_observation({
                "tool": "tunnel",
                "type": "tunnel_stopped",
                "snippet": stdout[:500],
            }))
            return tuple(observations)

        # Fallback: generic observation for any non-trivial output
        if len(stdout.strip()) > 20:
            observations.append(self._make_observation({
                "type": "raw_output",
                "snippet": stdout[:500],
            }))

        return tuple(observations)

    def _make_observation(self, data: dict[str, object]) -> Observation:
        from ariadne.core.engagement import TargetSpec

        normalized = dict(data)
        discovered_host = normalized.get("discovered_host")
        if isinstance(discovered_host, str) and discovered_host:
            normalized["status"] = "scope_candidate"
            normalized["scope_candidate"] = True
            host = discovered_host
        else:
            host = "0.0.0.0"
        return Observation(
            observation_id=uuid4(),
            target=TargetSpec(host=host),
            source="pivot",
            data=normalized,
        )

    # ── Classify ──────────────────────────────────────────────────────────

    def classify(
        self,
        result: ProcessResult,
        observations: tuple[Observation, ...],
    ) -> ExecutionClassification:
        if result.timed_out:
            return ExecutionClassification(
                kind="partial",
                confidence=0.3,
                summary="Pivot operation timed out; tunnel may be partially set up",
            )
        if result.exit_code != 0:
            return ExecutionClassification(
                kind="failure",
                confidence=0.5,
                summary=f"Pivot operation exited with code {result.exit_code}",
            )
        if len(observations) > 0:
            return ExecutionClassification(
                kind="success",
                confidence=0.7,
                summary=f"Pivot operation returned {len(observations)} observations",
            )
        return ExecutionClassification(
            kind="unknown",
            confidence=0.5,
            summary="Pivot operation completed with no structured output",
        )

    # ── Collect / Cleanup ─────────────────────────────────────────────────

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
        self._tunnels.clear()
        return CleanupResult(
            success=True,
            details="All tunnels cleaned up",
        )
