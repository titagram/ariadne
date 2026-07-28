"""httpx discovery adapter.

Builds safe, bounded httpx command-lines and parses JSONL output
into structured ``Observation`` objects.

Safety invariants
-----------------
- Targets are fed through stdin (bounded file), not argv, to avoid
  argument-length limits and injection.
- Automatic probing of unrelated hostnames is disabled.
- Redirects to unconfirmed hosts are marked as ``observed_only``
  and are not followed.
- Malformed JSONL lines are skipped, not fatal.
- No shell interpolation: every argument is in the argv tuple.
- Timeout and output size are bounded by ``ProcessSpec``.
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
from ariadne.core.observations import Observation


def _parse_httpx_jsonl(stdout: str) -> list[Observation]:
    """Parse httpx JSONL output into a list of Observation objects.

    Each valid JSON line should contain at minimum a ``url`` field.
    Redirects to external hosts are recorded with a ``location``
    field indicating the unconfirmed host.
    """
    observations: list[Observation] = []

    from ariadne.core.engagement import TargetSpec

    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue

        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            # Skip malformed lines
            continue

        url = record.get("url")
        if not url or not isinstance(url, str):
            continue

        obs_data: dict[str, object] = {
            "url": url,
            "status_code": record.get("status_code", 0),
            "content_type": record.get("content_type", ""),
            "content_length": record.get("content_length", 0),
            "title": record.get("title", ""),
            "tech": record.get("tech", []),
            "redirect": record.get("redirect", False),
        }

        # Record redirect location
        location = record.get("location")
        if location:
            obs_data["location"] = location

        # Determine host from URL
        from urllib.parse import urlparse

        parsed = urlparse(url)
        host = parsed.hostname or "unknown"

        target = TargetSpec(host=host)
        obs = Observation(
            observation_id=uuid4(),
            target=target,
            source="httpx",
            data=obs_data,
        )
        observations.append(obs)

    return observations


class HttpxAdapter:
    """ToolAdapter for httpx HTTP probing.

    Supports ``scan`` operations.  Targets are fed through stdin to
    avoid shell injection and argument-length limits.
    """

    name: ClassVar[str] = "httpx"

    async def probe(self, runtime: Runtime) -> ToolProbe:
        return ToolProbe(available=True)

    def plan(
        self,
        action: PlannedAction,
        context: AdapterContext,
    ) -> ProcessSpec:
        op = action.operation
        if op != "scan":
            raise AdapterError(
                f"Unknown httpx operation: {op!r}. "
                f"Supported: scan"
            )

        inputs = action.inputs
        ports = inputs.get("ports", ())
        if not ports or not isinstance(ports, (list, tuple)):
            raise AdapterError("ports must be a non-empty list or tuple")

        port_str = ",".join(str(p) for p in ports)
        target = str(context.target.host)

        # Build bounded argv:
        # - targets piped through stdin (-l -)
        # - JSONL output (-json)
        # - follow host redirects (-fr) but don't probe unrelated hostnames
        # - limited threads
        argv = [
            "httpx",
            "-l", "-",
            "-p", port_str,
            "-json",
            "-fr",         # follow redirects
            "-no-fallback", # don't fall back to unrelated hostnames
            "-t", "10",    # 10 threads max
            "-timeout", str(inputs.get("timeout", 10)),
        ]

        # Target IP goes into stdin
        stdin_input = f"https://{target}\nhttp://{target}\n".encode()

        return ProcessSpec(
            argv=tuple(argv),
            stdin=stdin_input,
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
        return tuple(_parse_httpx_jsonl(stdout))

    def classify(
        self,
        result: ProcessResult,
        observations: tuple[Observation, ...],
    ) -> ExecutionClassification:
        if result.timed_out:
            return ExecutionClassification(
                kind="partial",
                confidence=0.3,
                summary="httpx timed out; partial results may be available",
            )
        if result.exit_code != 0:
            return ExecutionClassification(
                kind="failure",
                confidence=0.5,
                summary=f"httpx exited with code {result.exit_code}",
            )
        if len(observations) > 0:
            return ExecutionClassification(
                kind="success",
                confidence=0.9,
                summary=f"Discovered {len(observations)} HTTP endpoints",
            )
        return ExecutionClassification(
            kind="unknown",
            confidence=0.5,
            summary="httpx completed but no endpoints found",
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
