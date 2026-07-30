"""httpx discovery adapter.

Builds safe, bounded httpx command-lines and parses JSONL output
into structured ``Observation`` objects.

Safety invariants
-----------------
- Targets are fed through stdin (bounded file), not argv, to avoid
  argument-length limits and injection.
- Automatic probing of unrelated hostnames is disabled.
- Redirect locations are recorded without being followed. A distinct redirect
  host is emitted as a ``scope_candidate`` for a targeted amendment.
- Malformed JSONL lines are skipped, not fatal.
- No shell interpolation: every argument is in the argv tuple.
- Timeout and output size are bounded by ``ProcessSpec``.
"""

from __future__ import annotations

import ipaddress
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
from ariadne.core.engagement import TargetSpec
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

        # If this record is a redirect to an external host, emit a
        # synthetic scope-candidate observation. Downstream enforcement records
        # local evidence and rejects active probing until an amendment.
        status_code = record.get("status_code")
        is_redirect = record.get("redirect") is True or (
            isinstance(status_code, int)
            and not isinstance(status_code, bool)
            and 300 <= status_code < 400
        )
        location = record.get("location", "")
        if is_redirect and location and isinstance(location, str):
            loc_parsed = urlparse(location)
            loc_host = loc_parsed.hostname or ""
            if (
                loc_parsed.scheme in {"http", "https"}
                and loc_host
                and loc_host.casefold() != host.casefold()
            ):
                ext_obs = Observation(
                    observation_id=uuid4(),
                    target=TargetSpec(host=loc_host),
                    source="httpx",
                    data={
                        "url": location,
                        "redirect_source": url,
                        "redirect_source_host": host,
                        "scope_candidate": True,
                        "status": "scope_candidate",
                    },
                )
                observations.append(ext_obs)

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
            raise AdapterError(f"Unknown httpx operation: {op!r}. Supported: scan")

        inputs = action.inputs
        ports = inputs.get("ports", ())
        if not ports or not isinstance(ports, (list, tuple)):
            raise AdapterError("ports must be a non-empty list or tuple")
        request_timeout = int(inputs.get("timeout", 10))
        http_host = inputs.get("http_host")
        if http_host is not None:
            if not isinstance(http_host, str):
                raise AdapterError("http_host must be a hostname")
            alias = TargetSpec(host=http_host).host
            if alias == context.target.host:
                raise AdapterError("http_host must be distinct from the network target")
            try:
                ipaddress.ip_address(alias)
            except ValueError:
                http_host = alias
            else:
                raise AdapterError("http_host must be an approved FQDN alias")

        port_str = ",".join(str(p) for p in ports)
        target = str(context.target.host)

        # Build bounded argv:
        # - targets piped through stdin (httpx reads stdin when -l is omitted)
        # - JSONL output (-json)
        # - don't probe unrelated hostnames and don't follow redirects
        # - limited threads
        argv = [
            "httpx-toolkit",
            "-p",
            port_str,
            "-json",
            "-no-fallback",  # don't fall back to unrelated hostnames
            "-t",
            "10",  # 10 threads max
            "-timeout",
            str(request_timeout),
        ]
        if http_host is not None:
            argv.extend(("-H", f"Host: {http_host}"))

        # Target IP goes into stdin
        stdin_input = f"https://{target}\nhttp://{target}\n".encode()

        return ProcessSpec(
            argv=tuple(argv),
            stdin=stdin_input,
            timeout_seconds=int(inputs.get("process_timeout", max(30, request_timeout * 2 + 5))),  # type: ignore[arg-type]
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
