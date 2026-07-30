"""Bounded ProjectDiscovery Katana crawler adapter."""

from __future__ import annotations

import json
import re
from typing import ClassVar
from urllib.parse import parse_qsl, urlparse
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


def _bounded_integer(
    value: object,
    *,
    minimum: int,
    maximum: int,
    name: str,
) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise AdapterError(f"{name} must be an integer") from exc
    if not minimum <= parsed <= maximum:
        raise AdapterError(
            f"{name} must be between {minimum} and {maximum}"
        )
    return parsed


def _endpoint_from_record(record: dict[str, object]) -> str | None:
    direct = record.get("url") or record.get("endpoint")
    if isinstance(direct, str) and direct:
        return direct
    request = record.get("request")
    if isinstance(request, dict):
        endpoint = request.get("endpoint")
        if isinstance(endpoint, str) and endpoint:
            return endpoint
    return None


class KatanaAdapter:
    """Run a same-host, budgeted crawl and emit structured endpoints."""

    name: ClassVar[str] = "katana"

    async def probe(self, runtime: Runtime) -> ToolProbe:
        return ToolProbe(available=True)

    def plan(
        self,
        action: PlannedAction,
        context: AdapterContext,
    ) -> ProcessSpec:
        if action.operation != "crawl":
            raise AdapterError(
                f"Unknown Katana operation: {action.operation!r}. "
                "Supported: crawl"
            )
        raw_urls = action.inputs.get("urls")
        if not isinstance(raw_urls, (list, tuple)) or not raw_urls:
            raise AdapterError("urls must be a non-empty list or tuple")

        target = context.target.host.casefold()
        seeds: list[str] = []
        for raw_url in raw_urls:
            if not isinstance(raw_url, str):
                raise AdapterError("crawler seeds must be URL strings")
            parsed = urlparse(raw_url)
            if (
                parsed.scheme not in {"http", "https"}
                or parsed.hostname is None
                or parsed.hostname.casefold() != target
                or parsed.username is not None
                or parsed.password is not None
                or parsed.fragment
            ):
                raise AdapterError(
                    f"crawler seed {raw_url!r} is outside the exact target scope"
                )
            if raw_url not in seeds:
                seeds.append(raw_url)
        if len(seeds) > 10:
            raise AdapterError("crawler accepts at most 10 target-bound seeds")

        depth = _bounded_integer(
            action.inputs.get("depth", 3),
            minimum=1,
            maximum=5,
            name="depth",
        )
        duration = _bounded_integer(
            action.inputs.get("duration_seconds", 60),
            minimum=5,
            maximum=300,
            name="duration_seconds",
        )
        max_pages = _bounded_integer(
            action.inputs.get("max_pages", 200),
            minimum=1,
            maximum=500,
            name="max_pages",
        )
        request_timeout = _bounded_integer(
            action.inputs.get("request_timeout", 10),
            minimum=1,
            maximum=30,
            name="request_timeout",
        )
        rate = min(context.limits.max_rate or 10, 20)
        concurrency = min(context.limits.max_concurrency or 2, 4)
        scope_regex = (
            rf"^https?://{re.escape(context.target.host)}"
            r"(?::[0-9]+)?(?:/|$)"
        )
        argv = (
            "katana",
            "-u",
            ",".join(seeds),
            "-d",
            str(depth),
            "-ct",
            f"{duration}s",
            "-mdp",
            str(max_pages),
            "-c",
            str(concurrency),
            "-p",
            "1",
            "-rl",
            str(rate),
            "-timeout",
            str(request_timeout),
            "-retry",
            "1",
            "-cs",
            scope_regex,
            "-kf",
            "all",
            "-jc",
            "-fx",
            "-xhr",
            "-iqp",
            "-jsonl",
            "-omit-raw",
            "-omit-body",
            "-silent",
            "-duc",
        )
        return ProcessSpec(
            argv=argv,
            timeout_seconds=duration + 15,
            max_output_bytes=min(
                context.limits.max_output_bytes or 10 * 1024 * 1024,
                10 * 1024 * 1024,
            ),
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
        return self._parse(result, target=None)

    def parse_for_target(
        self,
        result: ProcessResult,
        target: TargetSpec,
    ) -> tuple[Observation, ...]:
        return self._parse(result, target=target)

    def _parse(
        self,
        result: ProcessResult,
        *,
        target: TargetSpec | None,
    ) -> tuple[Observation, ...]:
        observations: list[Observation] = []
        seen: set[str] = set()
        for line in result.stdout.splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            endpoint = _endpoint_from_record(record)
            if endpoint is None or endpoint in seen:
                continue
            parsed = urlparse(endpoint)
            if (
                parsed.scheme not in {"http", "https"}
                or parsed.hostname is None
                or (
                    target is not None
                    and parsed.hostname.casefold() != target.host.casefold()
                )
            ):
                continue
            request = record.get("request")
            response = record.get("response")
            method = (
                request.get("method", "GET")
                if isinstance(request, dict)
                else "GET"
            )
            status_code = (
                response.get("status_code", 0)
                if isinstance(response, dict)
                else record.get("status_code", 0)
            )
            seen.add(endpoint)
            observations.append(
                Observation(
                    observation_id=uuid4(),
                    target=TargetSpec(host=parsed.hostname),
                    source="katana",
                    data={
                        "type": "web_path",
                        "url": endpoint,
                        "path": parsed.path or "/",
                        "method": str(method),
                        "status_code": status_code,
                        "parameters": tuple(
                            dict.fromkeys(key for key, _ in parse_qsl(parsed.query))
                        ),
                    },
                )
            )
        return tuple(observations)

    def classify(
        self,
        result: ProcessResult,
        observations: tuple[Observation, ...],
    ) -> ExecutionClassification:
        if result.timed_out:
            if not observations:
                return ExecutionClassification(
                    kind="failure",
                    confidence=0.8,
                    summary="Katana timed out without collecting target-bound endpoints",
                )
            return ExecutionClassification(
                kind="partial",
                confidence=0.5,
                summary=f"Katana timed out after collecting {len(observations)} endpoints",
            )
        if result.exit_code != 0:
            return ExecutionClassification(
                kind="failure",
                confidence=0.8,
                summary=f"Katana exited with code {result.exit_code}",
            )
        if observations:
            return ExecutionClassification(
                kind="success",
                confidence=0.9,
                summary=f"Katana collected {len(observations)} target-bound endpoints",
            )
        return ExecutionClassification(
            kind="unknown",
            confidence=0.5,
            summary="Katana completed without target-bound endpoints",
        )

    async def collect(
        self,
        result: ProcessResult,
        collector: object,
    ) -> tuple[str, ...]:
        return ()

    async def cleanup(self, context: AdapterContext) -> CleanupResult:
        return CleanupResult(
            success=True,
            details="Katana crawl uses no persistent remote artifacts",
        )
