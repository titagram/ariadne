"""Minimal same-host HTTP fallback backed by the system curl binary."""

from __future__ import annotations

from html.parser import HTMLParser
from typing import ClassVar
from urllib.parse import parse_qsl, urljoin, urlparse
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


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        attribute = {
            "a": "href",
            "area": "href",
            "form": "action",
            "iframe": "src",
            "img": "src",
            "link": "href",
            "script": "src",
        }.get(tag.casefold())
        if attribute is None:
            return
        for key, value in attrs:
            if key.casefold() == attribute and isinstance(value, str) and value:
                self.references.append(value)


class CurlAdapter:
    """Fetch one known page without redirects and extract local references."""

    name: ClassVar[str] = "curl"

    async def probe(self, runtime: Runtime) -> ToolProbe:
        return ToolProbe(available=True)

    def plan(
        self,
        action: PlannedAction,
        context: AdapterContext,
    ) -> ProcessSpec:
        if action.operation != "fetch":
            raise AdapterError(
                f"Unknown curl operation: {action.operation!r}. Supported: fetch"
            )
        url = action.inputs.get("url")
        if not isinstance(url, str) or not url:
            raise AdapterError("url must be a non-empty HTTP URL")
        parsed = urlparse(url)
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname is None
            or parsed.hostname.casefold() != context.target.host.casefold()
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise AdapterError(f"URL {url!r} is outside the exact target scope")
        timeout = int(action.inputs.get("timeout", 20))
        if not 1 <= timeout <= 30:
            raise AdapterError("timeout must be between 1 and 30 seconds")
        max_bytes = int(action.inputs.get("max_output", 1024 * 1024))
        if not 1 <= max_bytes <= 2 * 1024 * 1024:
            raise AdapterError("max_output must be between 1 byte and 2 MiB")
        return ProcessSpec(
            argv=(
                "curl",
                "--silent",
                "--show-error",
                "--proto",
                "=http,https",
                "--connect-timeout",
                str(min(timeout, 10)),
                "--max-time",
                str(timeout),
                "--max-filesize",
                str(max_bytes),
                "--compressed",
                "--url",
                url,
            ),
            timeout_seconds=timeout + 5,
            max_output_bytes=max_bytes,
        )

    async def execute(
        self,
        spec: ProcessSpec,
        runtime: Runtime,
    ) -> ProcessResult:
        return await runtime.run(spec)

    def parse(self, result: ProcessResult) -> tuple[Observation, ...]:
        return ()

    def parse_for_spec(
        self,
        result: ProcessResult,
        target: TargetSpec,
        spec: ProcessSpec,
    ) -> tuple[Observation, ...]:
        try:
            seed = spec.argv[spec.argv.index("--url") + 1]
        except (ValueError, IndexError):
            return ()
        extractor = _LinkExtractor()
        extractor.feed(result.stdout)
        urls = [seed]
        urls.extend(urljoin(seed, reference) for reference in extractor.references)
        observations: list[Observation] = []
        seen: set[str] = set()
        for url in urls:
            parsed = urlparse(url)
            if (
                url in seen
                or parsed.scheme not in {"http", "https"}
                or parsed.hostname is None
                or parsed.hostname.casefold() != target.host.casefold()
            ):
                continue
            seen.add(url)
            observations.append(
                Observation(
                    observation_id=uuid4(),
                    target=target,
                    source="curl",
                    data={
                        "type": "web_path",
                        "url": url,
                        "path": parsed.path or "/",
                        "method": "GET",
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
            return ExecutionClassification(
                kind="partial",
                confidence=0.3,
                summary="curl fallback timed out",
            )
        if result.exit_code != 0:
            return ExecutionClassification(
                kind="failure",
                confidence=0.8,
                summary=f"curl exited with code {result.exit_code}",
            )
        if observations:
            return ExecutionClassification(
                kind="success",
                confidence=0.8,
                summary=f"curl extracted {len(observations)} same-host URLs",
            )
        return ExecutionClassification(
            kind="unknown",
            confidence=0.5,
            summary="curl completed without parseable HTML references",
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
            details="curl fallback creates no persistent remote artifacts",
        )
