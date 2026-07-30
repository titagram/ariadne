"""Minimal same-host HTTP fallback backed by the system curl binary."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from html.parser import HTMLParser
from pathlib import Path
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
        for key, value in attrs:
            if (
                key.casefold() == "onclick"
                and isinstance(value, str)
                and (
                    match := re.fullmatch(
                        r"""\s*(?:window\.)?location(?:\.href)?\s*=\s*
                        (?P<quote>['"])(?P<url>[^'"]+)(?P=quote)\s*;?\s*""",
                        value,
                        flags=re.VERBOSE | re.IGNORECASE,
                    )
                )
                is not None
            ):
                self.references.append(match.group("url"))
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

    @staticmethod
    def _http_host(
        action: PlannedAction,
        context: AdapterContext,
    ) -> str | None:
        value = action.inputs.get("http_host")
        if value is None:
            return None
        if not isinstance(value, str):
            raise AdapterError("http_host must be a hostname")
        alias = TargetSpec(host=value).host
        if alias == context.target.host:
            raise AdapterError("http_host must be distinct from the network target")
        try:
            ipaddress.ip_address(alias)
        except ValueError:
            return alias
        raise AdapterError("http_host must be an approved FQDN alias")

    def plan(
        self,
        action: PlannedAction,
        context: AdapterContext,
    ) -> ProcessSpec:
        if action.operation not in {"fetch", "probe_references", "download"}:
            raise AdapterError(
                f"Unknown curl operation: {action.operation!r}. "
                "Supported: fetch, probe_references, download"
            )
        if action.operation == "probe_references":
            return self._plan_reference_probe(action, context)
        if action.operation == "download":
            return self._plan_download(action, context)
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
        argv = [
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
        ]
        http_host = self._http_host(action, context)
        if http_host is not None:
            argv.extend(("--header", f"Host: {http_host}"))
        argv.extend(("--url", url))
        return ProcessSpec(
            argv=tuple(argv),
            timeout_seconds=timeout + 5,
            max_output_bytes=max_bytes,
        )

    def _target_url(self, value: object, context: AdapterContext) -> str:
        if not isinstance(value, str) or not value:
            raise AdapterError("url must be a non-empty HTTP URL")
        parsed = urlparse(value)
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname is None
            or parsed.hostname.casefold() != context.target.host.casefold()
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise AdapterError(f"URL {value!r} is outside the exact target scope")
        return value

    def _plan_reference_probe(
        self,
        action: PlannedAction,
        context: AdapterContext,
    ) -> ProcessSpec:
        if context.run_root is None:
            raise AdapterError("reference probe requires a durable run root")
        values = action.inputs.get("urls")
        if not isinstance(values, (list, tuple)) or not values:
            raise AdapterError("urls must contain target-bound object references")
        urls = tuple(dict.fromkeys(self._target_url(value, context) for value in values))
        if not 1 <= len(urls) <= 8:
            raise AdapterError("reference probe accepts between 1 and 8 URLs")
        timeout = int(action.inputs.get("timeout", 20))
        if not 1 <= timeout <= 30:
            raise AdapterError("timeout must be between 1 and 30 seconds")
        digest = context.action_digest or hashlib.sha256("\n".join(urls).encode()).hexdigest()
        if not all(character in "0123456789abcdef" for character in digest.casefold()):
            raise AdapterError("action digest is invalid")
        probe_root = context.run_root.resolve() / "probes"
        probe_root.mkdir(parents=True, exist_ok=True)
        argv = [
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
            str(2 * 1024 * 1024),
            "--write-out",
            "%{json}\\n",
        ]
        for index, url in enumerate(urls):
            output = probe_root / f"webref_{digest[:20]}_{index}.body"
            argv.extend(("--output", str(output), "--url", url))
        return ProcessSpec(
            argv=tuple(argv),
            timeout_seconds=min(300, timeout * len(urls) + 5),
            max_output_bytes=256 * 1024,
        )

    def _plan_download(
        self,
        action: PlannedAction,
        context: AdapterContext,
    ) -> ProcessSpec:
        if context.run_root is None:
            raise AdapterError("download requires a durable run root")
        url = self._target_url(action.inputs.get("url"), context)
        timeout = int(action.inputs.get("timeout", 30))
        if not 1 <= timeout <= 60:
            raise AdapterError("download timeout must be between 1 and 60 seconds")
        max_bytes = int(action.inputs.get("max_output", 2 * 1024 * 1024))
        if not 1 <= max_bytes <= 10 * 1024 * 1024:
            raise AdapterError("download max_output must be between 1 byte and 10 MiB")
        digest = context.action_digest or hashlib.sha256(url.encode()).hexdigest()
        if not all(character in "0123456789abcdef" for character in digest.casefold()):
            raise AdapterError("action digest is invalid")
        artifact_root = context.run_root.resolve() / "artifacts"
        artifact_root.mkdir(parents=True, exist_ok=True)
        output = artifact_root / f"web_{digest[:20]}.download"
        return ProcessSpec(
            argv=(
                "curl",
                "--silent",
                "--show-error",
                "--fail",
                "--proto",
                "=http,https",
                "--connect-timeout",
                str(min(timeout, 10)),
                "--max-time",
                str(timeout),
                "--max-filesize",
                str(max_bytes),
                "--output",
                str(output),
                "--write-out",
                "%{json}\\n",
                "--url",
                url,
            ),
            timeout_seconds=timeout + 5,
            max_output_bytes=256 * 1024,
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
        if "--write-out" in spec.argv:
            return self._parse_metadata(result, target, spec)
        try:
            seed = spec.argv[spec.argv.index("--url") + 1]
        except (ValueError, IndexError):
            return ()
        extractor = _LinkExtractor()
        extractor.feed(result.stdout)
        urls = [seed]
        urls.extend(urljoin(seed, reference) for reference in extractor.references)
        # JavaScript assets commonly expose routes through fetch/axios calls
        # rather than HTML links. Extract only literal same-host path strings;
        # dynamic expressions remain untrusted and are ignored.
        urls.extend(
            urljoin(seed, reference)
            for reference in re.findall(
                r"(?:fetch|axios\.(?:get|post|request)|(?:url|endpoint|path))\s*"
                r"(?:\(|:|=)\s*[\"'](?P<path>/[^\"']+)[\"']",
                result.stdout,
                flags=re.IGNORECASE,
            )
        )
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
                        "fetched": url == seed,
                        "parameters": tuple(
                            dict.fromkeys(key for key, _ in parse_qsl(parsed.query))
                        ),
                    },
                )
            )
        return tuple(observations)

    def _parse_metadata(
        self,
        result: ProcessResult,
        target: TargetSpec,
        spec: ProcessSpec,
    ) -> tuple[Observation, ...]:
        output_paths = tuple(
            Path(spec.argv[index + 1])
            for index, argument in enumerate(spec.argv)
            if argument == "--output"
        )
        reference_probe = bool(output_paths and output_paths[0].name.startswith("webref_"))
        download_path = output_paths[0] if len(output_paths) == 1 and not reference_probe else None
        observations: list[Observation] = []
        for record_index, line in enumerate(result.stdout.splitlines()):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            url = record.get("url_effective")
            parsed = urlparse(url) if isinstance(url, str) else None
            if (
                not isinstance(url, str)
                or parsed is None
                or parsed.scheme not in {"http", "https"}
                or parsed.hostname is None
                or parsed.hostname.casefold() != target.host.casefold()
            ):
                continue
            status = record.get("response_code", record.get("http_code"))
            size = record.get("size_download", 0)
            content_type = record.get("content_type") or ""
            if isinstance(status, float) and status.is_integer():
                status = int(status)
            if isinstance(size, float) and size.is_integer():
                size = int(size)
            if not isinstance(status, int) or not isinstance(size, int):
                continue
            if download_path is None:
                observations.append(
                    Observation(
                        observation_id=uuid4(),
                        target=target,
                        source="web_object_reference",
                        data={
                            "type": "object_reference_candidate",
                            "url": url,
                            "path": parsed.path or "/",
                            "status_code": status,
                            "content_type": str(content_type),
                            "size_bytes": size,
                            "download_candidate": (
                                200 <= status < 300
                                and size >= 24
                                and not str(content_type).casefold().startswith("text/html")
                            ),
                        },
                    )
                )
                if (
                    reference_probe
                    and 200 <= status < 300
                    and str(content_type).casefold().startswith("text/html")
                    and record_index < len(output_paths)
                    and output_paths[record_index].is_file()
                ):
                    observations.extend(
                        self._parse_html_references(
                            output_paths[record_index].read_text(
                                encoding="utf-8",
                                errors="replace",
                            ),
                            url,
                            target,
                        )
                    )
                continue
            if result.exit_code != 0 or not 200 <= status < 300 or not download_path.is_file():
                continue
            content = download_path.read_bytes()
            observations.append(
                Observation(
                    observation_id=uuid4(),
                    target=target,
                    source="web_artifact",
                    data={
                        "type": "downloaded_artifact",
                        "url": url,
                        "artifact": download_path.name,
                        "content_type": str(content_type),
                        "size_bytes": len(content),
                        "sha256": hashlib.sha256(content).hexdigest(),
                    },
                )
            )
        return tuple(observations)

    def _parse_html_references(
        self,
        body: str,
        seed: str,
        target: TargetSpec,
    ) -> tuple[Observation, ...]:
        extractor = _LinkExtractor()
        extractor.feed(body)
        observations: list[Observation] = []
        seen: set[str] = set()
        for reference in extractor.references:
            url = urljoin(seed, reference)
            parsed = urlparse(url)
            if (
                url == seed
                or url in seen
                or parsed.scheme not in {"http", "https"}
                or parsed.hostname is None
                or parsed.hostname.casefold() != target.host.casefold()
                or parsed.username is not None
                or parsed.password is not None
                or parsed.fragment
            ):
                continue
            seen.add(url)
            observations.append(
                Observation(
                    observation_id=uuid4(),
                    target=target,
                    source="curl",
                    data={
                        "type": "web_paths",
                        "url": url,
                        "path": parsed.path or "/",
                        "method": "GET",
                        "fetched": False,
                        "discovered_from": seed,
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

    async def collect_for_spec(
        self,
        result: ProcessResult,
        spec: ProcessSpec,
        collector: object,
    ) -> tuple[str, ...]:
        if "--output" not in spec.argv:
            return ()
        output = Path(spec.argv[spec.argv.index("--output") + 1])
        if output.name.startswith("webref_") or not output.is_file():
            return ()
        return (output.name,)

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
