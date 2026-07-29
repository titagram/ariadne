"""Bounded local probing and atomic runtime verification promotion."""

from __future__ import annotations

import os
import selectors
import shutil
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import ValidationError

from ariadne.knowledge.catalog import KnowledgeIndex
from ariadne.knowledge.models import (
    RuntimeVerification,
    ToolCard,
    ToolDiscovery,
    ToolVerificationBlockedError,
)

OfficialProvider = Callable[[str, int], str]
GuidanceSource = Literal["local_help", "local_man", "official_provider"]


def _bounded_text(value: bytes | str, limit: int) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return raw[:limit].decode("utf-8", errors="ignore").strip()


class LocalToolProbe:
    """Inspect only version and concise local help under strict bounds."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 3,
        max_output_bytes: int = 4096,
        man_executable: str | None = "man",
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_output_bytes < 1:
            raise ValueError("max_output_bytes must be positive")
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes
        self.man_executable = man_executable

    def inspect(
        self,
        card: ToolCard,
        official_provider: OfficialProvider | None,
    ) -> tuple[str, str, str, GuidanceSource]:
        executable = self._resolve(card.executable)
        version = self._run((executable, *card.version_args))
        if version is None:
            raise ToolVerificationBlockedError(
                f"{card.id}: local version probe failed or returned no version"
            )

        help_text = self._run(
            (executable, *card.help_args),
            accept_truncated=True,
        )
        if help_text:
            return executable, version, help_text, "local_help"

        if self.man_executable:
            man = shutil.which(self.man_executable)
            if man is not None:
                man_text = self._run(
                    (man, Path(executable).name),
                    pager_safe=True,
                    accept_truncated=True,
                )
                if man_text:
                    return executable, version, man_text, "local_man"

        if official_provider is None:
            raise ToolVerificationBlockedError(
                f"{card.id}: no local help and no injected official provider"
            )
        official_text = _bounded_text(
            official_provider(card.official_source_url, self.max_output_bytes),
            self.max_output_bytes,
        )
        if not official_text:
            raise ToolVerificationBlockedError(f"{card.id}: official provider returned no guidance")
        return executable, version, official_text, "official_provider"

    @staticmethod
    def _resolve(executable: str) -> str:
        candidate = Path(executable)
        if candidate.is_absolute():
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
            raise ToolVerificationBlockedError(f"tool executable is unavailable: {executable}")
        resolved = shutil.which(executable)
        if resolved is None:
            raise ToolVerificationBlockedError(f"tool executable is unavailable: {executable}")
        return resolved

    def _run(
        self,
        argv: tuple[str, ...],
        *,
        pager_safe: bool = False,
        accept_truncated: bool = False,
    ) -> str | None:
        environment = os.environ.copy()
        environment["LC_ALL"] = "C"
        if pager_safe:
            environment["MANPAGER"] = "cat"
            environment["PAGER"] = "cat"
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=environment,
            )
        except OSError:
            return None

        assert process.stdout is not None
        output = bytearray()
        deadline = time.monotonic() + self.timeout_seconds
        clipped = False
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    process.kill()
                    process.wait()
                    return None
                events = selector.select(remaining_time)
                if not events:
                    if process.poll() is not None:
                        break
                    continue
                chunk = os.read(
                    process.stdout.fileno(),
                    min(4096, self.max_output_bytes + 1 - len(output)),
                )
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > self.max_output_bytes:
                    clipped = True
                    process.kill()
                    process.wait()
                    break

        if clipped:
            return _bounded_text(bytes(output), self.max_output_bytes) if accept_truncated else None
        try:
            return_code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            return None
        if return_code != 0:
            return None
        bounded_output = _bounded_text(bytes(output), self.max_output_bytes)
        return bounded_output or None


class RuntimeVerificationStore:
    """Small immutable-record store using same-directory atomic replacement."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def _path(self, tool_id: str) -> Path:
        safe_name = tool_id.replace("/", "_").replace("\\", "_")
        return self.root / f"{safe_name}.json"

    def get(self, tool_id: str) -> RuntimeVerification | None:
        path = self._path(tool_id)
        if not path.exists():
            return None
        try:
            return RuntimeVerification.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError) as exc:
            raise ToolVerificationBlockedError(
                f"{tool_id}: invalid runtime verification record"
            ) from exc

    def promote(self, record: RuntimeVerification) -> None:
        """Atomically make a successful verification visible."""
        self.root.mkdir(parents=True, exist_ok=True)
        destination = self._path(record.tool_id)
        temporary = self.root / f".{destination.name}.{uuid4().hex}.tmp"
        try:
            with temporary.open("x", encoding="utf-8") as handle:
                handle.write(record.model_dump_json())
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)


class ToolCardVerifier:
    """Policy-gated JIT tool-card verifier."""

    def __init__(
        self,
        *,
        index: KnowledgeIndex,
        probe: LocalToolProbe,
        store: RuntimeVerificationStore,
        official_provider: OfficialProvider | None = None,
    ) -> None:
        self.index = index
        self.probe = probe
        self.store = store
        self.official_provider = official_provider

    def inspect(
        self,
        tool_id: str,
        *,
        allowed_policy: frozenset[str],
        inspection: tuple[str, str, str, GuidanceSource] | None = None,
    ) -> RuntimeVerification:
        card = self.index.tool_card(tool_id)
        denied = sorted(card.policy - allowed_policy)
        if denied:
            raise ToolVerificationBlockedError(
                f"{tool_id}: policy requirements are not allowed: {', '.join(denied)}"
            )

        if inspection is None:
            executable, version, guidance, guidance_source = self.probe.inspect(
                card,
                self.official_provider,
            )
        else:
            executable, version, guidance, guidance_source = inspection
            executable = executable.strip()
            version = _bounded_text(version, 4096)
            guidance = _bounded_text(guidance, 4096)
            if not executable or not version or not guidance:
                raise ToolVerificationBlockedError(f"{tool_id}: runtime inspection was incomplete")
        record = RuntimeVerification(
            tool_id=card.id,
            card_digest=card.digest,
            status="documented",
            executable_path=executable,
            version=version,
            guidance=guidance,
            guidance_source=guidance_source,
            verified_at=datetime.now(UTC).isoformat(),
        )
        return record

    def inspect_or_discover(
        self,
        discovery: ToolDiscovery,
        *,
        allowed_policy: frozenset[str],
        inspection: tuple[str, str, str, GuidanceSource] | None = None,
    ) -> RuntimeVerification:
        """Create a missing concise card, then inspect its installed version."""
        self.index.discover_tool(discovery)
        return self.inspect(
            discovery.tool_id,
            allowed_policy=allowed_policy,
            inspection=inspection,
        )

    def promote_after_success(
        self,
        record: RuntimeVerification,
    ) -> RuntimeVerification:
        """Promote only after the actual bounded tool action succeeded."""
        verified = record.model_copy(
            update={
                "status": "runtime_verified",
                "verified_at": datetime.now(UTC).isoformat(),
            }
        )
        self.index.promote_tool(verified)
        self.store.promote(verified)
        return verified

    def verify(
        self,
        tool_id: str,
        *,
        allowed_policy: frozenset[str],
    ) -> RuntimeVerification:
        """Compatibility helper for callers that already proved tool success."""
        return self.promote_after_success(self.inspect(tool_id, allowed_policy=allowed_policy))
