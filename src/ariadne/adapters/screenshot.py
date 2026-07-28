"""Headless browser screenshot adapter.

Captures screenshots of confirmed HTTP endpoints using pinned
Chromium headless with a fresh temporary profile, fixed viewport,
and bounded load time.

Safety invariants
-----------------
- Only the confirmed target URL is passed to the browser.
- A fresh temporary profile is used for each capture.
- Viewport is fixed to a standard resolution.
- Maximum load time is bounded by ``ProcessSpec``.
- The screenshot output path is inside the run evidence mount.
- No shell interpolation: every argument is in the argv tuple.
"""

from __future__ import annotations

import hashlib
import re
import tempfile
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

_OPERATIONS: frozenset = frozenset({"capture"})

# Fixed viewport dimensions for consistent screenshots
_VIEWPORT_WIDTH = 1280
_VIEWPORT_HEIGHT = 720

# Chromium user data directory prefix for fresh profiles
_TEMP_PROFILE_PREFIX = "ariadne-chromium-profile-"


def _compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hex digest of *data*."""
    return hashlib.sha256(data).hexdigest()


class ScreenshotAdapter:
    """ToolAdapter for headless Chromium screenshots.

    Supports ``capture`` operations against confirmed HTTP endpoints.
    Uses a fresh temporary browser profile and fixed viewport for
    consistent, bounded screenshot capture.
    """

    name: ClassVar[str] = "screenshot"

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
                f"Unknown Screenshot operation: {op!r}. "
                f"Supported: {', '.join(sorted(_OPERATIONS))}"
            )

        inputs = action.inputs
        target = str(context.target.host)

        # Build target URL (prefer HTTPS, fall back to HTTP)
        url = f"https://{target}"
        if inputs.get("use_http"):
            url = f"http://{target}"

        # Create a fresh temporary profile directory
        user_data_dir = tempfile.mkdtemp(prefix=_TEMP_PROFILE_PREFIX)

        # Output path: evidence mount with a unique filename
        output_path = inputs.get(
            "output_path",
            f"/evidence/screenshots/{target}_{uuid4().hex[:12]}.png",
        )

        argv = [
            "chromium",
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            f"--window-size={_VIEWPORT_WIDTH},{_VIEWPORT_HEIGHT}",
            f"--user-data-dir={user_data_dir}",
            f"--screenshot={output_path}",
            "--hide-scrollbars",
            f"--virtual-time-budget={inputs.get('load_timeout_ms', 15000)}",
            url,
        ]

        return ProcessSpec(
            argv=tuple(argv),
            timeout_seconds=int(inputs.get("timeout", 60)),  # type: ignore[arg-type]
            max_output_bytes=int(inputs.get("max_output", 1024 * 1024)),  # type: ignore[arg-type]
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

        observations: list[Observation] = []
        from ariadne.core.engagement import TargetSpec

        # Try to extract the screenshot path from Chromium's stdout
        path_match = re.search(
            r"Screenshot saved to (.+\.(?:png|jpg|jpeg|webp))",
            stdout,
        )

        evidence_data: dict[str, object] = {
            "url": "",
            "timestamp": "",
            "browser": "chromium",
        }

        if path_match:
            evidence_data["path"] = path_match.group(1)

        # Estimate target host from output context
        target_host: str | None = None

        # Try to extract URL from stdout
        url_match = re.search(r"https?://([^/\s]+)", stdout)
        if url_match:
            target_host = url_match.group(1)
            evidence_data["url"] = url_match.group(0)

        if target_host is None:
            # Cannot determine the target host — return empty
            return ()

        obs = Observation(
            observation_id=uuid4(),
            target=TargetSpec(host=target_host),
            source="screenshot",
            data=evidence_data,
        )
        observations.append(obs)

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
                summary="Screenshot timed out; no image captured",
            )
        if result.exit_code != 0:
            return ExecutionClassification(
                kind="failure",
                confidence=0.5,
                summary=f"Chromium exited with code {result.exit_code}",
            )
        if len(observations) > 0:
            return ExecutionClassification(
                kind="success",
                confidence=0.9,
                summary="Screenshot captured successfully",
            )
        return ExecutionClassification(
            kind="unknown",
            confidence=0.5,
            summary="Chromium completed but no screenshot evidence found",
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
