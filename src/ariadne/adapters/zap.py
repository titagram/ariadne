"""OWASP ZAP web-application scanning adapter.

Builds a bounded ZAP Automation Framework YAML plan from the engagement
context and parses ZAP JSON alert output into structured Observation
objects.

Safety invariants
-----------------
- The automation plan includes only the confirmed target URL and its
  sub-paths in the context ``includePaths`` regex.
- No shell interpolation: every argument is in the argv tuple.
- Timeout and output size are bounded by ``ProcessSpec``.
- ZAP alerts are treated as candidates, not validated findings.
"""

from __future__ import annotations

import json
import re
from typing import Any, ClassVar
from uuid import uuid4

import yaml

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


def _escape_regex_for_zap(host: str) -> str:
    """Escape a host string for use in a ZAP includePath regex."""
    return re.escape(host)


def _build_automation_plan(context: AdapterContext) -> dict[str, Any]:
    """Build a ZAP Automation Framework plan dict from the engagement context.

    The plan restricts scope to the confirmed target and its sub-paths,
    and includes passive scanning, spidering, and optionally active scan.
    """
    host = str(context.target.host)
    escaped_host = _escape_regex_for_zap(host)

    plan: dict[str, Any] = {
        "env": {
            "contexts": [
                {
                    "name": "ariadne",
                    "urls": [f"https://{host}"],
                    "includePaths": [f"https://{escaped_host}/.*"],
                    "excludePaths": [],
                }
            ]
        },
        "jobs": [
            {
                "type": "passiveScan-config",
                "parameters": {
                    "maxAlertsPerRule": 10,
                },
            },
            {
                "type": "spider",
                "parameters": {
                    "maxDepth": 2,
                    "maxDuration": 5,
                },
            },
        ],
    }

    return plan


_OPERATIONS: frozenset = frozenset({"passive_scan", "active_scan", "spider"})


class ZapAdapter:
    """ToolAdapter for OWASP ZAP web-application scanning.

    Supports ``passive_scan``, ``active_scan``, and ``spider`` operations.
    Generates a ZAP Automation Framework YAML plan from the engagement
    context and feeds it through stdin.
    """

    name: ClassVar[str] = "zap"

    # ── ToolAdapter protocol ─────────────────────────────────────────────

    async def probe(self, runtime: Runtime) -> ToolProbe:
        return ToolProbe(available=True)

    def automation_plan(self, context: AdapterContext) -> dict[str, Any]:
        """Return the ZAP Automation Framework plan dict for *context*.

        This method is public so that contract tests can inspect the
        generated plan structure without executing the tool.
        """
        return _build_automation_plan(context)

    def plan(
        self,
        action: PlannedAction,
        context: AdapterContext,
    ) -> ProcessSpec:
        op = action.operation
        if op not in _OPERATIONS:
            raise AdapterError(
                f"Unknown ZAP operation: {op!r}. "
                f"Supported: {', '.join(sorted(_OPERATIONS))}"
            )

        plan = _build_automation_plan(context)
        inputs = action.inputs

        if op == "active_scan":
            plan["jobs"].append(
                {
                    "type": "activeScan",
                    "parameters": {
                        "maxDuration": int(inputs.get("max_duration", 30)),  # type: ignore[arg-type]
                    },
                }
            )
        elif op == "spider":
            plan["jobs"] = [
                j for j in plan["jobs"] if j["type"] != "spider"
            ]
            plan["jobs"].insert(
                1,
                {
                    "type": "spider",
                    "parameters": {
                        "maxDepth": int(inputs.get("max_depth", 3)),  # type: ignore[arg-type]
                        "maxDuration": int(inputs.get("max_duration", 10)),  # type: ignore[arg-type]
                    },
                },
            )

        # Serialize to YAML for stdin
        yaml_bytes = yaml.dump(plan, default_flow_style=False).encode("utf-8")

        return ProcessSpec(
            argv=(
                "zap.sh",
                "-cmd",
                "-autorun",
                "-",
            ),
            stdin=yaml_bytes,
            timeout_seconds=int(inputs.get("timeout", 600)),  # type: ignore[arg-type]
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

        observations: list[Observation] = []

        try:
            alerts = json.loads(stdout)
        except json.JSONDecodeError as e:
            raise AdapterError(
                f"Failed to parse ZAP output as JSON: {e}"
            ) from e

        if not isinstance(alerts, list):
            return ()

        from ariadne.core.engagement import TargetSpec

        for alert in alerts:
            if not isinstance(alert, dict):
                continue

            obs_data: dict[str, object] = {
                "alert": alert.get("alert", ""),
                "risk": alert.get("risk", ""),
                "confidence": alert.get("confidence", ""),
                "url": alert.get("url", ""),
                "param": alert.get("param", ""),
                "attack": alert.get("attack", ""),
                "evidence": alert.get("evidence", ""),
                "description": alert.get("description", ""),
                "solution": alert.get("solution", ""),
                "alertRef": alert.get("alertRef", ""),
                "pluginId": alert.get("pluginId", ""),
            }

            # Determine target host from the alert URL
            alert_url = alert.get("url", "")
            if isinstance(alert_url, str) and alert_url:
                from urllib.parse import urlparse

                parsed = urlparse(alert_url)
                alert_host = parsed.hostname or "unknown"
            else:
                alert_host = "unknown"

            obs = Observation(
                observation_id=uuid4(),
                target=TargetSpec(host=alert_host),
                source="zap",
                data=obs_data,
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
                summary="ZAP timed out; partial results may be available",
            )
        if result.exit_code != 0:
            return ExecutionClassification(
                kind="failure",
                confidence=0.5,
                summary=f"ZAP exited with code {result.exit_code}",
            )
        if len(observations) > 0:
            risks = [o.data.get("risk", "") for o in observations]
            high_risks = [r for r in risks if r == "High"]
            if high_risks:
                return ExecutionClassification(
                    kind="success",
                    confidence=0.7,
                    summary=f"Found {len(observations)} alerts ({len(high_risks)} high risk)",
                )
            return ExecutionClassification(
                kind="success",
                confidence=0.6,
                summary=f"Found {len(observations)} alerts",
            )
        return ExecutionClassification(
            kind="unknown",
            confidence=0.5,
            summary="ZAP completed with no alerts",
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
