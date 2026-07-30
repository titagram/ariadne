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

import ipaddress
import json
import re
from typing import Any, ClassVar
from urllib.parse import urlparse
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
from ariadne.core.engagement import TargetSpec
from ariadne.core.observations import Observation


def _build_automation_plan(
    context: AdapterContext,
    *,
    seed_url: str | None = None,
    http_host: str | None = None,
) -> dict[str, Any]:
    """Build a ZAP Automation Framework plan dict from the engagement context.

    The plan restricts scope to the confirmed target and its sub-paths,
    and includes passive scanning, spidering, and optionally active scan.
    """
    host = str(context.target.host)
    target_url = seed_url or f"https://{host}"
    parsed = urlparse(target_url)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.hostname.casefold() != host.casefold()
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise AdapterError(f"ZAP seed {target_url!r} is outside the exact target scope")
    if http_host is not None:
        alias = TargetSpec(host=http_host).host
        if alias == context.target.host:
            raise AdapterError("http_host must be distinct from the network target")
        try:
            ipaddress.ip_address(alias)
        except ValueError:
            http_host = alias
        else:
            raise AdapterError("http_host must be an approved FQDN alias")

    try:
        port = parsed.port
    except ValueError as exc:
        raise AdapterError(f"ZAP seed {target_url!r} has an invalid port") from exc
    scan_host = http_host or parsed.hostname
    scan_port = (
        None
        if (parsed.scheme, port) in {("http", 80), ("https", 443)}
        else port
    )
    scan_netloc = f"{scan_host}:{scan_port}" if scan_port is not None else str(scan_host)
    root_url = f"{parsed.scheme}://{scan_netloc}"
    escaped_root = re.escape(root_url)

    jobs: list[dict[str, Any]] = [
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
    ]
    plan: dict[str, Any] = {
        "env": {
            "contexts": [
                {
                    "name": "ariadne",
                    "urls": [root_url],
                    "includePaths": [f"{escaped_root}/.*"],
                    "excludePaths": [],
                }
            ]
        },
        "jobs": jobs,
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
                f"Unknown ZAP operation: {op!r}. Supported: {', '.join(sorted(_OPERATIONS))}"
            )

        inputs = action.inputs
        seed_url = inputs.get("url")
        if seed_url is not None and not isinstance(seed_url, str):
            raise AdapterError("ZAP url must be a string")
        http_host = inputs.get("http_host")
        if http_host is not None and not isinstance(http_host, str):
            raise AdapterError("http_host must be a hostname")
        plan = _build_automation_plan(
            context,
            seed_url=seed_url,
            http_host=http_host,
        )

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
            plan["jobs"] = [j for j in plan["jobs"] if j["type"] != "spider"]
            plan["jobs"].append(
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
        requested_timeout = int(inputs.get("timeout", 600))  # type: ignore[arg-type]
        timeout = min(
            requested_timeout,
            context.limits.max_duration_seconds or requested_timeout,
        )

        return ProcessSpec(
            argv=(
                "zaproxy",
                "-cmd",
                "-silent",
                "-autorun",
                "/dev/stdin",
            ),
            environment=(
                {
                    "ARIADNE_ZAP_HTTP_HOST": http_host,
                    "ARIADNE_ZAP_NETWORK_TARGET": str(context.target.host),
                }
                if http_host is not None
                else {}
            ),
            stdin=yaml_bytes,
            timeout_seconds=timeout,
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
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            # Automation Framework progress and JVM logs are not findings.
            # Preserve them as process output without inventing observations.
            return ()

        alerts: list[object] = []
        if isinstance(payload, list):
            alerts = payload
        elif isinstance(payload, dict):
            sites = payload.get("site")
            if isinstance(sites, list):
                for site in sites:
                    if isinstance(site, dict) and isinstance(site.get("alerts"), list):
                        alerts.extend(site["alerts"])

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
                "pluginId": alert.get("pluginId", alert.get("pluginid", "")),
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
            kind="success",
            confidence=0.8,
            summary="ZAP completed successfully with no alerts",
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
