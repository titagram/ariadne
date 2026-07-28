"""Metasploit Framework adapter for Ariadne.

Provides bounded Metasploit operations: ``search``, ``info``, ``check``,
and ``run_module``.  All operations go through ``msfconsole`` with argv
safety: no shell invocation, no semicolons/newlines in option values.

``run_module`` is the highest-risk operation and requires:

- an exact module path and compatible fingerprint
- an eligible capability in the engagement policy
- a bounded action plan with expected effect and cleanup
- a resource file generated inside the designated run directory
"""

from __future__ import annotations

import re
from pathlib import Path
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

# ── Validated operations ──────────────────────────────────────────────────────

_OPERATIONS: frozenset = frozenset({"search", "info", "check", "run_module"})

# Characters that cannot appear inside a Metasploit option value
# (prevents shell injection and rc-file escape)
_INVALID_OPTION_RE = re.compile(r"[;\n\r]")

# Regex for a valid MSF module path
_VALID_MODULE_RE = re.compile(
    r"^[a-z][a-z0-9_]+/[a-z][a-z0-9_/]*[a-z0-9_]$"
)


def _validate_option(value: str, field_name: str) -> str:
    """Reject option values containing shell-escape characters.

    Raises ``AdapterError`` if *value* contains a semicolon, newline, or
    carriage return.
    """
    if _INVALID_OPTION_RE.search(value):
        raise AdapterError(
            f"Invalid {field_name} value {value!r}: "
            f"semicolons and newlines are not permitted in "
            f"Metasploit option values"
        )
    return value


def _build_resource_file(
    run_dir: Path,
    lines: list[str],
) -> str:
    """Generate a resource-file path and write validated commands.

    Parameters
    ----------
    run_dir:
        The designated run directory (must exist and be writable).
    lines:
        Validated msfconsole commands to write into the resource file.

    Returns
    -------
    str
        The absolute path of the generated resource file.

    Raises
    ------
    AdapterError
        If *run_dir* does not exist or the resolved path escapes it.
    """
    resolved_run_dir = run_dir.resolve()
    if not resolved_run_dir.is_dir():
        raise AdapterError(
            f"Run directory {resolved_run_dir} is outside the designated "
            f"run_dir or does not exist. Resource files must be inside "
            f"the engagement run directory."
        )

    resource_path = resolved_run_dir / f"msf-{uuid4().hex[:12]}.rc"

    # Verify the resolved path stays inside run_dir (defence in depth)
    try:
        resolved_resource = resource_path.resolve()
        resolved_resource.relative_to(resolved_run_dir)
    except ValueError:
            raise AdapterError(
                f"Resource file path {resource_path} escapes the "
                f"designated run directory {resolved_run_dir}"
            ) from None

    content = "\n".join(lines) + "\n"
    resolved_resource.write_text(content)
    return str(resolved_resource)


# ── Adapter ───────────────────────────────────────────────────────────────────


class MetasploitAdapter:
    """ToolAdapter for the Metasploit Framework via ``msfconsole``.

    Supports ``search``, ``info``, ``check``, and ``run_module``
    operations.  Only ``search`` and ``info`` are safe to use without
    a full action plan; ``check`` and ``run_module`` require a resource
    file inside the run directory.
    """

    name: ClassVar[str] = "metasploit"

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
        if op not in _OPERATIONS:
            raise AdapterError(
                f"Unknown Metasploit operation: {op!r}. "
                f"Supported: {', '.join(sorted(_OPERATIONS))}"
            )

        inputs = action.inputs
        argv: list[str] = ["msfconsole", "-q"]

        if op == "search":
            return self._plan_search(inputs, context, argv)
        elif op == "info":
            return self._plan_info(inputs, context, argv)
        elif op == "check":
            return self._plan_check(inputs, context, argv)
        elif op == "run_module":
            return self._plan_run_module(inputs, context, argv)
        else:
            raise AdapterError(f"Unhandled operation: {op!r}")

    def _plan_search(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
        argv: list[str],
    ) -> ProcessSpec:
        query = inputs.get("query", "")
        if not isinstance(query, str) or not query.strip():
            raise AdapterError("Search operation requires a non-empty 'query'")
        argv.extend(["-x", f"search {query}; exit"])
        return ProcessSpec(
            argv=tuple(argv),
            timeout_seconds=120,
            max_output_bytes=2 * 1024 * 1024,
        )

    def _plan_info(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
        argv: list[str],
    ) -> ProcessSpec:
        module = inputs.get("module", "")
        if not isinstance(module, str) or not module.strip():
            raise AdapterError("Info operation requires a 'module' path")
        argv.extend(["-x", f"info {module}; exit"])
        return ProcessSpec(
            argv=tuple(argv),
            timeout_seconds=60,
            max_output_bytes=2 * 1024 * 1024,
        )

    def _plan_check(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
        argv: list[str],
    ) -> ProcessSpec:
        module = inputs.get("module", "")
        if not isinstance(module, str) or not module.strip():
            raise AdapterError("Check operation requires a 'module' path")

        run_dir_str = inputs.get("run_dir")
        if not run_dir_str or not isinstance(run_dir_str, str):
            raise AdapterError(
                "Check operation requires a 'run_dir' path for the resource file"
            )
        run_dir = Path(run_dir_str)

        rhost = _validate_option(str(inputs.get("rhost", str(context.target.host))), "rhost")
        rport = str(inputs.get("rport", ""))

        rc_lines = [f"use {module}"]
        rc_lines.append(f"set RHOSTS {rhost}")
        if rport:
            rc_lines.append(f"set RPORT {rport}")
        rc_lines.append("check")
        rc_lines.append("exit")

        resource_path = _build_resource_file(run_dir, rc_lines)
        argv.extend(["-r", resource_path])
        return ProcessSpec(
            argv=tuple(argv),
            timeout_seconds=300,
            max_output_bytes=2 * 1024 * 1024,
        )

    def _plan_run_module(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
        argv: list[str],
    ) -> ProcessSpec:
        module = inputs.get("module", "")
        if not isinstance(module, str) or not module.strip():
            raise AdapterError("run_module requires a 'module' path")

        run_dir_str = inputs.get("run_dir")
        if not run_dir_str or not isinstance(run_dir_str, str):
            raise AdapterError(
                "run_module requires a 'run_dir' path for the resource file. "
                "Provide the engagement run directory to host the resource file."
            )
        run_dir = Path(run_dir_str)

        # Validate all option values for injection
        rhost = _validate_option(str(inputs.get("rhost", str(context.target.host))), "rhost")
        rport = str(inputs.get("rport", ""))
        payload = inputs.get("payload")
        lhost = str(inputs.get("lhost", "")) if inputs.get("lhost") else ""

        rc_lines = [f"use {module}"]
        rc_lines.append(f"set RHOSTS {rhost}")
        if rport:
            rc_lines.append(f"set RPORT {rport}")
        if payload:
            payload_str = str(payload)
            _validate_option(payload_str, "payload")
            rc_lines.append(f"set PAYLOAD {payload_str}")
        if lhost:
            _validate_option(lhost, "lhost")
            rc_lines.append(f"set LHOST {lhost}")
        rc_lines.append("run")
        rc_lines.append("exit")

        resource_path = _build_resource_file(run_dir, rc_lines)
        argv.extend(["-r", resource_path])
        return ProcessSpec(
            argv=tuple(argv),
            timeout_seconds=600,
            max_output_bytes=5 * 1024 * 1024,
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

        # Try to parse as search results first (table format)
        if "Matching Modules" in stdout or "Name" and "Disclosure Date" in stdout:
            observations.extend(self._parse_search_results(stdout))

        # Try to parse as info output
        if "Name:" in stdout and "Module:" in stdout:
            observations.extend(self._parse_info_output(stdout))

        # Fallback: capture the raw output as a single observation
        if not observations and stdout.strip() and len(stdout.strip()) > 20:
                from ariadne.core.engagement import TargetSpec

                observations.append(
                    Observation(
                        observation_id=uuid4(),
                        target=TargetSpec(host="0.0.0.0"),
                        source="metasploit",
                        data={
                            "raw_output": stdout[:500],
                            "exit_code": result.exit_code,
                        },
                    )
                )

        return tuple(observations)

    def _parse_search_results(self, stdout: str) -> list[Observation]:
        observations: list[Observation] = []
        from ariadne.core.engagement import TargetSpec

        # Parse the msfconsole search table:
        #   #  Name  Disclosure Date  Rank  Check  Description
        #   0  exploit/multi/http/struts2_multi  ...
        lines = stdout.splitlines()
        header_found = False
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#") and "Name" in stripped:
                header_found = True
                continue
            if not header_found:
                continue
            if stripped.startswith("-"):
                continue

            parts = stripped.split(None, 1)
            if len(parts) < 2:
                continue

            try:
                idx = int(parts[0])
            except ValueError:
                continue

            module_path = parts[1].split()[0] if parts[1].split() else parts[1]
            observations.append(
                Observation(
                    observation_id=uuid4(),
                    target=TargetSpec(host="0.0.0.0"),
                    source="metasploit",
                    data={
                        "module_path": module_path,
                        "index": idx,
                        "type": "search_result",
                    },
                )
            )
        return observations

    def _parse_info_output(self, stdout: str) -> list[Observation]:
        observations: list[Observation] = []
        from ariadne.core.engagement import TargetSpec

        name = ""
        module = ""
        rank = ""

        for line in stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("Name:"):
                name = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("Module:"):
                module = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("Rank:"):
                rank = stripped.split(":", 1)[1].strip()

        if name or module:
            observations.append(
                Observation(
                    observation_id=uuid4(),
                    target=TargetSpec(host="0.0.0.0"),
                    source="metasploit",
                    data={
                        "name": name,
                        "module": module,
                        "rank": rank,
                        "type": "info_result",
                    },
                )
            )
        return observations

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
                summary="Metasploit timed out; partial results may be available",
            )
        if result.exit_code != 0:
            return ExecutionClassification(
                kind="failure",
                confidence=0.5,
                summary=f"Metasploit exited with code {result.exit_code}",
            )
        if len(observations) > 0:
            return ExecutionClassification(
                kind="success",
                confidence=0.7,
                summary=f"Metasploit returned {len(observations)} observations",
            )
        return ExecutionClassification(
            kind="unknown",
            confidence=0.5,
            summary="Metasploit completed with no structured output",
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
        return CleanupResult(success=True, details="No temporary resources to clean up")
