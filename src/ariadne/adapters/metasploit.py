"""Metasploit Framework adapter for Ariadne.

Provides bounded Metasploit operations: ``search``, ``info``, ``check``,
and ``run_module``.  All operations go through ``msfconsole`` with argv
safety: no shell invocation, no semicolons/newlines in option values.

``run_module`` is the highest-risk operation and requires:

- an exact module path and compatible fingerprint
- an eligible capability in the engagement policy
- a bounded action plan with expected effect and cleanup
- a persisted positive ``check`` result for the exact target and module
"""

from __future__ import annotations

import re
from typing import ClassVar, cast
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
_VALID_MODULE_RE = re.compile(r"^[a-z][a-z0-9_]+/[a-z][a-z0-9_/]*[a-z0-9_]$")


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


def _validated_candidate(
    inputs: dict[str, object],
    context: AdapterContext,
    *,
    require_check: bool = False,
) -> dict[str, object]:
    candidate = inputs.get("validated_candidate")
    if not isinstance(candidate, dict):
        raise AdapterError("Metasploit verification/use requires a validated candidate")
    candidate_map = cast(dict[str, object], candidate)
    required = {
        "candidate_id",
        "cve_id",
        "product",
        "version",
        "target",
        "validation_status",
        "compatible",
        "applicability_evidence",
        "module",
        "evidence_id",
        "provenance",
    }
    if (
        not required.issubset(candidate_map)
        or candidate_map.get("validation_status") != "validated"
        or candidate_map.get("compatible") is not True
        or candidate_map.get("target") != context.target.host
    ):
        raise AdapterError("Metasploit candidate is not validated, compatible, and target-bound")
    applicability = candidate_map.get("applicability_evidence")
    if (
        not isinstance(applicability, (list, tuple))
        or not applicability
        or not all(isinstance(item, str) and item.strip() for item in applicability)
    ):
        raise AdapterError("Metasploit candidate has no version/CPE applicability evidence")
    module = candidate_map.get("module")
    if (
        not isinstance(module, str)
        or _VALID_MODULE_RE.fullmatch(module) is None
        or inputs.get("module") != module
    ):
        raise AdapterError("Metasploit module must exactly match the validated candidate")
    if not all(
        isinstance(candidate_map.get(field), str) and str(candidate_map[field]).strip()
        for field in (
            "candidate_id",
            "cve_id",
            "product",
            "version",
            "target",
            "evidence_id",
            "provenance",
        )
    ):
        raise AdapterError("Metasploit candidate provenance is incomplete")
    if require_check and (
        inputs.get("check_status") != "vulnerable"
        or not isinstance(inputs.get("check_evidence_id"), str)
        or not str(inputs["check_evidence_id"]).strip()
    ):
        raise AdapterError(
            "Metasploit use requires a vulnerable check and persisted check evidence"
        )
    return candidate_map


# ── Adapter ───────────────────────────────────────────────────────────────────


class MetasploitAdapter:
    """ToolAdapter for the Metasploit Framework via ``msfconsole``.

    Supports ``search``, ``info``, ``check``, and ``run_module``
    operations. ``search`` discovers modules; ``info``/``check`` require a
    validated compatible research candidate; ``run_module`` additionally
    requires persisted evidence that ``check`` reported vulnerable.
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
                f"Unknown Metasploit operation: {op!r}. Supported: {', '.join(sorted(_OPERATIONS))}"
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
        _validated_candidate(inputs, context)
        module = inputs.get("module", "")
        assert isinstance(module, str)
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
        _validated_candidate(inputs, context)
        module = inputs.get("module", "")
        assert isinstance(module, str)

        rhost = _validate_option(str(inputs.get("rhost", str(context.target.host))), "rhost")
        if rhost != context.target.host:
            raise AdapterError("Metasploit RHOSTS must equal the engagement target")
        rport = str(inputs.get("rport", ""))
        _validate_option(rport, "rport")

        rc_lines = [f"use {module}"]
        rc_lines.append(f"set RHOSTS {rhost}")
        if rport:
            rc_lines.append(f"set RPORT {rport}")
        rc_lines.append("check")
        rc_lines.append("exit")

        argv.extend(["-x", "; ".join(rc_lines)])
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
        _validated_candidate(inputs, context, require_check=True)
        module = inputs.get("module", "")
        assert isinstance(module, str)

        # Validate all option values for injection
        rhost = _validate_option(str(inputs.get("rhost", str(context.target.host))), "rhost")
        if rhost != context.target.host:
            raise AdapterError("Metasploit RHOSTS must equal the engagement target")
        rport = str(inputs.get("rport", ""))
        _validate_option(rport, "rport")
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

        argv.extend(["-x", "; ".join(rc_lines)])
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

    def parse_for_spec(
        self,
        result: ProcessResult,
        target: object,
        spec: ProcessSpec,
    ) -> tuple[Observation, ...]:
        """Parse target-affecting commands without inventing success."""
        from ariadne.core.engagement import TargetSpec

        if not isinstance(target, TargetSpec):
            raise AdapterError("Metasploit parsing requires an explicit target")
        commands = (
            {command.strip() for command in spec.argv[-1].split(";") if command.strip()}
            if len(spec.argv) == 4 and spec.argv[2] == "-x"
            else set()
        )
        module = next(
            (
                command.removeprefix("use ").strip()
                for command in commands
                if command.startswith("use ")
            ),
            "",
        )
        output = f"{result.stdout}\n{result.stderr}".casefold()
        if "check" in commands:
            if "not vulnerable" in output or "safe" in output:
                check_status = "safe"
            elif (
                "target is vulnerable" in output
                or "appears to be vulnerable" in output
                or "vulnerable:" in output
            ):
                check_status = "vulnerable"
            else:
                check_status = "unknown"
            source = (
                "metasploit_check_vulnerable"
                if check_status == "vulnerable"
                else "metasploit_check"
            )
            return (
                Observation(
                    observation_id=uuid4(),
                    target=target,
                    source=source,
                    data={
                        "type": source,
                        "module": module,
                        "check_status": check_status,
                        "summary": (f"Metasploit check result: {check_status}"),
                    },
                ),
            )
        if "run" in commands:
            succeeded = bool(
                re.search(
                    r"(?:meterpreter|command shell|session \d+) session "
                    r"(?:opened|created)",
                    output,
                )
            )
            source = "exploit_succeeded" if succeeded else "metasploit_run"
            return (
                Observation(
                    observation_id=uuid4(),
                    target=target,
                    source=source,
                    data={
                        "type": source,
                        "module": module,
                        "session_opened": succeeded,
                        "summary": (
                            "Metasploit established a session"
                            if succeeded
                            else "Metasploit ran without proof of a session"
                        ),
                    },
                ),
            )
        return tuple(
            observation.model_copy(update={"target": target}) for observation in self.parse(result)
        )

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
