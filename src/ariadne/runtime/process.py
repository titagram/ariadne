"""Bounded subprocess runner for Ariadne tool adapters.

Provides a safe, bounded ``ProcessRunner`` that enforces timeouts, output
limits, and argv safety invariants (no shell invocation, no NUL bytes,
no encoded PowerShell commands).

Every subprocess is created in a new process group so that timeout
termination can kill the entire process tree.  stderr and stdout are
drained concurrently via asyncio subprocess pipes.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ProcessStatus(StrEnum):
    """Execution status of a bounded process."""

    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    OUTPUT_LIMIT_EXCEEDED = "output_limit_exceeded"


class ProcessSpec(BaseModel):
    """Bounded, validated specification for subprocess execution.

    Every field is validated at construction time:
    - ``argv`` must be non-empty and free of shell-invocation patterns
    - ``timeout_seconds`` is clamped to [1, 3600]
    - ``max_output_bytes`` is clamped to [1024, 100_000_000]
    - No ``argv`` element may contain a NUL byte
    - ``sh -c``, ``bash -c``, ``powershell -EncodedCommand``,
      and ``pwsh -EncodedCommand`` are rejected
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    argv: tuple[str, ...] = Field(min_length=1)
    cwd: Path | None = None
    environment: Mapping[str, str] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=300, ge=1, le=3600)
    max_output_bytes: int = Field(default=1_048_576, ge=1024, le=100_000_000)
    stdin: bytes | None = None

    _SHELL_INVOCATIONS: tuple[tuple[str, ...], ...] = (
        ("sh", "-c"),
        ("bash", "-c"),
        ("dash", "-c"),
        ("zsh", "-c"),
        ("ksh", "-c"),
        ("powershell", "-EncodedCommand"),
        ("pwsh", "-EncodedCommand"),
    )

    def _has_nul(self, value: str) -> bool:
        return "\x00" in value

    def _is_shell_invocation(self, argv: tuple[str, ...]) -> bool:
        normalized = (Path(argv[0]).name, *argv[1:])
        for prefix in self._SHELL_INVOCATIONS:
            if (
                len(normalized) >= len(prefix)
                and normalized[: len(prefix)] == prefix
            ):
                return True
        return False

    @model_validator(mode="after")
    def _validate_argv(self) -> ProcessSpec:
        if not self.argv:
            raise ValueError("argv must be non-empty")

        if self._is_shell_invocation(self.argv):
            first = self.argv[0]
            second = self.argv[1] if len(self.argv) > 1 else ""
            raise ValueError(
                f"Shell invocation rejected: {first} {second} is not allowed"
            )

        for i, arg in enumerate(self.argv):
            if self._has_nul(arg):
                raise ValueError(
                    f"NUL byte in argv[{i}] is not allowed"
                )

        return self


class ProcessResult(BaseModel):
    """Result of a bounded process execution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    exit_code: int
    stdout: str
    stderr: str
    status: ProcessStatus = ProcessStatus.COMPLETED
    output_truncated: bool = False
    process_tree_terminated: bool = False

    # Backward-compat alias (used by DockerRuntime.exec before Task 13)
    timed_out: bool = False


class ProcessLimits(BaseModel):
    """Bounded execution limits (subset of ProcessSpec for Docker exec).

    This type exists for backward compatibility with ``DockerRuntime.exec``
    which passes only the limit fields, not a full spec.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    timeout_seconds: int = Field(default=300, ge=1, le=3600)
    max_output_bytes: int = Field(default=10 * 1024 * 1024, ge=1024, le=100_000_000)


class ProcessRunner:
    """Async bounded subprocess runner.

    Launches each process in a new process group (``start_new_session``)
    so that a timeout can kill the entire process tree via ``SIGTERM`` /
    ``SIGKILL`` escalation.  Stdout and stderr are drained concurrently.
    """

    _KILL_GRACE_SECONDS: float = 2.0

    async def run(self, spec: ProcessSpec) -> ProcessResult:
        """Execute *spec* and return a bounded ``ProcessResult``.

        Raises ``ProcessError`` if the process cannot be started.
        """
        process = await asyncio.create_subprocess_exec(
            *spec.argv,
            cwd=spec.cwd,
            env={
                **os.environ,
                **dict(spec.environment),
            }
            if spec.environment
            else None,
            stdin=asyncio.subprocess.PIPE if spec.stdin is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )

        # Feed stdin if provided, then close the pipe
        if spec.stdin is not None and process.stdin is not None:
            process.stdin.write(spec.stdin)
            await process.stdin.drain()
            process.stdin.close()

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(),
                timeout=spec.timeout_seconds,
            )
        except TimeoutError:
            return await self._handle_timeout(process, spec)

        # Process completed before timeout
        exit_code = process.returncode if process.returncode is not None else -1
        stdout_str = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
        stderr_str = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""

        output_truncated = False
        if len(stdout_str) > spec.max_output_bytes:
            stdout_str = stdout_str[: spec.max_output_bytes]
            output_truncated = True
        if len(stderr_str) > spec.max_output_bytes:
            stderr_str = stderr_str[: spec.max_output_bytes]
            output_truncated = True

        if exit_code != 0:
            status = ProcessStatus.FAILED
        elif output_truncated:
            status = ProcessStatus.OUTPUT_LIMIT_EXCEEDED
        else:
            status = ProcessStatus.COMPLETED

        return ProcessResult(
            exit_code=exit_code,
            stdout=stdout_str,
            stderr=stderr_str,
            status=status,
            output_truncated=output_truncated,
        )

    async def _handle_timeout(
        self,
        process: asyncio.subprocess.Process,
        spec: ProcessSpec,
    ) -> ProcessResult:
        """Kill the timed-out process tree and return a TIMED_OUT result."""
        pid = process.pid
        tree_terminated = False

        if pid is not None:
            try:
                # Kill the entire process group (negative PID = PGID)
                os.killpg(pid, signal.SIGTERM)
                tree_terminated = True
            except (ProcessLookupError, PermissionError, OSError):
                pass

            if tree_terminated:
                try:
                    await asyncio.wait_for(
                        process.wait(),
                        timeout=self._KILL_GRACE_SECONDS,
                    )
                except TimeoutError:
                    # Escalate to SIGKILL
                    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                        os.killpg(pid, signal.SIGKILL)
                    await process.wait()

        # Read any partial output before the kill
        partial_stdout: str = ""
        partial_stderr: str = ""
        for stream, attr in [
            (process.stdout, "stdout"),
            (process.stderr, "stderr"),
        ]:
            if stream is not None:
                try:
                    remaining = await asyncio.wait_for(
                        stream.read(), timeout=self._KILL_GRACE_SECONDS
                    )
                    decoded = remaining.decode("utf-8", errors="replace") if remaining else ""
                    if attr == "stdout":
                        partial_stdout = decoded
                    else:
                        partial_stderr = decoded
                except (TimeoutError, Exception):
                    pass

        if len(partial_stdout) > spec.max_output_bytes:
            partial_stdout = partial_stdout[: spec.max_output_bytes]
        if len(partial_stderr) > spec.max_output_bytes:
            partial_stderr = partial_stderr[: spec.max_output_bytes]

        return ProcessResult(
            exit_code=-1,
            stdout=partial_stdout,
            stderr=partial_stderr,
            status=ProcessStatus.TIMED_OUT,
            process_tree_terminated=tree_terminated,
        )
