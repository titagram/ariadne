"""Tests for the bounded process runner.

Covers timeout enforcement, output truncation, argv validation
(shell commands, NUL bytes, boundaries), and basic execution.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from ariadne.runtime.process import (
    ProcessRunner,
    ProcessSpec,
    ProcessStatus,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def runner() -> ProcessRunner:
    return ProcessRunner()


# ── ProcessSpec validation ────────────────────────────────────────────────────


class TestProcessSpecValidation:
    def test_rejects_empty_argv(self) -> None:
        with pytest.raises(ValidationError):
            ProcessSpec(argv=(), timeout_seconds=30, max_output_bytes=4096)

    def test_rejects_shell_command_sh(self) -> None:
        with pytest.raises(ValidationError):
            ProcessSpec(argv=("sh", "-c", "nmap target"), timeout_seconds=30, max_output_bytes=4096)

    def test_rejects_shell_command_bash(self) -> None:
        with pytest.raises(ValidationError):
            ProcessSpec(
                argv=("bash", "-c", "nmap target"),
                timeout_seconds=30,
                max_output_bytes=4096,
            )

    def test_rejects_powershell_encoded_command(self) -> None:
        with pytest.raises(ValidationError):
            ProcessSpec(
                argv=("powershell", "-EncodedCommand", "ZwB..."),
                timeout_seconds=30,
                max_output_bytes=4096,
            )

    def test_rejects_pwsh_encoded_command(self) -> None:
        with pytest.raises(ValidationError):
            ProcessSpec(
                argv=("pwsh", "-EncodedCommand", "ZwB..."),
                timeout_seconds=30,
                max_output_bytes=4096,
            )

    def test_rejects_nul_in_argv(self) -> None:
        with pytest.raises(ValidationError):
            ProcessSpec(
                argv=("echo", "hello\x00world"),
                timeout_seconds=30,
                max_output_bytes=4096,
            )

    def test_rejects_negative_timeout(self) -> None:
        with pytest.raises(ValidationError):
            ProcessSpec(argv=("echo", "hi"), timeout_seconds=0, max_output_bytes=4096)

    def test_rejects_timeout_above_limit(self) -> None:
        with pytest.raises(ValidationError):
            ProcessSpec(argv=("echo", "hi"), timeout_seconds=3601, max_output_bytes=4096)

    def test_rejects_output_below_minimum(self) -> None:
        with pytest.raises(ValidationError):
            ProcessSpec(argv=("echo", "hi"), timeout_seconds=30, max_output_bytes=1023)

    def test_rejects_output_above_maximum(self) -> None:
        with pytest.raises(ValidationError):
            ProcessSpec(argv=("echo", "hi"), timeout_seconds=30, max_output_bytes=100_000_001)

    def test_accepts_valid_spec(self) -> None:
        spec = ProcessSpec(argv=("echo", "hi"), timeout_seconds=30, max_output_bytes=4096)
        assert spec.argv == ("echo", "hi")


# ── ProcessRunner execution ──────────────────────────────────────────────────


class TestProcessRunner:
    @pytest.mark.asyncio
    async def test_completes_successfully(self, runner: ProcessRunner) -> None:
        result = await runner.run(
            ProcessSpec(argv=("echo", "hello world"), timeout_seconds=10, max_output_bytes=4096)
        )
        assert result.status is ProcessStatus.COMPLETED
        assert result.exit_code == 0
        assert "hello world" in result.stdout
        assert result.process_tree_terminated is False

    @pytest.mark.asyncio
    async def test_captures_exit_code_and_stderr(self, runner: ProcessRunner) -> None:
        result = await runner.run(
            ProcessSpec(
                argv=("python", "-c", "import sys; print('err', file=sys.stderr); sys.exit(2)"),
                timeout_seconds=10,
                max_output_bytes=4096,
            )
        )
        assert result.status is ProcessStatus.FAILED
        assert result.exit_code == 2
        assert "err" in result.stderr

    @pytest.mark.asyncio
    async def test_kills_process_group_on_timeout(self, runner: ProcessRunner) -> None:
        """Ensure a long-running process is killed and TIMED_OUT is reported."""
        result = await runner.run(
            ProcessSpec(
                argv=("python", "-c", "import time; time.sleep(60)"),
                timeout_seconds=1,
                max_output_bytes=1024,
            )
        )
        assert result.status is ProcessStatus.TIMED_OUT
        assert result.process_tree_terminated

    @pytest.mark.asyncio
    async def test_truncates_stdout_when_exceeding_limit(self, runner: ProcessRunner) -> None:
        """Output exceeding max_output_bytes must be truncated in the result."""
        # Generate ~5KB of output, capped at 1024 bytes (minimum allowed)
        result = await runner.run(
            ProcessSpec(
                argv=("python", "-c", "print('x' * 5000)"),
                timeout_seconds=10,
                max_output_bytes=1024,
            )
        )
        assert len(result.stdout) <= 1024
        assert result.status in (ProcessStatus.COMPLETED, ProcessStatus.OUTPUT_LIMIT_EXCEEDED)

    @pytest.mark.asyncio
    async def test_stdin_is_passed_to_process(self, runner: ProcessRunner) -> None:
        result = await runner.run(
            ProcessSpec(
                argv=("python", "-c", "import sys; print(sys.stdin.read().strip())"),
                timeout_seconds=10,
                max_output_bytes=4096,
                stdin=b"hello from stdin",
            )
        )
        assert result.status is ProcessStatus.COMPLETED
        assert "hello from stdin" in result.stdout

    @pytest.mark.asyncio
    async def test_environment_is_set(self, runner: ProcessRunner) -> None:
        result = await runner.run(
            ProcessSpec(
                argv=(
                    "python",
                    "-c",
                    "import os; print(os.environ.get('ARIADNE_TEST_VAR', 'missing'))",
                ),
                timeout_seconds=10,
                max_output_bytes=4096,
                environment={"ARIADNE_TEST_VAR": "custom_value"},
            )
        )
        assert result.status is ProcessStatus.COMPLETED
        assert "custom_value" in result.stdout

    @pytest.mark.asyncio
    async def test_works_with_cwd(self, runner: ProcessRunner, tmp_path: Path) -> None:
        result = await runner.run(
            ProcessSpec(
                argv=("python", "-c", "import os; print(os.getcwd())"),
                cwd=tmp_path,
                timeout_seconds=10,
                max_output_bytes=4096,
            )
        )
        assert result.status is ProcessStatus.COMPLETED
        assert str(tmp_path) in result.stdout

    @pytest.mark.asyncio
    async def test_drains_stdout_and_stderr_concurrently(self, runner: ProcessRunner) -> None:
        """Both stdout and stderr must be captured from a process that writes to both."""
        result = await runner.run(
            ProcessSpec(
                argv=(
                    "python",
                    "-c",
                    "import sys, time; print('stdout_line'); "
                    "time.sleep(0.05); print('stderr_line', file=sys.stderr)",
                ),
                timeout_seconds=10,
                max_output_bytes=4096,
            )
        )
        assert result.status is ProcessStatus.COMPLETED
        assert "stdout_line" in result.stdout
        assert "stderr_line" in result.stderr
