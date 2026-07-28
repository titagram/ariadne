"""Docker Compose lifecycle for the Ariadne container stack.

Manages the pinned Kali, ZAP, and netguard containers. Engines the
lifecycle contract: ``prepare`` (build + up), ``exec`` (run a command
inside a service), and ``destroy`` (teardown).

Forward-reference types
-----------------------
``RuntimeHandle``, ``ProcessLimits``, and ``ProcessResult`` are defined
here as minimal Pydantic models so that ``DockerRuntime`` can be imported
and used before Task 13 introduces the canonical bounded-runner types.
Task 13 should re-export these or alias the canonical versions.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from ariadne.core.engagement import EngagementSnapshot

# ── Canonical types (re-exported from Task 13's process module) ──────────
# These were forward references before Task 13.  Now they're defined in
# runtime/process.py and re-exported here for backward compatibility.
from ariadne.runtime.process import ProcessLimits as ProcessLimits  # noqa: F811
from ariadne.runtime.process import ProcessResult as ProcessResult  # noqa: F811


@dataclass(frozen=True)
class RuntimeHandle:
    """Opaque handle representing a running container stack instance.

    Carries enough context for ``destroy()`` to tear down the correct
    stack (Compose project name, working directory, snapshot identity).
    """

    compose_dir: Path
    project_name: str
    snapshot: EngagementSnapshot


# ── DockerRuntime ────────────────────────────────────────────────────────

_COMPOSE_DIR: Final[Path] = Path(__file__).resolve().parent.parent.parent.parent / "containers"


class DockerRuntime:
    """Lifecycle manager for the Ariadne container stack.

    Every operation delegates to ``docker compose`` in the ``containers/``
    directory using the project name ``ariadne``.
    """

    def __init__(self, compose_dir: Path = _COMPOSE_DIR) -> None:
        self._compose_dir = compose_dir.resolve(strict=True)
        self._project_name = "ariadne"
        self._env = os.environ.copy()

    def prepare(self, snapshot: EngagementSnapshot) -> RuntimeHandle:
        """Build images and start the container stack for *snapshot*.

        Passes the snapshot's confirmed target addresses as the
        ``ARIADNE_ALLOW_TARGETS`` environment variable so that netguard
        generates the correct nftables allowlist.

        Returns a ``RuntimeHandle`` that must be passed to ``destroy()``
        for clean teardown.
        """
        targets = _targets_to_allowlist(snapshot)
        self._env["ARIADNE_ALLOW_TARGETS"] = targets

        # Bring the stack up (build if needed) and wait for readiness
        self._compose("up", "--build", "--detach", "--wait")

        return RuntimeHandle(
            compose_dir=self._compose_dir,
            project_name=self._project_name,
            snapshot=snapshot,
        )

    def exec(
        self,
        service: str,
        argv: tuple[str, ...],
        limits: ProcessLimits,
    ) -> ProcessResult:
        """Execute *argv* in *service* with given *limits*.

        Runs ``docker compose exec -T <service> <argv...>``.
        """
        cmd: list[str] = ["exec", "-T", service]
        cmd.extend(argv)

        try:
            result = subprocess.run(
                self._compose_cmd(cmd),
                capture_output=True,
                text=True,
                timeout=limits.timeout_seconds,
                env=self._env,
            )
        except subprocess.TimeoutExpired as exc:
            stdout: str = ""
            stderr: str = ""
            if isinstance(exc.stdout, bytes):
                stdout = exc.stdout.decode("utf-8", errors="replace")
            elif exc.stdout is not None:
                stdout = exc.stdout
            if isinstance(exc.stderr, bytes):
                stderr = exc.stderr.decode("utf-8", errors="replace")
            elif exc.stderr is not None:
                stderr = exc.stderr
            return ProcessResult(
                exit_code=-1,
                stdout=stdout,
                stderr=stderr,
                timed_out=True,
            )

        stdout = result.stdout[: limits.max_output_bytes]
        stderr = result.stderr[: limits.max_output_bytes]

        return ProcessResult(
            exit_code=result.returncode,
            stdout=stdout,
            stderr=stderr,
        )

    def destroy(self, handle: RuntimeHandle) -> None:
        """Tear down the container stack identified by *handle*."""
        self._compose("down", "--volumes", "--remove-orphans")

    # ── Internal helpers ────────────────────────────────────────────────

    def _compose_cmd(self, args: list[str]) -> list[str]:
        return [
            "docker",
            "compose",
            "-f",
            str(self._compose_dir / "compose.yaml"),
            "-p",
            self._project_name,
            *args,
        ]

    def _compose(self, *args: str) -> None:
        cmd = self._compose_cmd(list(args))
        subprocess.run(cmd, check=True, capture_output=True, timeout=120, env=self._env)


# ── Utility ──────────────────────────────────────────────────────────────


def _targets_to_allowlist(snapshot: EngagementSnapshot) -> str:
    """Convert snapshot targets to the ``ARIADNE_ALLOW_TARGETS`` format.

    Returns a space-separated ``ip:port`` list. In v1, known ports
    are derived from common service ports; a future task can enrich
    this from the snapshot's objective or a configured port list.

    For now, each target gets: 22, 80, 443, 8080, 8443 (common initial
    recon ports).
    """
    default_ports: Final[tuple[int, ...]] = (22, 80, 443, 8080, 8443)
    entries: list[str] = []
    for t in snapshot.targets:
        for port in default_ports:
            entries.append(f"{t.host}:{port}")
    return " ".join(entries)
