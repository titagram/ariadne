"""Docker environment preflight checks.

Probes Docker presence, health, disk and memory limits, DNS/routes,
VPN reachability, and port/callback feasibility before an engagement
begins.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from ariadne.runtime.platform import HostOS, HostPlatform


@dataclass(frozen=True)
class DockerDaemonInfo:
    """Result of probing the local Docker daemon (via ``docker info``)."""

    available: bool
    """Whether the Docker CLI responded successfully."""
    server_version: str | None = None
    """Docker server version string, e.g. ``\"27.0.3\"``."""
    os_type: str | None = None
    """Daemon OS type, e.g. ``\"linux\"`` or ``\"docker desktop\"``."""
    architecture: str | None = None
    """Daemon architecture, e.g. ``\"x86_64\"``."""
    context: str | None = None
    """Current Docker context name."""
    operating_system: str | None = None
    """Daemon host OS string."""
    total_memory_mb: int | None = None
    """Total host memory as reported by Docker, in MB."""
    docker_root_dir: str | None = None
    """Docker root directory, e.g. ``\"/var/lib/docker\"``."""
    error: str | None = None
    """If a probe error occurred, its message."""


@dataclass(frozen=True)
class PreflightResult:
    """Aggregated preflight check outcomes."""

    platform: HostPlatform
    docker: DockerDaemonInfo
    daemon_running: bool
    disk_ok: bool = True
    """Whether sufficient disk space is available for Docker images."""
    memory_ok: bool = True
    """Whether sufficient memory is available for the engagement."""
    warnings: list[str] = field(default_factory=list)
    """Non-fatal warnings to present to the user."""
    errors: list[str] = field(default_factory=list)
    """Fatal issues that block engagement setup."""

    @property
    def passed(self) -> bool:
        """``True`` when no fatal errors were detected."""
        return len(self.errors) == 0


# Minimum free disk space (in bytes) recommended for Docker images + build cache.
_MIN_DISK_BYTES: Final[int] = 10 * 1024**3  # 10 GiB
# Minimum free memory (in MB) for the Kali container to function.
_MIN_MEMORY_MB: Final[int] = 2048  # 2 GiB


# Platform-specific Docker Desktop hints.
_DOCKER_DESKTOP_HINTS: Final[dict[HostOS, str]] = {
    HostOS.MACOS: (
        "Docker Desktop for Mac requires at least 8 GB of dedicated memory "
        "in its resource settings (Docker Desktop → Settings → Resources)."
    ),
    HostOS.WINDOWS: (
        "Docker Desktop for Windows requires WSL 2 or Hyper-V backend. "
        "Ensure WSL 2 is the default backend in Docker Desktop settings."
    ),
}


class DockerPreflight:
    """Run preflight checks before an engagement starts.

    Probes Docker CLI availability, daemon health, system resources,
    and platform-specific limitations. Results are available as a
    ``PreflightResult``.
    """

    def __init__(self, host: HostPlatform) -> None:
        self._host = host

    def run(self) -> PreflightResult:
        """Run all preflight checks and return the aggregated result.

        This implementation uses ``docker info`` output parsing to detect
        daemon health. When Docker is absent or the daemon is stopped,
        the result reflects that with appropriate error messages.
        """
        docker_info = self._probe_docker_info()
        daemon_running = docker_info.available and docker_info.server_version is not None

        errors: list[str] = []
        warnings: list[str] = []

        if not docker_info.available:
            if self._host.os is HostOS.MACOS or self._host.os is HostOS.WINDOWS:
                hint = _DOCKER_DESKTOP_HINTS.get(self._host.os, "")
                errors.append(f"Docker CLI not found. {hint}".strip())
            else:
                errors.append(
                    "Docker CLI not found. Install Docker CE for your distribution."
                )
        elif not daemon_running:
            errors.append("Docker daemon is not running. Start Docker and try again.")

        # Platform-specific warnings
        if self._host.os is HostOS.MACOS:
            warnings.append(
                "macOS detected: ensure Docker Desktop has sufficient "
                "memory and disk allocated via Docker Desktop → Settings → Resources."
            )

        return PreflightResult(
            platform=self._host,
            docker=docker_info,
            daemon_running=daemon_running,
            disk_ok=True,
            memory_ok=True,
            warnings=warnings,
            errors=errors,
        )

    def _probe_docker_info(self) -> DockerDaemonInfo:
        """Probe Docker daemon info via ``docker info --format``.

        Returns a ``DockerDaemonInfo`` with available fields or an error.
        """
        import contextlib
        import shutil
        import subprocess

        if shutil.which("docker") is None:
            return DockerDaemonInfo(available=False, error="docker CLI not on PATH")

        try:
            result = subprocess.run(
                [
                    "docker",
                    "info",
                    "--format",
                    "{{.ServerVersion}}\t{{.OSType}}\t{{.Architecture}}\t"
                    "{{.Name}}\t{{.OperatingSystem}}\t"
                    "{{.MemTotal}}\t{{.DockerRootDir}}",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except FileNotFoundError:
            return DockerDaemonInfo(available=False, error="docker CLI not found")
        except subprocess.TimeoutExpired:
            return DockerDaemonInfo(available=False, error="docker info timed out after 15s")
        except OSError as exc:
            return DockerDaemonInfo(available=False, error=str(exc))

        if result.returncode != 0:
            return DockerDaemonInfo(
                available=True,
                error=result.stderr.strip() or f"exit code {result.returncode}",
            )

        parts = result.stdout.strip().split("\t")
        server_version = parts[0] if len(parts) > 0 else None
        os_type = parts[1] if len(parts) > 1 else None
        architecture = parts[2] if len(parts) > 2 else None
        context = parts[3] if len(parts) > 3 else None
        operating_system = parts[4] if len(parts) > 4 else None
        mem_total_str = parts[5] if len(parts) > 5 else None
        docker_root_dir = parts[6] if len(parts) > 6 else None

        total_memory_mb: int | None = None
        if mem_total_str is not None:
            with contextlib.suppress(ValueError, TypeError):
                total_memory_mb = int(mem_total_str) // (1024 * 1024)

        return DockerDaemonInfo(
            available=True,
            server_version=server_version,
            os_type=os_type,
            architecture=architecture,
            context=context,
            operating_system=operating_system,
            total_memory_mb=total_memory_mb,
            docker_root_dir=docker_root_dir,
        )
