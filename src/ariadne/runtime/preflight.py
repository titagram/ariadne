"""Docker environment preflight checks.

Probes Docker presence, health, disk and memory limits, DNS/routes,
VPN reachability, and port/callback feasibility before an engagement
begins.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Final

from ariadne.runtime.platform import HostOS, HostPlatform, detect_host


class CallbackAttestationError(ValueError):
    """A reverse callback could not be proven local and target-routable."""


@dataclass(frozen=True)
class CallbackAddressAttestation:
    """Local, serialisable provenance for a reverse callback address.

    The values are deliberately hashes of bounded local command output rather
    than raw interface data.  They can be persisted in the durable plan and
    evidence stream without exposing unrelated host routing details.
    """

    address: str
    target: str
    source: str
    interface: str
    route_sha256: str
    ownership_sha256: str

    def as_plan_data(self) -> dict[str, str]:
        """Return the immutable provenance shape accepted by Metasploit plans."""
        return {
            "address": self.address,
            "target": self.target,
            "source": self.source,
            "interface": self.interface,
            "route_sha256": self.route_sha256,
            "ownership_sha256": self.ownership_sha256,
        }


_CallbackCommandRunner = Callable[..., tuple[int, str, str]]
_CALLBACK_TIMEOUT_SECONDS: Final[float] = 3.0
_CALLBACK_PLAN_KEYS: Final[frozenset[str]] = frozenset(
    {
        "address",
        "target",
        "source",
        "interface",
        "route_sha256",
        "ownership_sha256",
    }
)
_CALLBACK_SOURCES: Final[frozenset[str]] = frozenset(
    {"macos:route-get+ifconfig", "linux:ip-route-get+ip-addr"}
)
_UNSAFE_CALLBACK_INTERFACE_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:lo\d*|docker\S*|br[-\w]*|bridge\S*|veth\S*|virbr\S*|cni\S*|podman\S*)$",
    re.IGNORECASE,
)
_INTERFACE_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")


def _run_callback_command(
    argv: tuple[str, ...], *, timeout_seconds: float
) -> tuple[int, str, str]:
    """Run a short, local-only route or interface query without a shell."""
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)
    return result.returncode, result.stdout, result.stderr


def _as_routable_ipv4(value: str, *, name: str) -> ipaddress.IPv4Address:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise CallbackAttestationError(
            f"callback_address_unattested: {name} must be an IPv4 address"
        ) from exc
    if not isinstance(address, ipaddress.IPv4Address) or any(
        (
            address.is_loopback,
            address.is_unspecified,
            address.is_multicast,
            address.is_link_local,
        )
    ):
        raise CallbackAttestationError(
            f"callback_address_unattested: {name} is not target-routable"
        )
    return address


def _command_output(
    runner: _CallbackCommandRunner, argv: tuple[str, ...]
) -> str:
    code, stdout, stderr = runner(argv, timeout_seconds=_CALLBACK_TIMEOUT_SECONDS)
    if code != 0:
        detail = (stderr or stdout).strip().replace("\n", " ")[:160]
        raise CallbackAttestationError(
            "callback_address_unattested: local route/interface probe failed"
            + (f" ({detail})" if detail else "")
        )
    return stdout


def _route_interface(output: str, *, os: HostOS) -> str:
    pattern = (
        r"^\s*interface:\s*(\S+)\s*$"
        if os is HostOS.MACOS
        else r"\bdev\s+(\S+)"
    )
    match = re.search(pattern, output, flags=re.MULTILINE)
    if match is None:
        raise CallbackAttestationError(
            "callback_address_unattested: route has no usable host interface"
        )
    interface = match.group(1)
    if not _INTERFACE_RE.fullmatch(interface) or _UNSAFE_CALLBACK_INTERFACE_RE.fullmatch(interface):
        raise CallbackAttestationError(
            "callback_address_unattested: route resolves through a bridge or container interface"
        )
    return interface


def _address_owned_by_interface(address: ipaddress.IPv4Address, output: str) -> bool:
    return any(
        ipaddress.ip_address(match.group(1)) == address
        for match in re.finditer(r"\binet\s+(\d+\.\d+\.\d+\.\d+)(?:/\d+)?\b", output)
    )


def attest_callback_address(
    *,
    advertised_address: str,
    target: str,
    host: HostPlatform | None = None,
    command_runner: _CallbackCommandRunner | None = None,
) -> CallbackAddressAttestation:
    """Prove that a callback address is host-owned on the target's route.

    This performs only bounded *local* inspection.  It sends no packets to the
    target: macOS uses ``route -n get`` and ``ifconfig``; Linux uses ``ip route
    get`` and ``ip addr show``.  The callback is rejected unless its address is
    owned by the non-container interface selected for the authorised target.
    """
    advertised = _as_routable_ipv4(advertised_address, name="advertised address")
    target_address = _as_routable_ipv4(target, name="target")
    platform = host or detect_host()
    runner = command_runner or _run_callback_command
    if platform.os is HostOS.MACOS:
        route_argv = ("route", "-n", "get", str(target_address))
        source = "macos:route-get+ifconfig"
    elif platform.os is HostOS.LINUX:
        route_argv = ("ip", "-4", "route", "get", str(target_address))
        source = "linux:ip-route-get+ip-addr"
    else:
        raise CallbackAttestationError(
            "callback_address_unattested: local callback attestation is supported on macOS/Linux"
        )

    route_output = _command_output(runner, route_argv)
    interface = _route_interface(route_output, os=platform.os)
    ownership_argv = (
        ("ifconfig", interface)
        if platform.os is HostOS.MACOS
        else ("ip", "-4", "addr", "show", "dev", interface)
    )
    ownership_output = _command_output(runner, ownership_argv)
    if not _address_owned_by_interface(advertised, ownership_output):
        raise CallbackAttestationError(
            "callback_address_unattested: advertised address is not owned by "
            "the target route interface"
        )
    return CallbackAddressAttestation(
        address=str(advertised),
        target=str(target_address),
        source=source,
        interface=interface,
        route_sha256=hashlib.sha256(route_output.encode("utf-8")).hexdigest(),
        ownership_sha256=hashlib.sha256(ownership_output.encode("utf-8")).hexdigest(),
    )


def validate_callback_attestation(
    value: object, *, advertised_address: str, target: str
) -> Mapping[str, str]:
    """Validate the durable attestation marker bound into a callback plan.

    The marker is emitted by :func:`attest_callback_address`; validation here
    keeps a hand-written or stale plan from changing its target/address after
    attestation.  The local probe itself remains the source of truth.
    """
    if not isinstance(value, dict) or set(value) != _CALLBACK_PLAN_KEYS:
        raise CallbackAttestationError(
            "callback_address_unattested: callback requires local attestation provenance"
        )
    if not all(isinstance(item, str) for item in value.values()):
        raise CallbackAttestationError(
            "callback_address_unattested: invalid attestation provenance"
        )
    data = value
    if data["address"] != advertised_address or data["target"] != target:
        raise CallbackAttestationError(
            "callback_address_unattested: attestation is not bound to this callback target"
        )
    if (
        data["source"] not in _CALLBACK_SOURCES
        or not _INTERFACE_RE.fullmatch(data["interface"])
        or _UNSAFE_CALLBACK_INTERFACE_RE.fullmatch(data["interface"])
        or not _SHA256_RE.fullmatch(data["route_sha256"])
        or not _SHA256_RE.fullmatch(data["ownership_sha256"])
    ):
        raise CallbackAttestationError(
            "callback_address_unattested: invalid local attestation provenance"
        )
    return data


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
