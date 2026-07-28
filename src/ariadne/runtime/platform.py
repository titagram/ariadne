"""Host platform detection for Ariadne's Docker runtime.

Provides OS/architecture detection and Docker platform string
resolution for confirming installation proposals.
"""

from __future__ import annotations

import platform as _platform
from enum import StrEnum
from typing import Final


class HostOS(StrEnum):
    """Detected host operating system."""

    MACOS = "macos"
    WINDOWS = "windows"
    LINUX = "linux"
    UNKNOWN = "unknown"


class Architecture(StrEnum):
    """Detected host CPU architecture."""

    X86_64 = "x86_64"
    ARM64 = "arm64"
    UNKNOWN = "unknown"


# Mapping from platform.system() -> HostOS
_OS_MAP: Final[dict[str, HostOS]] = {
    "Darwin": HostOS.MACOS,
    "Windows": HostOS.WINDOWS,
    "Linux": HostOS.LINUX,
}

# Mapping from platform.machine() -> Architecture
_ARCH_MAP: Final[dict[str, Architecture]] = {
    "x86_64": Architecture.X86_64,
    "amd64": Architecture.X86_64,
    "AMD64": Architecture.X86_64,
    "arm64": Architecture.ARM64,
    "ARM64": Architecture.ARM64,
    "aarch64": Architecture.ARM64,
}

# Docker platform string for each architecture
_DOCKER_PLATFORM: Final[dict[Architecture, str]] = {
    Architecture.X86_64: "linux/amd64",
    Architecture.ARM64: "linux/arm64",
    Architecture.UNKNOWN: "linux/amd64",  # safest default
}


class HostPlatform:
    """Detected and normalized host platform information.

    Immutable container for OS, architecture, and the corresponding
    Docker platform string.
    """

    __slots__ = ("_os", "_arch", "_docker_platform")

    def __init__(self, os: HostOS, arch: Architecture, docker_platform: str) -> None:
        object.__setattr__(self, "_os", os)
        object.__setattr__(self, "_arch", arch)
        object.__setattr__(self, "_docker_platform", docker_platform)

    @property
    def os(self) -> HostOS:
        return self._os

    @property
    def arch(self) -> Architecture:
        return self._arch

    @property
    def docker_platform(self) -> str:
        return self._docker_platform

    def __setattr__(self, key: str, value: object) -> None:
        raise AttributeError(f"HostPlatform is immutable: cannot set {key!r}")

    def __delattr__(self, key: str) -> None:
        raise AttributeError(f"HostPlatform is immutable: cannot delete {key!r}")

    def __repr__(self) -> str:
        return f"HostPlatform(os={self._os!r}, arch={self._arch!r})"


def detect_host(
    system: str | None = None,
    machine: str | None = None,
) -> HostPlatform:
    """Detect and normalise the current host OS and architecture.

    When *system* and *machine* are ``None`` (the default), probes the
    live platform via ``platform.system()`` and ``platform.machine()``.

    Args:
        system: Override for platform.system() (e.g. ``\"Darwin\"``).
        machine: Override for platform.machine() (e.g. ``\"arm64\"``).

    Returns:
        A normalised ``HostPlatform`` with resolved OS, architecture,
        and Docker platform string.
    """
    raw_os = system if system is not None else _platform.system()
    raw_arch = machine if machine is not None else _platform.machine()

    normalized_os = _OS_MAP.get(raw_os, HostOS.UNKNOWN)
    normalized_arch = _ARCH_MAP.get(raw_arch, Architecture.UNKNOWN)
    docker_platform = _DOCKER_PLATFORM.get(normalized_arch, "linux/amd64")

    return HostPlatform(
        os=normalized_os,
        arch=normalized_arch,
        docker_platform=docker_platform,
    )
