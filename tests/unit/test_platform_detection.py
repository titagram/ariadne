"""Tests for host platform detection.

Covers macOS, Linux, and Windows on x86_64 and ARM64,
unknown architectures, and unknown OS fallback.
"""

from __future__ import annotations

from ariadne.runtime.platform import Architecture, HostOS, detect_host


def test_apple_silicon_is_normalized() -> None:
    """Apple Silicon macOS returns MACOS + ARM64 + linux/arm64."""
    host = detect_host(system="Darwin", machine="arm64")
    assert host.os is HostOS.MACOS
    assert host.arch is Architecture.ARM64
    assert host.docker_platform == "linux/arm64"


def test_intel_macos() -> None:
    """Intel macOS returns MACOS + X86_64 + linux/amd64."""
    host = detect_host(system="Darwin", machine="x86_64")
    assert host.os is HostOS.MACOS
    assert host.arch is Architecture.X86_64
    assert host.docker_platform == "linux/amd64"


def test_linux_x86_64() -> None:
    """Linux on x86_64 returns LINUX + X86_64."""
    host = detect_host(system="Linux", machine="x86_64")
    assert host.os is HostOS.LINUX
    assert host.arch is Architecture.X86_64


def test_linux_aarch64() -> None:
    """Linux on aarch64 returns LINUX + ARM64."""
    host = detect_host(system="Linux", machine="aarch64")
    assert host.os is HostOS.LINUX
    assert host.arch is Architecture.ARM64


def test_windows_amd64() -> None:
    """Windows on AMD64 returns WINDOWS + X86_64."""
    host = detect_host(system="Windows", machine="AMD64")
    assert host.os is HostOS.WINDOWS
    assert host.arch is Architecture.X86_64


def test_windows_arm64() -> None:
    """Windows on ARM64 returns WINDOWS + ARM64."""
    host = detect_host(system="Windows", machine="ARM64")
    assert host.os is HostOS.WINDOWS
    assert host.arch is Architecture.ARM64


def test_unknown_architecture() -> None:
    """An unrecognised machine string maps to Architecture.UNKNOWN."""
    host = detect_host(system="Linux", machine="mips64")
    assert host.arch is Architecture.UNKNOWN


def test_unknown_operating_system() -> None:
    """An unrecognised system string maps to HostOS.UNKNOWN."""
    host = detect_host(system="FreeBSD", machine="amd64")
    assert host.os is HostOS.UNKNOWN


def test_detect_host_defaults_to_live_platform() -> None:
    """Calling detect_host() with no arguments uses the real platform."""
    host = detect_host()
    assert isinstance(host.os, HostOS)
    assert isinstance(host.arch, Architecture)
    assert host.docker_platform.startswith("linux/")


def test_host_platform_is_frozen() -> None:
    """HostPlatform should be immutable."""
    host = detect_host(system="Linux", machine="x86_64")
    try:
        host.os = HostOS.MACOS  # type: ignore[misc]
        msg = "Expected AttributeError or frozen guard"
        raise AssertionError(msg)
    except (AttributeError, TypeError):
        pass
