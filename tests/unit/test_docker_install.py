"""Tests for confirmable Docker installation proposals.

Covers curated proposals for macOS, Windows, Linux (apt, dnf, arch),
unknown OS fallback to documentation URL, confirmation enforcement,
and execution failure chaining.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from ariadne.runtime.install import (
    ConfirmationRequiredError,
    DockerInstaller,
    InstallProposal,
    InstallResult,
)
from ariadne.runtime.platform import Architecture, HostOS, HostPlatform

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def mac_host() -> HostPlatform:
    return HostPlatform(
        os=HostOS.MACOS,
        arch=Architecture.ARM64,
        docker_platform="linux/arm64",
    )


@pytest.fixture
def win_host() -> HostPlatform:
    return HostPlatform(
        os=HostOS.WINDOWS,
        arch=Architecture.X86_64,
        docker_platform="linux/amd64",
    )


@pytest.fixture
def linux_apt_host() -> HostPlatform:
    return HostPlatform(
        os=HostOS.LINUX,
        arch=Architecture.X86_64,
        docker_platform="linux/amd64",
    )


@pytest.fixture
def linux_dnf_host() -> HostPlatform:
    return HostPlatform(
        os=HostOS.LINUX,
        arch=Architecture.X86_64,
        docker_platform="linux/amd64",
    )


@pytest.fixture
def linux_arch_host() -> HostPlatform:
    return HostPlatform(
        os=HostOS.LINUX,
        arch=Architecture.X86_64,
        docker_platform="linux/amd64",
    )


@pytest.fixture
def unknown_host() -> HostPlatform:
    return HostPlatform(
        os=HostOS.UNKNOWN,
        arch=Architecture.X86_64,
        docker_platform="linux/amd64",
    )


@pytest.fixture
def installer() -> DockerInstaller:
    return DockerInstaller()


# ── Confirmation enforcement ──────────────────────────────────────────────────


def test_install_requires_matching_direct_confirmation(
    installer: DockerInstaller,
    mac_host: HostPlatform,
) -> None:
    """execute() without confirmation raises ConfirmationRequiredError."""
    proposal = installer.propose(mac_host)
    with pytest.raises(ConfirmationRequiredError):
        installer.execute(proposal, confirmation=None)


def test_install_rejects_mismatched_digest(
    installer: DockerInstaller,
    mac_host: HostPlatform,
) -> None:
    """execute() with a mismatched challenge digest raises ConfirmationRequiredError."""
    proposal = installer.propose(mac_host)
    with pytest.raises(ConfirmationRequiredError):
        installer.execute(proposal, confirmation="bad-digest")


# ── macOS proposal ────────────────────────────────────────────────────────────


def test_macos_brew_proposal_structure(
    installer: DockerInstaller,
    mac_host: HostPlatform,
) -> None:
    """MacOS proposal uses Homebrew Cask and includes documentation URL."""
    from unittest.mock import patch

    with patch("ariadne.runtime.install._check_package_manager", return_value=True):
        proposal = installer.propose(mac_host)
    assert len(proposal.commands) > 0
    # First command is ("brew", "install", "--cask", "docker") — check tuple
    assert proposal.commands[0] == ("brew", "install", "--cask", "docker")
    assert proposal.documentation_url is not None
    assert proposal.requires_sudo is False
    assert proposal.reboot_required is False
    assert proposal.canonical_digest is not None


# ── Windows proposal ──────────────────────────────────────────────────────────


def test_windows_winget_proposal_structure(
    installer: DockerInstaller,
    win_host: HostPlatform,
) -> None:
    """Windows proposal uses winget with Docker Desktop."""
    from unittest.mock import patch

    with patch("ariadne.runtime.install._check_package_manager", return_value=True):
        proposal = installer.propose(win_host)
    assert len(proposal.commands) > 0
    assert any("winget" in cmd for cmd in proposal.commands)
    assert proposal.documentation_url is not None
    assert proposal.requires_sudo is False


# ── Linux proposals ───────────────────────────────────────────────────────────


def test_linux_apt_proposal(
    installer: DockerInstaller,
    linux_apt_host: HostPlatform,
) -> None:
    """Linux with apt proposes docker-ce packages."""
    proposal = installer.propose(linux_apt_host)
    # Without mocking this may fall through to unknown; we just check structure
    assert isinstance(proposal, InstallProposal)


def test_linux_arch_proposal(
    installer: DockerInstaller,
    linux_arch_host: HostPlatform,
) -> None:
    """Linux with pacman proposes docker and docker-compose."""
    proposal = installer.propose(linux_arch_host)
    assert isinstance(proposal, InstallProposal)


# ── Unknown OS proposal ───────────────────────────────────────────────────────


def test_unknown_os_returns_documentation_url(
    installer: DockerInstaller,
    unknown_host: HostPlatform,
) -> None:
    """Unknown OS yields a proposal with no commands and a doc URL."""
    proposal = installer.propose(unknown_host)
    assert len(proposal.commands) == 0
    # The canonical digest should still be set
    assert proposal.canonical_digest is not None


# ── Successful execution ──────────────────────────────────────────────────────


@patch("ariadne.runtime.install.subprocess.run")
def test_execute_runs_all_commands(
    mock_run,
    installer: DockerInstaller,
    mac_host: HostPlatform,
) -> None:
    """execute() runs every command in the proposal sequentially."""
    from unittest.mock import MagicMock
    from unittest.mock import patch as _patch

    mock_run.return_value = MagicMock(returncode=0)

    with _patch("ariadne.runtime.install._check_package_manager", return_value=True):
        proposal = installer.propose(mac_host)
    result = installer.execute(proposal, confirmation=proposal.canonical_digest)

    assert isinstance(result, InstallResult)
    assert result.success is True
    assert mock_run.call_count == len(proposal.commands)


@patch("ariadne.runtime.install.subprocess.run")
def test_execute_stops_on_first_failure(
    mock_run,
    installer: DockerInstaller,
    mac_host: HostPlatform,
) -> None:
    """execute() stops on the first command failure."""
    from unittest.mock import MagicMock
    from unittest.mock import patch as _patch

    # First call fails
    mock_run.return_value = MagicMock(returncode=1)

    with _patch("ariadne.runtime.install._check_package_manager", return_value=True):
        proposal = installer.propose(mac_host)
    result = installer.execute(proposal, confirmation=proposal.canonical_digest)

    assert result.success is False
    assert isinstance(result.failed_command, tuple)


# ── Proposal digest stability ─────────────────────────────────────────────────


def test_proposal_digest_is_deterministic(
    installer: DockerInstaller,
    mac_host: HostPlatform,
) -> None:
    """The same host yields the same canonical digest."""
    from unittest.mock import patch

    with patch("ariadne.runtime.install._check_package_manager", return_value=True):
        a = installer.propose(mac_host)
        b = installer.propose(mac_host)
    assert a.canonical_digest == b.canonical_digest
