"""Curated, confirmable Docker installation proposals.

Generates approved installation argument vectors for macOS, Windows,
and supported Linux distributions. Never pipes remote scripts into a
shell, never auto-adds a repository, and requires a matching digest
confirmation before any execution.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Final

from ariadne.runtime.platform import HostOS, HostPlatform


class ConfirmationRequiredError(Exception):
    """Raised when an installation confirmation is missing or does not match.

    This is an installation-domain error, distinct from the engagement
    ``ConfirmationError``. It signals that the ``confirm`` digest did not
    match the proposal's canonical digest, or that no confirmation was
    supplied at all.
    """


@dataclass(frozen=True)
class InstallProposal:
    """A curated Docker installation proposal for presentation and execution.

    The proposal contains exact command argument vectors (not shell
    strings), a documentation URL, privilege requirements, side-effect
    notes, and a deterministic canonical digest for confirmation.
    """

    commands: tuple[tuple[str, ...], ...] = ()
    """Ordered argument vectors to execute. An empty tuple means no
    automated installation is available."""

    documentation_url: str | None = None
    """Link to the official Docker installation documentation for the
    detected platform."""

    requires_sudo: bool = False
    """Whether the commands require administrative privileges."""

    reboot_required: bool = False
    """Whether a reboot or relogin is needed after installation."""

    notes: list[str] = field(default_factory=list)
    """Human-readable notes about the installation (side effects, known
    issues, Docker Desktop licensing reminders, etc.)."""

    canonical_digest: str | None = None
    """SHA-256 hex digest of the proposal's structured content, used as
    a confirmation challenge."""


@dataclass(frozen=True)
class InstallResult:
    """Outcome of a Docker installation execution."""

    success: bool
    """Whether all commands completed successfully."""
    failed_command: tuple[str, ...] | None = None
    """The command that failed, if any."""
    error: str | None = None
    """Error message from the failing command."""


# ── Official Docker installation documentation URLs ───────────────────────────

_DOC_URLS: Final[dict[HostOS, str]] = {
    HostOS.MACOS: "https://docs.docker.com/desktop/install/mac-install/",
    HostOS.WINDOWS: "https://docs.docker.com/desktop/install/windows-install/",
    HostOS.LINUX: "https://docs.docker.com/engine/install/",
}

# ── Curated installation argument vectors ─────────────────────────────────────
# Never pipe remote scripts into a shell. Never auto-add a repository.
# These are the approved official installation paths.

MACOS_BREW: Final[tuple[tuple[str, ...], ...]] = (
    ("brew", "install", "--cask", "docker"),
)

WINDOWS_WINGET: Final[tuple[tuple[str, ...], ...]] = (
    (
        "winget", "install", "--id", "Docker.DockerDesktop", "--exact",
        "--accept-source-agreements", "--accept-package-agreements",
    ),
)

# Linux package sets for distributions with Docker CE repositories configured.
_APT_PACKAGES: Final[tuple[tuple[str, ...], ...]] = (
    ("apt-get", "install", "--yes",
     "docker-ce", "docker-ce-cli", "containerd.io",
     "docker-buildx-plugin", "docker-compose-plugin"),
)

_DNF_PACKAGES: Final[tuple[tuple[str, ...], ...]] = (
    ("dnf", "install", "--yes",
     "docker-ce", "docker-ce-cli", "containerd.io",
     "docker-buildx-plugin", "docker-compose-plugin"),
)

_ARCH_PACKAGES: Final[tuple[tuple[str, ...], ...]] = (
    ("pacman", "--noconfirm", "-S", "docker", "docker-compose"),
)


def _compute_digest(commands: tuple[tuple[str, ...], ...], doc_url: str | None) -> str:
    """Deterministic SHA-256 digest of a proposal's structured content."""
    payload = {
        "commands": [list(cmd) for cmd in commands],
        "documentation_url": doc_url,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _check_package_manager(name: str) -> bool:
    """Check whether a package manager is on PATH (read-only probe)."""
    return shutil.which(name) is not None


def _check_apt_candidate() -> bool:
    """Check whether docker-ce has a candidate (without changing state).

    Runs ``apt-cache policy docker-ce`` and checks for a candidate line.
    Returns ``False`` if apt-cache is unavailable or no candidate exists.
    """
    if not _check_package_manager("apt-cache"):
        return False
    try:
        result = subprocess.run(
            ["apt-cache", "policy", "docker-ce"],
            capture_output=True, text=True, timeout=10,
        )
        # A candidate exists when the output contains a "Candidate:" line
        # with a non-empty value.
        for line in result.stdout.splitlines():
            if line.strip().startswith("Candidate:") and not line.strip().endswith("(none)"):
                return True
        return False
    except (subprocess.TimeoutExpired, OSError):
        return False


def _check_dnf_candidate() -> bool:
    """Check whether docker-ce is available via DNF (without changing state)."""
    if not _check_package_manager("dnf"):
        return False
    try:
        result = subprocess.run(
            ["dnf", "list", "--available", "docker-ce"],
            capture_output=True, text=True, timeout=15,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


class DockerInstaller:
    """Proposes and executes curated Docker installation commands.

    Proposals are generated per-platform using only approved argument
    vectors. Execution requires a matching confirmation digest and runs
    each command independently, stopping on the first failure.
    """

    def propose(self, host: HostPlatform) -> InstallProposal:
        """Build a curated ``InstallProposal`` for *host*.

        Args:
            host: The detected host platform.

        Returns:
            An ``InstallProposal`` with approved commands, the official
            documentation URL, and a deterministic canonical digest.
        """
        commands: tuple[tuple[str, ...], ...] = ()
        doc_url: str | None = _DOC_URLS.get(host.os)
        requires_sudo = False
        reboot_required = False
        notes: list[str] = []

        if host.os is HostOS.MACOS:
            if _check_package_manager("brew"):
                commands = MACOS_BREW
                notes = [
                    "Docker Desktop will be installed via Homebrew Cask.",
                    "After installation, launch Docker Desktop from /Applications.",
                ]
            else:
                doc_url = _DOC_URLS[HostOS.MACOS]
                notes = [
                    "Homebrew not found. Install Docker Desktop manually from "
                    "the official URL above, or install Homebrew first "
                    "(https://brew.sh).",
                ]

        elif host.os is HostOS.WINDOWS:
            if _check_package_manager("winget"):
                commands = WINDOWS_WINGET
                notes = [
                    "Docker Desktop will be installed via winget.",
                    "A restart may be required after installation.",
                ]
                reboot_required = True
            else:
                doc_url = _DOC_URLS[HostOS.WINDOWS]
                notes = [
                    "winget not found. Install Docker Desktop manually from "
                    "the official URL above.",
                ]

        elif host.os is HostOS.LINUX:
            # Prefer the Docker CE packages when the Docker repository is
            # already configured on the system. Otherwise fall back to
            # distribution packages for known distros.
            if _check_package_manager("apt-get") and _check_apt_candidate():
                commands = _APT_PACKAGES
                requires_sudo = True
                notes = [
                    "Docker CE packages will be installed via apt-get.",
                    "Add your user to the 'docker' group after installation "
                    "to run Docker without sudo.",
                ]
                reboot_required = True
            elif _check_package_manager("dnf") and _check_dnf_candidate():
                commands = _DNF_PACKAGES
                requires_sudo = True
                notes = [
                    "Docker CE packages will be installed via DNF.",
                    "Add your user to the 'docker' group after installation.",
                ]
                reboot_required = True
            elif _check_package_manager("pacman"):
                commands = _ARCH_PACKAGES
                requires_sudo = True
                notes = [
                    "Docker and Docker Compose will be installed via pacman.",
                    "Enable and start docker.service after installation.",
                ]
                reboot_required = True
            else:
                notes = [
                    "No curated Docker packages detected for this Linux "
                    "distribution. Install Docker manually by following the "
                    "official documentation.",
                ]

        # For unknown OS, we just provide the doc URL with empty commands.

        digest = _compute_digest(commands, doc_url)

        return InstallProposal(
            commands=commands,
            documentation_url=doc_url,
            requires_sudo=requires_sudo,
            reboot_required=reboot_required,
            notes=notes,
            canonical_digest=digest,
        )

    def execute(
        self,
        proposal: InstallProposal,
        confirmation: str | None,
    ) -> InstallResult:
        """Execute a confirmed installation proposal.

        Re-computes the proposal's canonical digest and compares it
        against *confirmation*. Runs each command independently and
        stops on the first failure.

        Args:
            proposal: The ``InstallProposal`` to execute.
            confirmation: The expected digest, provided by the user
                via direct confirmation. ``None`` or a mismatched value
                raises ``ConfirmationRequiredError``.

        Returns:
            An ``InstallResult`` describing the outcome.

        Raises:
            Raises ``ConfirmationRequiredError`` if *confirmation* is ``None`` or does
                not match the proposal's canonical digest.
        """
        if confirmation is None or proposal.canonical_digest is None:
            raise ConfirmationRequiredError(
                "Installation confirmation is required. "
                "Use /ariadne confirm <digest> to approve the proposal."
            )

        # Recompute digest to detect any modification between propose and execute
        expected = _compute_digest(proposal.commands, proposal.documentation_url)
        if confirmation != expected:
            raise ConfirmationRequiredError(
                f"Confirmation digest mismatch: expected {expected}, "
                f"got {confirmation}"
            )

        # Execute each command independently; stop on first failure.
        for argv in proposal.commands:
            try:
                result = subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=600,
                )
            except subprocess.TimeoutExpired:
                return InstallResult(
                    success=False,
                    failed_command=argv,
                    error="Command timed out after 600s",
                )
            except OSError as exc:
                return InstallResult(
                    success=False,
                    failed_command=argv,
                    error=str(exc),
                )

            if result.returncode != 0:
                stderr = result.stderr.strip() or f"exit code {result.returncode}"
                return InstallResult(
                    success=False,
                    failed_command=argv,
                    error=stderr,
                )

        return InstallResult(success=True)
