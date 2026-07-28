"""Integration test fixtures for isolated Docker Compose services.

Provides fixtures that reference the integration test Compose stack,
including allowed/blocked target descriptors and runtime connectivity
helpers for in-container checks.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

_COMPOSE_FILE = Path(__file__).resolve().parent.parent / "compose.yaml"


# ── Helpers ───────────────────────────────────────────────────────────────────


def _docker_available() -> bool:
    """Check whether the Docker daemon is responsive."""
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0 and bool(result.stdout.strip())
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _compose_running() -> bool:
    """Check whether the integration Compose stack is up."""
    try:
        args = [
            "docker", "compose", "-f", str(_COMPOSE_FILE),
            "ps", "--status", "running", "-q",
        ]
        result = subprocess.run(args, capture_output=True, text=True, timeout=15)
        return bool(result.stdout.strip())
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def integration_targets() -> object:
    """Provide allowed/blocked target descriptors for integration testing.

    The integration Compose network publishes:
    - ``allowed.ariadne.test`` (10.10.10.10) as the engagement target.
    - ``blocked.ariadne.test`` (10.10.10.11) as a discoverable neighbor
      that the netguard firewall must deny.
    """
    from types import SimpleNamespace

    return SimpleNamespace(
        allowed_host="10.10.10.10",
        allowed_fqdn="allowed.ariadne.test",
        blocked_host="10.10.10.11",
        blocked_fqdn="blocked.ariadne.test",
    )


@pytest.fixture(scope="module")
def integration_runtime() -> object:
    """Provide a runtime helper for in-container connectivity checks.

    Uses ``docker exec`` against the Kali container of the integration
    Compose stack to probe TCP connectivity from inside the netguard
    firewall.
    """

    class _IntegrationRuntime:
        @staticmethod
        def tcp_reachable(host: str, port: int = 80) -> bool:
            """Check whether TCP *port* on *host* is reachable from Kali.

            Uses a Python one-liner (available via python:3.11-alpine image)
            for a pure-TCP connection probe — succeeds when a TCP handshake
            completes, fails on timeout, connection refused, or packet drop
            (as when netguard's default-drop policy denies egress).
            """
            result = subprocess.run(
                [
                    "docker", "compose", "-f", str(_COMPOSE_FILE),
                    "exec", "-T", "kali",
                    "python3", "-c",
                    "import socket; s=socket.socket(); "
                    f"s.settimeout(3); s.connect(('{host}', {port})); "
                    "s.close(); print('ok')",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return "ok" in result.stdout.strip()

        @staticmethod
        def http_get(path: str = "/") -> str:
            """Perform an HTTP GET from inside Kali, returning response body.

            Uses Python's urllib (available via python:3.11-alpine image).
            Target is ``allowed.ariadne.test`` (resolves to 10.10.10.10
            inside the Docker bridge network).
            """
            result = subprocess.run(
                [
                    "docker", "compose", "-f", str(_COMPOSE_FILE),
                    "exec", "-T", "kali",
                    "python3", "-c",
                    "import urllib.request; "
                    f"print(urllib.request.urlopen('http://allowed.ariadne.test"
                    f"{path}', timeout=5).read().decode())",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.stdout.strip()

    return _IntegrationRuntime()


# Disable the "fixture not found" collection for these module-scoped fixtures
# when Docker is unavailable — the skips happen at test execution time.
skip_no_docker = pytest.mark.skipif(
    not _docker_available(), reason="Docker daemon is not available",
)
skip_no_compose = pytest.mark.skipif(
    not _compose_running(), reason="Integration Compose stack is not running",
)
