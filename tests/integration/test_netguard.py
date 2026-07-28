"""Integration tests for the netguard egress firewall.

Requires a running Docker Compose stack and a pre-configured test
network with an allowed target and a blocked neighbor.
"""

from __future__ import annotations

import subprocess

import pytest

pytestmark = pytest.mark.integration


# ── Helpers ─────────────────────────────────────────────────────────────────────


def _docker_available() -> bool:
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
    """Check whether the ariadne Compose stack is up."""
    try:
        args = [
            "docker", "compose", "-f", "containers/compose.yaml",
            "ps", "--status", "running", "-q",
        ]
        result = subprocess.run(args, capture_output=True, text=True, timeout=15)
        return bool(result.stdout.strip())
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


# ── Fixtures ────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def target_fixture() -> object:
    """Provide allowed/blocked target descriptors for integration testing.

    In a real Docker test the allowed host is the engagement target;
    the blocked neighbor is a distinct address on the same test bridge
    that netguard should deny.
    """
    from types import SimpleNamespace

    target = SimpleNamespace(
        allowed_host="10.10.10.10",
        blocked_neighbor="10.10.10.11",
    )
    return target


@pytest.fixture(scope="module")
def runtime() -> object:
    """Provide a DockerRuntime-like object for in-container checks.

    In a real dockerised test this would be a DockerRuntime bound to the
    ariadne compose stack, using ``docker exec`` to probe connectivity
    from inside the Kali or netguard container.
    """

    class _TestRuntime:
        @staticmethod
        def tcp_connect(host: str, port: int) -> bool:
            result = subprocess.run(
                [
                    "docker", "compose", "-f", "containers/compose.yaml",
                    "exec", "-T", "kali",
                    "sh", "-c",
                    f"echo >/dev/null/tcp/{host}/{port} 2>/dev/null && echo ok || echo fail",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return "ok" in result.stdout.strip()

    return _TestRuntime()


# ── Tests ───────────────────────────────────────────────────────────────────────


@pytest.mark.skipif(
    not _docker_available(), reason="Docker daemon is not available"
)
@pytest.mark.skipif(
    not _compose_running(), reason="Ariadne compose stack is not running"
)
def test_netguard_allows_target_and_blocks_neighbor(
    runtime: object,
    target_fixture: object,
) -> None:
    """Allowlist target must be reachable; blocked neighbor must be denied."""
    assert runtime.tcp_connect(target_fixture.allowed_host, 8080), (
        "Netguard should allow TCP to the confirmed target"
    )
    assert not runtime.tcp_connect(target_fixture.blocked_neighbor, 8080), (
        "Netguard should block TCP to a non-allowlisted neighbor"
    )
