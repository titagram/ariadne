"""Tests for GuardHook pre-tool-call enforcement.

Verifies that during an active Ariadne-bound session, generic execution
and file-mutation tools are blocked while Ariadne tools, read-only
tools, and non-engagement sessions remain unaffected.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest

from ariadne.hades_adapter.guard_hook import (
    ARIADNE_TOOLS,
    GuardHook,
)
from ariadne.hades_adapter.session import ChallengeLedger


@pytest.fixture
def ledger() -> ChallengeLedger:
    """A ChallengeLedger with an active session binding."""
    led = ChallengeLedger()
    eng_id = uuid4()
    challenge_id = led.create_challenge(
        payload_digest="abc123",
        payload={},
        challenge_type="contract",
        engagement_id=eng_id,
    )
    led.consume_challenge(challenge_id)
    led.bind_session(
        challenge_id=challenge_id,
        session_id="active-session",
        engagement_id=eng_id,
        snapshot_hash="snap123",
    )
    return led


@pytest.fixture
def inactive_ledger() -> ChallengeLedger:
    """A ChallengeLedger with no session bindings."""
    return ChallengeLedger()


@pytest.fixture
def guard(ledger: ChallengeLedger) -> GuardHook:
    """GuardHook wired to an active engagement ledger."""
    return GuardHook(ledger)


@pytest.fixture
def inactive_guard(inactive_ledger: ChallengeLedger) -> GuardHook:
    """GuardHook wired to an inactive ledger."""
    return GuardHook(inactive_ledger)


# ── Blocked: generic execution tools during active engagement ──────────


@pytest.mark.parametrize(
    ("tool_name", "args"),
    [
        ("terminal", {"command": "nmap 10.10.10.10"}),
        ("python", {"code": "subprocess.run(['curl','http://10.10.10.10'])"}),
        ("write_file", {"path": ".../engagement.lock.yaml", "content": "changed"}),
        ("terminal", {"command": "docker exec ariadne-kali nmap target"}),
    ],
)
def test_active_engagement_blocks_generic_execution(
    guard: GuardHook, tool_name: str, args: dict[str, Any]
) -> None:
    """During an active engagement, generic execution tools are blocked."""
    result = guard(
        tool_name=tool_name, args=args, session_id="active-session"
    )
    assert result is not None
    assert result["action"] == "block"
    assert result["message"]


# ── Allowed: Ariadne tools during active engagement ────────────────────


@pytest.mark.parametrize("tool_name", sorted(ARIADNE_TOOLS))
def test_active_engagement_allows_ariadne_tools(
    guard: GuardHook, tool_name: str
) -> None:
    """During an active engagement, Ariadne's own tools are always allowed."""
    result = guard(
        tool_name=tool_name, args={}, session_id="active-session"
    )
    assert result is None, f"Ariadne tool {tool_name} should be allowed"


# ── Allowed: non-engagement session (not bound) ────────────────────────


@pytest.mark.parametrize(
    ("tool_name", "args"),
    [
        ("terminal", {"command": "echo hello"}),
        ("write_file", {"path": "/tmp/test.txt", "content": "test"}),
        ("python", {"code": "print('hello')"}),
    ],
)
def test_inactive_session_allows_generic_tools(
    inactive_guard: GuardHook, tool_name: str, args: dict[str, Any]
) -> None:
    """Generic tools are allowed when no engagement is bound."""
    result = inactive_guard(
        tool_name=tool_name, args=args, session_id="unknown-session"
    )
    assert result is None


# ── Specific additional execution tools are blocked ────────────────────


def test_shell_blocked_during_active_engagement(guard: GuardHook) -> None:
    """shell is a generic execution tool and is blocked."""
    result = guard(
        tool_name="shell", args={"command": "ls"}, session_id="active-session"
    )
    assert result is not None
    assert result["action"] == "block"


def test_computer_blocked_during_active_engagement(guard: GuardHook) -> None:
    """computer is a generic execution tool and is blocked."""
    result = guard(
        tool_name="computer",
        args={"action": "click"},
        session_id="active-session",
    )
    assert result is not None
    assert result["action"] == "block"


def test_apply_patch_blocked_during_active_engagement(guard: GuardHook) -> None:
    """apply_patch is a file-mutation tool and is blocked."""
    result = guard(
        tool_name="apply_patch", args={}, session_id="active-session"
    )
    assert result is not None
    assert result["action"] == "block"


# ── Non-blocked session: session_id is not bound ───────────────────────


def test_unbound_session_allows_execution(guard: GuardHook) -> None:
    """A session that is not bound to the engagement is NOT blocked."""
    result = guard(
        tool_name="terminal",
        args={"command": "echo hello"},
        session_id="some-other-session",
    )
    assert result is None
