"""Authoritative pre-tool-call guard contracts."""

from __future__ import annotations

from typing import Any

import pytest

from ariadne.hades_adapter.commands import CURRENT_DISCLAIMER_VERSION, AriadneCommand
from ariadne.hades_adapter.guard_hook import ARIADNE_TOOLS, GuardHook
from ariadne.hades_adapter.session import ChallengeLedger
from ariadne.store.run_store import RunStore


def _answers() -> dict[str, object]:
    return {
        "authorization_attested": True,
        "disclaimer_version": CURRENT_DISCLAIMER_VERSION,
        "profile": "private-lab",
        "target_host": "10.10.10.10",
        "objectives": ["proof"],
        "autonomy": "full",
    }


@pytest.fixture
def command(tmp_path) -> AriadneCommand:
    cmd = AriadneCommand(
        ledger=ChallengeLedger(),
        store=RunStore(base_path=tmp_path),
    )
    cmd.prepare(
        _answers(),
        session_id="active-session",
        trusted_confirmation_digest="a" * 64,
    )
    return cmd


@pytest.fixture
def guard(command: AriadneCommand) -> GuardHook:
    return GuardHook(command)


@pytest.fixture
def inactive_guard(tmp_path) -> GuardHook:
    return GuardHook(
        AriadneCommand(
            ledger=ChallengeLedger(),
            store=RunStore(base_path=tmp_path),
        ),
    )


@pytest.mark.parametrize(
    ("tool_name", "args"),
    [
        ("terminal", {"command": "nmap 10.10.10.10"}),
        ("python", {"code": "subprocess.run(['curl','http://10.10.10.10'])"}),
        ("execute_code", {"code": "run target tool"}),
        ("write_file", {"path": ".../engagement.lock.yaml", "content": "changed"}),
        ("patch", {"path": ".../engagement.lock.yaml"}),
        ("computer", {"action": "click"}),
        ("apply_patch", {}),
    ],
)
def test_bound_session_blocks_execution_and_mutation(
    guard: GuardHook,
    tool_name: str,
    args: dict[str, Any],
) -> None:
    result = guard(tool_name=tool_name, args=args, session_id="active-session")
    assert result is not None
    assert result["action"] == "block"
    assert result["message"]


@pytest.mark.parametrize("tool_name", sorted(ARIADNE_TOOLS))
def test_bound_session_allows_ariadne_tools(
    guard: GuardHook,
    tool_name: str,
) -> None:
    assert guard(tool_name=tool_name, args={}, session_id="active-session") is None


@pytest.mark.parametrize(
    "tool_name",
    ("read_file", "search_files", "web_search", "clarify", "session_search"),
)
def test_bound_session_allows_explicit_read_only_tools(
    guard: GuardHook,
    tool_name: str,
) -> None:
    assert guard(tool_name=tool_name, args={}, session_id="active-session") is None


@pytest.mark.parametrize("tool_name", ("unknown_tool", "browser", "database_query"))
def test_bound_session_blocks_unknown_or_ambiguous_tools(
    guard: GuardHook,
    tool_name: str,
) -> None:
    result = guard(tool_name=tool_name, args={}, session_id="active-session")
    assert result is not None
    assert result["action"] == "block"


@pytest.mark.parametrize("tool_name", ("terminal", "write_file", "execute_code"))
def test_unbound_session_allows_generic_tools(
    inactive_guard: GuardHook,
    tool_name: str,
) -> None:
    assert inactive_guard(
        tool_name=tool_name,
        args={},
        session_id="unknown-session",
    ) is None


def test_guard_recovers_durable_binding_after_service_restart(
    command: AriadneCommand,
) -> None:
    restarted = AriadneCommand(
        ledger=ChallengeLedger(),
        store=command.store,
    )
    guard = GuardHook(restarted)

    result = guard(
        tool_name="execute_code",
        args={"code": "target action"},
        session_id="active-session",
    )

    assert result is not None
    assert result["action"] == "block"
