"""Contract tests for /ariadne grammar and atomic initial locking."""

from __future__ import annotations

import pytest

from ariadne.hades_adapter.commands import (
    CURRENT_DISCLAIMER_VERSION,
    AriadneCommand,
)
from ariadne.hades_adapter.session import ChallengeLedger
from ariadne.store.run_store import RunStore


@pytest.fixture
def command(tmp_path) -> AriadneCommand:
    return AriadneCommand(
        ledger=ChallengeLedger(),
        store=RunStore(base_path=tmp_path),
    )


@pytest.fixture
def valid_answers() -> dict:
    return {
        "authorization_attested": True,
        "disclaimer_version": CURRENT_DISCLAIMER_VERSION,
        "profile": "htb",
        "target_host": "10.10.10.10",
        "objectives": ["user_flag", "root_flag"],
        "autonomy": "controlled",
        "time_window_minutes": 30,
        "notes": "",
    }


def test_confirm_command_is_not_part_of_grammar(command: AriadneCommand) -> None:
    parsed = command.parse("confirm obsolete-token")
    assert parsed.error is not None
    assert "unknown" in parsed.error.lower()


def test_prepare_atomically_locks_snapshot_and_binding(
    command: AriadneCommand,
    valid_answers: dict,
) -> None:
    result = command.prepare(
        valid_answers,
        session_id="trusted-session",
    )
    assert result.status == "active"
    assert result.engagement_id is not None
    assert result.snapshot_hash
    assert command.store.has_snapshot(result.engagement_id)
    binding = command.get_session_binding("trusted-session")
    assert binding is not None
    assert binding.snapshot_hash == result.snapshot_hash


def test_prepare_requires_nonempty_trusted_session(
    command: AriadneCommand,
    valid_answers: dict,
) -> None:
    with pytest.raises(ValueError, match="trusted"):
        command.prepare(valid_answers, session_id="")


def test_atomic_lock_appends_auditable_events(
    command: AriadneCommand,
    valid_answers: dict,
) -> None:
    result = command.prepare(valid_answers, session_id="trusted-session")
    handle = command.store.open(result.engagement_id)
    assert handle is not None
    assert [
        event["event_type"] for event in command.store.read_events(handle)
    ] == ["engagement_locked", "session_bound"]


class TestApprovalCommands:
    def test_unknown_plan_cannot_be_approved(
        self,
        command: AriadneCommand,
    ) -> None:
        assert "unknown" in command.handle(
            "approve no-such-plan",
            trusted_session_id="trusted-test-session",
        ).lower()

    def test_unknown_plan_cannot_be_rejected(
        self,
        command: AriadneCommand,
    ) -> None:
        assert "unknown" in command.handle("reject no-such-plan").lower()
