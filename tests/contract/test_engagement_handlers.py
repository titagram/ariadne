"""Contract tests for Ariadne tool handlers (prepare_engagement, bind_engagement).

Verifies that the handler-level interface enforces challenge-bound
confirmation: prepare_engagement returns a challenge, bind_engagement
requires the same challenge, and the model-facing tool cannot bypass
user confirmation.
"""

from __future__ import annotations

import pytest

from ariadne.hades_adapter.commands import AriadneCommand
from ariadne.hades_adapter.handlers import (
    handle_bind_engagement,
    handle_prepare_engagement,
)
from ariadne.hades_adapter.session import ChallengeLedger
from ariadne.store.run_store import RunStore

pytestmark = pytest.mark.asyncio


# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture
def ledger() -> ChallengeLedger:
    return ChallengeLedger()


@pytest.fixture
def store(tmp_path) -> RunStore:
    return RunStore(base_path=tmp_path)


@pytest.fixture
def command(ledger, store) -> AriadneCommand:
    return AriadneCommand(ledger=ledger, store=store)


@pytest.fixture
def session_id() -> str:
    return "test-session-002"


# ── Handler-level tests ────────────────────────────────────────────────────────
# The handlers delegate to AriadneCommand which enforces the challenge
# contract.  These tests verify the handler signatures and integration
# with the command service.


class TestPrepareEngagement:
    """prepare_engagement tool handler contract tests."""

    def test_handler_exists(self) -> None:
        """The handle_prepare_engagement callable exists."""
        assert callable(handle_prepare_engagement)

    async def test_prepare_via_handler_with_command(
        self, command: AriadneCommand, session_id: str
    ) -> None:
        """Handler delegates to AriadneCommand.prepare() and returns status."""
        args = {
            "authorization_attested": True,
            "disclaimer_version": "2026-07-27",
            "profile": "htb",
            "target_host": "10.10.10.10",
            "objectives": ["user_flag"],
            "autonomy": "controlled",
        }
        result = await handle_prepare_engagement(
            args,
            session_id=session_id,
            ariadne_command=command,
        )
        assert result["status"] == "awaiting_user_confirmation"
        assert "challenge_id" in result


class TestBindEngagement:
    """bind_engagement tool handler contract tests."""

    def test_handler_exists(self) -> None:
        """The handle_bind_engagement callable exists."""
        assert callable(handle_bind_engagement)

    async def test_bind_via_handler_after_confirm(
        self, command: AriadneCommand, session_id: str
    ) -> None:
        """Handler delegates to AriadneCommand and returns snapshot data."""
        args = {
            "authorization_attested": True,
            "disclaimer_version": "2026-07-27",
            "profile": "htb",
            "target_host": "10.10.10.10",
            "objectives": ["user_flag"],
            "autonomy": "controlled",
        }
        prepare_result = await handle_prepare_engagement(
            args,
            session_id=session_id,
            ariadne_command=command,
        )
        challenge_id = prepare_result["challenge_id"]

        # Simulate user confirming via the /ariadne command
        command.handle(f"confirm {challenge_id}")

        # Now bind via the handler
        bind_args = {
            "challenge_id": challenge_id,
            "session_id": session_id,
        }
        bind_result = await handle_bind_engagement(
            bind_args,
            session_id=session_id,
            ariadne_command=command,
        )
        assert "snapshot_hash" in bind_result
        assert bind_result["snapshot_hash"] is not None

    async def test_bind_without_confirm_fails(
        self, command: AriadneCommand, session_id: str
    ) -> None:
        """Handler rejects binding without a prior confirmation."""
        args = {
            "challenge_id": "never-confirmed",
            "session_id": session_id,
        }
        result = await handle_bind_engagement(
            args,
            session_id=session_id,
            ariadne_command=command,
        )
        assert result.get("error") is not None or "snapshot_hash" not in result
