"""Contract tests for /ariadne command parsing and direct approvals.

Uses an in-memory ChallengeLedger and RunStore so tests are hermetic
and the model-facing tool never has direct access to challenge secrets.
"""

from __future__ import annotations

import pytest

from ariadne.hades_adapter.commands import AriadneCommand
from ariadne.hades_adapter.session import ChallengeLedger
from ariadne.store.run_store import RunStore

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
    return "test-session-001"


@pytest.fixture
def valid_answers() -> dict:
    return {
        "authorization_attested": True,
        "disclaimer_version": "2026-07-27",
        "profile": "htb",
        "target_host": "10.10.10.10",
        "objectives": ["user_flag", "root_flag"],
        "autonomy": "controlled",
    }


# ── Parse tests ────────────────────────────────────────────────────────────────


class TestParse:
    def test_new_command(self, command: AriadneCommand) -> None:
        result = command.parse("new")
        assert result.command == "new"
        assert result.args == []

    def test_confirm_command(self, command: AriadneCommand) -> None:
        result = command.parse("confirm abc123")
        assert result.command == "confirm"
        assert result.args == ["abc123"]

    def test_status_command(self, command: AriadneCommand) -> None:
        result = command.parse("status")
        assert result.command == "status"
        assert result.args == []

    def test_approve_with_id(self, command: AriadneCommand) -> None:
        result = command.parse("approve plan-42")
        assert result.command == "approve"
        assert result.args == ["plan-42"]

    def test_reject_with_id(self, command: AriadneCommand) -> None:
        result = command.parse("reject plan-99")
        assert result.command == "reject"
        assert result.args == ["plan-99"]

    def test_abort(self, command: AriadneCommand) -> None:
        result = command.parse("abort")
        assert result.command == "abort"
        assert result.args == []

    def test_report(self, command: AriadneCommand) -> None:
        result = command.parse("report")
        assert result.command == "report"
        assert result.args == []

    def test_extra_tokens_rejected(self, command: AriadneCommand) -> None:
        """Commands with wrong token count are rejected."""
        result = command.parse("confirm too many tokens here")
        assert result.error is not None

    def test_confirm_missing_arg(self, command: AriadneCommand) -> None:
        """confirm requires exactly one argument."""
        result = command.parse("confirm")
        assert result.error is not None

    def test_approve_missing_arg(self, command: AriadneCommand) -> None:
        """approve requires exactly one argument."""
        result = command.parse("approve")
        assert result.error is not None

    def test_unknown_command(self, command: AriadneCommand) -> None:
        result = command.parse("fly")
        assert result.error is not None
        assert "unknown" in result.error.lower()


# ── Prepare / confirm / bind flow tests ────────────────────────────────────────


class TestChallengeFlow:
    def test_prepare_returns_challenge_but_does_not_lock(
        self, command: AriadneCommand, valid_answers: dict
    ) -> None:
        """prepare() creates a challenge but does not write a snapshot."""
        result = command.prepare(valid_answers)
        assert result.status == "awaiting_user_confirmation"
        assert result.challenge_id is not None
        # No snapshot should exist yet — only prepare was called, not confirm
        engagement_id = result.engagement_id
        assert not command.store.has_snapshot(engagement_id)

    def test_direct_confirm_locks_then_bind_requires_same_challenge(
        self, command: AriadneCommand, valid_answers: dict, session_id: str
    ) -> None:
        """User confirms via /ariadne confirm <challenge>, then session binds."""
        prepare_result = command.prepare(valid_answers)
        challenge_id = prepare_result.challenge_id
        assert challenge_id is not None

        # Confirm through the command handler (simulating user input)
        confirm_response = command.handle(f"confirm {challenge_id}")
        assert "confirmed" in confirm_response.lower()

        # The snapshot exists — look up the binding by challenge_id to get
        # the actual engagement_id (it differs from prepare_result because
        # lock_engagement generates its own UUID)
        binding_record = command.ledger.get_binding(challenge_id)
        assert binding_record is not None
        assert binding_record.engagement_id is not None
        assert command.store.has_snapshot(binding_record.engagement_id)

        # Bind the session to the confirmed challenge
        bind_result = command.bind(challenge_id, session_id=session_id)
        assert bind_result.snapshot_hash is not None

    def test_challenge_cannot_be_reused(
        self, command: AriadneCommand, valid_answers: dict
    ) -> None:
        """A consumed challenge cannot be used again."""
        prepare_result = command.prepare(valid_answers)
        challenge_id = prepare_result.challenge_id
        command.handle(f"confirm {challenge_id}")

        # Consuming again should fail
        second = command.handle(f"confirm {challenge_id}")
        assert (
            "already" in second.lower()
            or "expired" in second.lower()
            or "invalid" in second.lower()
        )

    def test_expired_challenge_rejected(
        self, command: AriadneCommand, valid_answers: dict
    ) -> None:
        """A challenge older than 5 minutes is rejected."""
        prepare_result = command.prepare(valid_answers)
        challenge_id = prepare_result.challenge_id

        # Force-expire by setting the challenge's expiry in the past
        command.ledger._expire_challenge(challenge_id)

        response = command.handle(f"confirm {challenge_id}")
        # The error message mentions "expired" for timed-out challenges
        assert "expired" in response.lower() or "invalid" in response.lower()

    def test_wrong_challenge_id_rejected(
        self, command: AriadneCommand
    ) -> None:
        """An unrecognised challenge-id is rejected."""
        response = command.handle("confirm does-not-exist")
        assert "invalid" in response.lower() or "unknown" in response.lower()

    def test_bind_without_confirm_fails(
        self, command: AriadneCommand, valid_answers: dict, session_id: str
    ) -> None:
        """Binding without prior confirmation returns an error, not a snapshot hash."""
        prepare_result = command.prepare(valid_answers)
        challenge_id = prepare_result.challenge_id
        assert challenge_id is not None
        # NOTE: we did NOT call command.handle(f"confirm {challenge_id}")
        result = command.bind(challenge_id, session_id=session_id)
        assert result.error is not None or result.snapshot_hash is None

    def test_bind_with_wrong_session_still_works(
        self, command: AriadneCommand, valid_answers: dict, session_id: str
    ) -> None:
        """After confirming, any session can bind — session check happens later."""
        prepare_result = command.prepare(valid_answers)
        challenge_id = prepare_result.challenge_id
        assert challenge_id is not None
        command.handle(f"confirm {challenge_id}")

        # Different session binds (session binding is per-challenge, not
        # pre-authenticated — the actual session enforcement is in the
        # guard_hook, not in command.bind)
        result = command.bind(challenge_id, session_id="different-session")
        assert result.snapshot_hash is not None

    def test_status_after_confirm_shows_snapshot(
        self, command: AriadneCommand, valid_answers: dict
    ) -> None:
        """Status shows engagement info after confirmation."""
        prepare_result = command.prepare(valid_answers)
        command.handle(f"confirm {prepare_result.challenge_id}")

        status = command.handle("status")
        assert "draft" in status.lower()


# ── Approval command tests ─────────────────────────────────────────────────────


class TestApproval:
    def test_approve_plan_rejects_unknown_id(
        self, command: AriadneCommand
    ) -> None:
        """Approve with an unknown plan id returns a failure message."""
        response = command.handle("approve no-such-plan")
        assert "unknown" in response.lower() or "invalid" in response.lower()

    def test_reject_plan_returns_expected_message(
        self, command: AriadneCommand
    ) -> None:
        """Reject with an unknown plan id returns a failure message."""
        response = command.handle("reject no-such-plan")
        assert "unknown" in response.lower() or "invalid" in response.lower()

    def test_abort_works_without_active(
        self, command: AriadneCommand
    ) -> None:
        """Abort returns a message even when there is no active engagement."""
        response = command.handle("abort")
        assert response
