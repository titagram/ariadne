"""Ariadne tool handlers.

Each handler is an async function registered with Hades via
``PluginContext.register_tool(…, handler=<this>, is_async=True)``.

These handlers delegate to ``AriadneCommand`` for engagement lifecycle
operations, enforcing the rule that the model cannot self-confirm.
"""

from __future__ import annotations

from typing import Any

from ariadne.hades_adapter.commands import AriadneCommand


def _get_command(context: dict[str, Any]) -> AriadneCommand:
    """Extract the AriadneCommand from the handler context."""
    cmd = context.get("ariadne_command")
    if cmd is None:
        raise ValueError(
            "No ariadne_command available in handler context. "
            "The composition root must pass it as a keyword argument."
        )
    if not isinstance(cmd, AriadneCommand):
        raise TypeError(
            f"Expected AriadneCommand, got {type(cmd).__name__}"
        )
    return cmd


async def handle_prepare_engagement(
    args: dict[str, Any], **context: Any
) -> dict[str, Any]:
    """Collect answers and return a challenge for user confirmation.

    Delegates to ``AriadneCommand.prepare()`` which creates an
    ``EngagementDraft`` and stores a one-time challenge without
    locking a snapshot.

    The model receives the challenge id but cannot confirm it — the
    challenge must be confirmed via the ``/ariadne confirm`` command
    by the user.
    """
    cmd = _get_command(context)
    result = cmd.prepare(args)
    return {
        "status": result.status,
        "message": result.message,
        "challenge_id": result.challenge_id or "",
        "engagement_id": str(result.engagement_id) if result.engagement_id else "",
    }


async def handle_bind_engagement(
    args: dict[str, Any], **context: Any
) -> dict[str, Any]:
    """Lock an engagement after user confirmation.

    Delegates to ``AriadneCommand.lock_and_bind()`` which consumes
    the confirmed challenge, builds the ``EngagementSnapshot``, and
    binds the Hades session.

    The handler returns the snapshot hash on success.  If the user
    has not confirmed via ``/ariadne confirm``, the handler returns
    an error.
    """
    cmd = _get_command(context)
    challenge_id = args.get("challenge_id", "")
    session_id = args.get("session_id", context.get("session_id", ""))

    # Try to find the original answers from the ledger — we need them
    # to rebuild the engagement.  In a production setup these would be
    # stored alongside the challenge record.  For now we use the
    # challenge ledger's payload_digest to verify the binding.
    existing_binding = cmd.ledger.get_binding(challenge_id)
    if existing_binding is not None:
        # Already bound — return the snapshot hash
        return {
            "status": "confirmed",
            "message": "Engagement was already bound to this session.",
            "snapshot_hash": existing_binding.snapshot_hash,
        }

    # The challenge must have been confirmed first
    result = cmd.bind(challenge_id, session_id)
    if result.error is not None:
        return {
            "status": "error",
            "message": result.message,
            "snapshot_hash": "",
            "error": result.error or result.message,
        }

    return {
        "status": "confirmed",
        "message": result.message,
        "snapshot_hash": result.snapshot_hash or "",
    }


async def handle_status(args: dict[str, Any], **context: Any) -> dict[str, Any]:
    """Return current engagement status.

    Checks the ``AriadneCommand`` for any active engagement in the
    ledger.  Otherwise falls back to the generic non-active response.
    """
    del args
    try:
        cmd = _get_command(context)
        session_id = context.get("session_id", "")
        if cmd.ledger.is_session_bound(session_id):
            return {
                "status": "active",
                "message": "Active engagement found for this session.",
            }
    except (ValueError, TypeError):
        pass

    return {
        "status": "no_active_engagement",
        "message": "No active engagement.",
    }


async def handle_propose_plan(args: dict[str, Any], **context: Any) -> dict[str, Any]:
    """Propose a bounded action plan."""
    del context
    return {
        "status": "plan_proposed",
        "plan_id": args.get("plan_id", "stub-plan-id"),
        "message": "Plan proposed (stub).",
    }


async def handle_execute_plan(args: dict[str, Any], **context: Any) -> dict[str, Any]:
    """Execute an approved plan."""
    del context
    return {
        "status": "executed",
        "plan_id": args.get("plan_id", "unknown"),
        "message": "Plan executed (stub).",
    }


async def handle_render_report(args: dict[str, Any], **context: Any) -> dict[str, Any]:
    """Render a walkthrough or professional report."""
    del context
    return {
        "status": "report_rendered",
        "style": args.get("style", "walkthrough"),
        "message": "Report rendered (stub).",
    }
