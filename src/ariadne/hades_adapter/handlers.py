"""Ariadne tool handlers.

Each handler is an async function registered with Hades via
``PluginContext.register_tool(…, handler=<this>, is_async=True)``.

These stubs are replaced with real implementations in later tasks.
"""

from __future__ import annotations

from typing import Any


async def handle_prepare_engagement(args: dict[str, Any], **context: Any) -> dict[str, Any]:
    """Collect answers and return a challenge for user confirmation."""
    del args, context  # unused in stub
    return {
        "status": "awaiting_user_confirmation",
        "message": "Engagement answers recorded. Use /ariadne confirm <challenge-id> to lock.",
        "challenge_id": "stub-placeholder",
    }


async def handle_bind_engagement(args: dict[str, Any], **context: Any) -> dict[str, Any]:
    """Lock an engagement after user confirmation."""
    del args, context  # unused in stub
    return {
        "status": "confirmed",
        "message": "Engagement locked.",
        "snapshot_hash": "stub-hash",
    }


async def handle_status(args: dict[str, Any], **context: Any) -> dict[str, Any]:
    """Return current engagement status."""
    del args, context  # unused in stub
    return {
        "status": "no_active_engagement",
        "message": "No active engagement.",
    }


async def handle_propose_plan(args: dict[str, Any], **context: Any) -> dict[str, Any]:
    """Propose a bounded action plan."""
    del args, context  # unused in stub
    return {
        "status": "plan_proposed",
        "plan_id": "stub-plan-id",
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
