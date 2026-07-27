"""Hades PluginContext registration for all Ariadne services.

Registers the skill, tools, /ariadne command, and guard hook.
Tool handlers receive an ``ariadne_command`` object in their context
so they can enforce challenge-based confirmation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ariadne.composition import ServiceContainer
from ariadne.hades_adapter.handlers import (
    handle_bind_engagement,
    handle_execute_plan,
    handle_prepare_engagement,
    handle_propose_plan,
    handle_render_report,
    handle_status,
)
from ariadne.hades_adapter.schemas import ARIADNE_TOOLS


def register_plugin(ctx: object, services: ServiceContainer) -> None:
    """Register the Ariadne skill, tools, command, and guard hook."""
    _register_skill(ctx)
    _register_tools(ctx, services)
    _register_command(ctx, services)
    _register_hook(ctx)


# ── internal helpers ───────────────────────────────────────────────────


def _register_skill(ctx: object) -> None:
    skill_rel = Path("skills") / "lab-pentest" / "SKILL.md"
    ctx.register_skill(
        name="lab-pentest",
        path=str(skill_rel),
        description="Controlled authorized lab and CTF pentesting",
    )


def _register_tools(ctx: object, services: ServiceContainer) -> None:
    for tool_name, reg in ARIADNE_TOOLS.items():
        handler = _handler_for(tool_name, services)
        ctx.register_tool(
            name=tool_name,
            toolset="ariadne",
            schema=reg.schema,
            handler=handler,
            is_async=True,
            override=False,
            description=reg.description,
            emoji=reg.emoji,
        )


def _register_command(ctx: object, services: ServiceContainer) -> None:
    """Register /ariadne as a command handler that delegates to AriadneCommand."""

    async def command_handler(args: str, **context: object) -> dict[str, object]:
        del context
        response = services.command.handle(args)
        return {"output": response}

    ctx.register_command(
        name="ariadne",
        handler=command_handler,
        description="Ariadne pentesting engagement commands",
        args_hint=(
            "[new|confirm <code>|status|plan|approve <plan-id>|"
            "reject <plan-id>|evidence|report|abort|doctor]"
        ),
    )


def _register_hook(ctx: object) -> None:
    ctx.register_hook(
        name="pre_tool_call",
        callback=None,  # placeholder — real hook from guard_hook in Task 10
    )


def _handler_for(tool_name: str, services: ServiceContainer) -> object:
    """Return a handler callable with the AriadneCommand injected.

    Wraps the raw handler so that ``ariadne_command`` is passed in
    the ``**context`` dict alongside the Hades-provided context keys.
    """
    raw = _HANDLER_MAP[tool_name]

    async def wrapped(args: dict, **context: object) -> dict:
        return await raw(args, ariadne_command=services.command, **context)

    return wrapped


_HANDLER_MAP: dict[str, Any] = {
    "ariadne_prepare_engagement": handle_prepare_engagement,
    "ariadne_bind_engagement": handle_bind_engagement,
    "ariadne_status": handle_status,
    "ariadne_propose_plan": handle_propose_plan,
    "ariadne_execute_plan": handle_execute_plan,
    "ariadne_render_report": handle_render_report,
}
