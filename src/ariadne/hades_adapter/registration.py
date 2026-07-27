"""Hades PluginContext registration for all Ariadne services."""

from __future__ import annotations

from pathlib import Path

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
    _register_tools(ctx)
    _register_command(ctx)
    _register_hook(ctx)


# ── internal helpers ───────────────────────────────────────────────────


def _register_skill(ctx: object) -> None:
    skill_rel = Path("skills") / "lab-pentest" / "SKILL.md"
    ctx.register_skill(
        name="lab-pentest",
        path=str(skill_rel),
        description="Controlled authorized lab and CTF pentesting",
    )


def _register_tools(ctx: object) -> None:
    for tool_name, reg in ARIADNE_TOOLS.items():
        handler = _handler_for(tool_name)
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


def _register_command(ctx: object) -> None:
    from ariadne.hades_adapter.handlers import handle_status as command_handler

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


_HANDLER_MAP: dict[str, object] = {
    "ariadne_prepare_engagement": handle_prepare_engagement,
    "ariadne_bind_engagement": handle_bind_engagement,
    "ariadne_status": handle_status,
    "ariadne_propose_plan": handle_propose_plan,
    "ariadne_execute_plan": handle_execute_plan,
    "ariadne_render_report": handle_render_report,
}


def _handler_for(tool_name: str) -> object:
    """Return the handler callable for *tool_name*."""
    return _HANDLER_MAP[tool_name]
