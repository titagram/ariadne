"""Hades PluginContext registration for all Ariadne services.

Registers the skill, tools, /ariadne command, and guard hook.
Tool handlers receive an ``ariadne_command`` object in their context.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ariadne.composition import ServiceContainer
from ariadne.hades_adapter.handlers import (
    handle_execute_plan,
    handle_prepare_engagement,
    handle_propose_plan,
    handle_render_report,
    handle_status,
)
from ariadne.hades_adapter.schemas import ARIADNE_TOOLS


def register_plugin(ctx: Any, services: ServiceContainer) -> None:
    """Register the Ariadne skill, tools, command, and guard hook."""
    _register_skill(ctx)
    _register_tools(ctx, services)
    _register_command(ctx, services)
    _register_hook(ctx, services)


# ── internal helpers ───────────────────────────────────────────────────


def _register_skill(ctx: Any) -> None:
    manifest = getattr(ctx, "manifest", None)
    plugin_root = getattr(manifest, "path", None)
    skill_path = (
        Path(plugin_root) / "skills" / "lab-pentest" / "SKILL.md"
        if plugin_root is not None
        else Path(__file__).resolve().parents[3] / "skills" / "lab-pentest" / "SKILL.md"
    )
    ctx.register_skill(
        name="lab-pentest",
        path=skill_path,
        description="Controlled authorized lab and CTF pentesting",
    )


def _register_tools(ctx: Any, services: ServiceContainer) -> None:
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


def _register_command(ctx: Any, services: ServiceContainer) -> None:
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
            "[new|status|plan|approve <plan-id>|"
            "reject <plan-id>|evidence|report|abort|doctor]"
        ),
    )


def _register_hook(ctx: Any, services: ServiceContainer) -> None:
    from ariadne.hades_adapter.guard_hook import GuardHook

    hook = GuardHook(services.command)
    ctx.register_hook(
        hook_name="pre_tool_call",
        callback=hook,
    )


def _handler_for(tool_name: str, services: ServiceContainer) -> object:
    """Return a handler callable with the AriadneCommand injected.

    Wraps the raw handler so that ``ariadne_command``, ``planner``,
    and ``catalog`` are passed in the ``**context`` dict alongside the
    Hades-provided context keys.
    """
    raw = _HANDLER_MAP[tool_name]

    async def wrapped(args: dict, **context: object) -> str:
        import json
        # Inject Ariadne services into context if not already present
        if "ariadne_command" not in context:
            context["ariadne_command"] = services.command
        if "planner" not in context:
            context["planner"] = services.planner
        if "catalog" not in context:
            context["catalog"] = services.catalog
        if "adapter_registry" not in context:
            context["adapter_registry"] = services.adapter_registry
        if "runtime" not in context:
            context["runtime"] = services.adapter_registry.default_runtime
        result = await raw(args, **context)
        return json.dumps(result)

    return wrapped


_HANDLER_MAP: dict[str, Any] = {
    "ariadne_prepare_engagement": handle_prepare_engagement,
    "ariadne_status": handle_status,
    "ariadne_propose_plan": handle_propose_plan,
    "ariadne_execute_plan": handle_execute_plan,
    "ariadne_render_report": handle_render_report,
}
