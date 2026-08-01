"""Hades PluginContext registration for all Ariadne services.

Registers the skill, tools, /ariadne command, and guard hook.
Tool handlers receive an ``ariadne_command`` object in their context.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ariadne.composition import ServiceContainer
from ariadne.hades_adapter.handlers import (
    handle_amend_engagement,
    handle_execute_action,
    handle_execute_plan,
    handle_list_capabilities,
    handle_prepare_engagement,
    handle_propose_plan,
    handle_render_report,
    handle_run_engagement,
    handle_status,
    handle_strategy_hint,
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
        try:
            trusted_session_id = _trusted_session_id_from_hades()
        except RuntimeError as exc:
            return {"output": f"Error: {exc}"}
        response = services.command.handle(
            args,
            trusted_session_id=trusted_session_id,
        )
        return {"output": response}

    ctx.register_command(
        name="ariadne",
        handler=command_handler,
        description="Ariadne pentesting engagement commands",
        args_hint=(
            "[new|status|run|plan|amend-scope|approve <plan-id>|"
            "reject <plan-id>|evidence|report|abort|doctor]"
        ),
    )


def _trusted_session_id_from_hades() -> str:
    """Resolve the current command session from Hades-owned ContextVars.

    The slash command never accepts a session identifier in its arguments.
    If both supported Hades APIs are available they must agree; otherwise
    approval commands fail closed through an empty identity.
    """
    from importlib import import_module

    identities: list[str] = []
    try:
        get_current_session_key = import_module("tools.approval").get_current_session_key
        primary = get_current_session_key(default="")
        if isinstance(primary, str) and primary.strip():
            identities.append(primary.strip())
    except (ImportError, LookupError, RuntimeError, TypeError):
        pass

    try:
        get_session_env = import_module("gateway.session_context").get_session_env
        secondary = get_session_env("HERMES_SESSION_ID", "")
        if isinstance(secondary, str) and secondary.strip():
            identities.append(secondary.strip())
    except (ImportError, LookupError, RuntimeError, TypeError):
        pass

    unique = set(identities)
    if len(unique) > 1:
        raise RuntimeError("Ambiguous trusted Hades session identity.")
    return identities[0] if identities else ""


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

        # Reserved dependencies are composition-owned and non-overridable.
        context["ariadne_command"] = services.command
        context["planner"] = services.planner
        context["catalog"] = services.catalog
        context["adapter_registry"] = services.adapter_registry
        context["runtime"] = services.adapter_registry.default_runtime
        context["consent_gateway"] = services.consent_gateway
        context["execution_contract_registry"] = services.execution_contract_registry
        context["execution_coordinator"] = services.execution_coordinator
        context["tool_card_verifier"] = services.tool_card_verifier
        context["kali_runtime_factory"] = services.kali_runtime_factory
        context["callback_binding"] = services.callback_binding
        result = await raw(args, **context)
        return json.dumps(result)

    return wrapped


_HANDLER_MAP: dict[str, Any] = {
    "ariadne_prepare_engagement": handle_prepare_engagement,
    "ariadne_status": handle_status,
    "ariadne_amend_engagement": handle_amend_engagement,
    "ariadne_propose_plan": handle_propose_plan,
    "ariadne_list_capabilities": handle_list_capabilities,
    "ariadne_execute_action": handle_execute_action,
    "ariadne_strategy_hint": handle_strategy_hint,
    "ariadne_execute_plan": handle_execute_plan,
    "ariadne_run": handle_run_engagement,
    "ariadne_render_report": handle_render_report,
}
