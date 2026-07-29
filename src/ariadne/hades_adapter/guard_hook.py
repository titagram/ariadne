"""Non-bypassable pre-tool-call guardrail enforcement.

GuardHook is registered as a ``pre_tool_call`` hook on the Hades
PluginContext.  For sessions that have an active Ariadne engagement,
it blocks generic execution and file-mutation tools so the model
cannot bypass Ariadne's policy enforcement.

The hook does NOT inspect Hades's own approval mode (``--yolo``) and
therefore remains active regardless of that flag.
"""

from __future__ import annotations

from ariadne.hades_adapter.commands import AriadneCommand

ARIADNE_TOOLS: frozenset[str] = frozenset({
    "ariadne_prepare_engagement",
    "ariadne_status",
    "ariadne_propose_plan",
    "ariadne_execute_plan",
    "ariadne_render_report",
})

GENERIC_EXECUTION_TOOLS: frozenset[str] = frozenset({
    "execute_code",
    "terminal",
    "shell",
    "python",
    "python_exec",
    "computer",
    "write_file",
    "patch",
    "apply_patch",
    "edit_file",
    "delete_file",
})

# Conversational and read-only tools that are always permitted.
ALWAYS_ALLOWED: frozenset[str] = frozenset({
    "read_file",
    "search_files",
    "web_search",
    "clarify",
    "session_search",
})


class GuardHook:
    """Pre-tool-call hook that blocks execution bypasses during an active engagement.

    The hook is invoked synchronously by Hades before every tool call.
    If the current session has an active Ariadne binding and the tool
    is a generic execution or file-mutation tool, the call is blocked.
    """

    __slots__ = ("_command",)

    def __init__(self, command: AriadneCommand) -> None:
        self._command = command

    def __call__(self, **payload: object) -> dict[str, str] | None:
        """Evaluate the tool call and block if it violates guardrails.

        Args:
            **payload: Hades pre-tool-call hook keyword arguments including
                ``tool_name``, ``args``, ``session_id``, ``task_id``,
                ``tool_call_id``, ``turn_id``, and ``api_request_id``.

        Returns:
            ``None`` if the call is allowed, or a dict with ``action``
            set to ``"block"`` and a ``message`` explaining why.
        """
        tool_name = str(payload.get("tool_name", ""))
        session_id = str(payload.get("session_id", ""))

        # Always allow Ariadne's own registered tools.
        if tool_name in ARIADNE_TOOLS:
            return None

        # Always allow read-only conversational and retrieval tools.
        if tool_name in ALWAYS_ALLOWED:
            return None

        try:
            is_bound = self._command.get_session_binding(session_id) is not None
        except Exception as exc:
            return {
                "action": "block",
                "message": (
                    "Ariadne could not verify the durable session binding; "
                    f"tool call blocked fail-closed: {exc}"
                ),
            }

        # During a bound engagement only Ariadne and the explicit read-only
        # allowlist are permitted. Unknown/ambiguous tools fail closed.
        if is_bound:
            return {
                "action": "block",
                "message": (
                    f"Tool '{tool_name}' is blocked during an active "
                    "Ariadne engagement. Use Ariadne's tools to perform "
                    "engagement actions."
                ),
            }

        # No active engagement — Ariadne does not constrain the host session.
        return None
