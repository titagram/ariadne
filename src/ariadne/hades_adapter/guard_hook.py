"""Non-bypassable pre-tool-call guardrail enforcement.

GuardHook is registered as a ``pre_tool_call`` hook on the Hades
PluginContext.  For sessions that have an active Ariadne engagement,
it blocks generic execution and file-mutation tools so the model
cannot bypass Ariadne's policy enforcement.

The hook does NOT inspect Hades's own approval mode (``--yolo``) and
therefore remains active regardless of that flag.
"""

from __future__ import annotations

from ariadne.hades_adapter.session import ChallengeLedger

ARIADNE_TOOLS: frozenset[str] = frozenset({
    "ariadne_prepare_engagement",
    "ariadne_status",
    "ariadne_propose_plan",
    "ariadne_execute_plan",
    "ariadne_render_report",
})

GENERIC_EXECUTION_TOOLS: frozenset[str] = frozenset({
    "terminal",
    "shell",
    "python",
    "computer",
    "write_file",
    "apply_patch",
})

# Conversational and read-only tools that are always permitted.
ALWAYS_ALLOWED: frozenset[str] = frozenset({
    "read_file",
    "search_files",
    "web_search",
    "web_extract",
    "web_crawl",
    "clarify",
    "memory",
    "session_search",
})


class GuardHook:
    """Pre-tool-call hook that blocks execution bypasses during an active engagement.

    The hook is invoked synchronously by Hades before every tool call.
    If the current session has an active Ariadne binding and the tool
    is a generic execution or file-mutation tool, the call is blocked.
    """

    __slots__ = ("_ledger",)

    def __init__(self, ledger: ChallengeLedger) -> None:
        self._ledger = ledger

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

        # If the session is bound to an engagement, block execution tools.
        if self._ledger.is_session_bound(session_id) and tool_name in GENERIC_EXECUTION_TOOLS:
            return {
                    "action": "block",
                    "message": (
                        f"Tool '{tool_name}' is blocked during an active "
                        "Ariadne engagement. Use Ariadne's tools to perform "
                        "engagement actions."
                    ),
                }

        # No active engagement or unrecognised tool — allow.
        return None
