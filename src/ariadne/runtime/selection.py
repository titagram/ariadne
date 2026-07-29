"""Deterministic local-vs-Kali runtime selection.

Kali is an escalation of runtime complexity, not a mandatory first step.
Selection is pure and therefore reviewable before any container lifecycle or
installation action occurs.
"""

from __future__ import annotations

from enum import StrEnum


class RuntimeChoice(StrEnum):
    LOCAL = "local"
    KALI = "kali"
    BLOCKED = "blocked"


_SPECIALIST_PREFIXES = (
    "ad.",
    "pivot.",
    "route.",
    "vpn.",
    "exploit.",
    "postex.",
)


def choose_runtime(
    capabilities: tuple[str, ...],
    *,
    local_tool_available: bool,
    requires_isolation: bool = False,
    requires_compatibility: bool = False,
    requires_vpn_or_routing: bool = False,
) -> RuntimeChoice:
    """Choose the least-complex runtime that satisfies declared needs.

    This function never installs or starts anything. A ``KALI`` result is only
    a proposal for the separately policy-gated container lifecycle.
    """
    specialist = any(
        capability.startswith(_SPECIALIST_PREFIXES)
        for capability in capabilities
    )
    if (
        requires_isolation
        or requires_compatibility
        or requires_vpn_or_routing
        or (specialist and not local_tool_available)
    ):
        return RuntimeChoice.KALI
    if local_tool_available:
        return RuntimeChoice.LOCAL
    return RuntimeChoice.BLOCKED
