"""JSON Schemas for Ariadne's registered Hades tools.

Each schema follows the OpenAI function-calling format so that
``tools.registry.get_definitions()`` wraps them correctly into
``{"type": "function", "function": {...}}`` tool definitions.

The schema maps directly to the ``function`` object:
  {"name": "...", "description": "...", "parameters": {...}}
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


def _build_schema(model_cls: type[BaseModel], description: str = "") -> dict:
    """Build an OpenAI-compatible tool schema from a Pydantic model.

    Steps:
    1. Generate JSON Schema via ``model_json_schema()``
    2. Drop ``additionalProperties`` (causes HTTP 422 on strict providers)
    3. Wrap ``properties`` and ``required`` inside a ``"parameters"`` object
    4. Attach the human-readable description
    """
    raw = model_cls.model_json_schema()
    raw.pop("additionalProperties", None)  # strict providers reject this
    return {
        "description": description or raw.get("description", ""),
        "parameters": {
            "type": "object",
            "properties": raw.get("properties", {}),
            "required": raw.get("required", []),
        },
    }


# ── ariadne_prepare_engagement ─────────────────────────────────────────


class PrepareEngagementInput(BaseModel):
    """Answers collected during the interactive contract Q/A."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_attested: bool = Field(
        ...,
        description="True if the user has attested authorization for this engagement.",
    )
    disclaimer_version: str = Field(
        ...,
        description="Version string of the disclaimer accepted by the user (e.g. '2026-07-28').",
    )
    profile: Literal["private-lab", "htb"] = Field(
        ...,
        description="Environment profile. Must be one of: 'private-lab' or 'htb'.",
    )
    target_host: str = Field(
        ...,
        description="Target host IP address or FQDN (e.g. '192.168.2.148').",
    )
    objectives: list[
        Literal["user_flag", "root_flag", "domain_admin", "proof"]
    ] = Field(
        ...,
        min_length=1,
        description=(
            "List of objective kinds. Each must be one of: 'user_flag', "
            "'root_flag', 'domain_admin', 'proof'."
        ),
    )
    autonomy: Literal["controlled", "full"] = Field(
        default="controlled",
        description="Autonomy mode: 'controlled' (default) or 'full'.",
    )
    time_window_minutes: int = Field(
        default=60,
        ge=1,
        le=1440,
        description="Maximum engagement duration in minutes.",
    )
    max_requests_per_second: int = Field(
        default=10,
        ge=1,
        le=1000,
        description="Maximum target requests per second.",
    )
    max_concurrent_checks: int = Field(
        default=5,
        ge=1,
        le=100,
        description="Maximum concurrent target checks.",
    )
    notes: str = Field(
        default="",
        max_length=4000,
        description="Optional free-text notes for the engagement.",
    )


PREPARE_ENGAGEMENT_SCHEMA = _build_schema(
    PrepareEngagementInput,
    "Lock and activate an engagement after the interactive Q/A. Provide the "
    "authorized target, profile, objectives, limits, autonomy, and accepted "
    "server-controlled disclaimer version.",
)

# ── ariadne_status ──────────────────────────────────────────────────────


class StatusInput(BaseModel):
    """Request current engagement status."""

    model_config = ConfigDict(extra="forbid", frozen=True)



STATUS_SCHEMA = _build_schema(
    StatusInput,
    "Show the current engagement status and state information for this session.",
)

# ── ariadne_propose_plan ────────────────────────────────────────────────


class ProposePlanInput(BaseModel):
    """Request a bounded action plan for the current engagement."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    snapshot_hash: str = Field(
        ...,
        description="The snapshot hash returned by ariadne_prepare_engagement.",
    )
    hypothesis: str = Field(
        default="",
        description="Optional hypothesis statement for the plan "
        "(e.g. 'Recon and enumerate target').",
    )


PROPOSE_PLAN_SCHEMA = _build_schema(
    ProposePlanInput,
    "Propose a bounded action plan for the current engagement. Requires the "
    "snapshot hash from ariadne_prepare_engagement. Controlled and manual-only "
    "plans receive trusted Hades UI consent during execution; eligible full "
    "plans are durably auto-approved.",
)

# ── ariadne_execute_plan ────────────────────────────────────────────────


class ExecutePlanInput(BaseModel):
    """Execute a bounded plan, eliciting trusted consent when pending."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: str = Field(
        ...,
        description="The plan ID returned by ariadne_propose_plan. Pending "
        "plans trigger trusted Hades UI consent before execution.",
    )


EXECUTE_PLAN_SCHEMA = _build_schema(
    ExecutePlanInput,
    "Execute a bounded action plan. Pending plans require trusted Hades UI "
    "consent in this tool turn; approved plans proceed without another prompt.",
)

# ── ariadne_render_report ───────────────────────────────────────────────


class RenderReportInput(BaseModel):
    """Render a walkthrough or professional report."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    style: str = Field(
        default="walkthrough",
        description="Report style: 'walkthrough' (default) or 'professional'.",
    )


RENDER_REPORT_SCHEMA = _build_schema(
    RenderReportInput,
    "Render a walkthrough or professional report for the current engagement. "
    "Use 'walkthrough' for a step-by-step narrative or 'professional' for an "
    "executive-format report.",
)

# ── Registry ────────────────────────────────────────────────────────────


class ToolRegistration:
    """Metadata for each registered Ariadne tool."""

    __slots__ = ("name", "schema", "handler", "description", "emoji")

    def __init__(
        self,
        name: str,
        schema: dict,
        handler: object,
        description: str,
        emoji: str = "",
    ) -> None:
        self.name = name
        self.schema = schema
        self.handler = handler
        self.description = description
        self.emoji = emoji


ARIADNE_TOOLS: dict[str, ToolRegistration] = {
    "ariadne_prepare_engagement": ToolRegistration(
        name="ariadne_prepare_engagement",
        schema=PREPARE_ENGAGEMENT_SCHEMA,
        handler=None,
        description="Initiate an engagement contract with collected answers",
        emoji="📋",
    ),
    "ariadne_status": ToolRegistration(
        name="ariadne_status",
        schema=STATUS_SCHEMA,
        handler=None,
        description="Show current engagement and state information",
        emoji="📊",
    ),
    "ariadne_propose_plan": ToolRegistration(
        name="ariadne_propose_plan",
        schema=PROPOSE_PLAN_SCHEMA,
        handler=None,
        description="Propose a bounded action plan for the current engagement",
        emoji="📝",
    ),
    "ariadne_execute_plan": ToolRegistration(
        name="ariadne_execute_plan",
        schema=EXECUTE_PLAN_SCHEMA,
        handler=None,
        description="Execute an approved bounded action plan",
        emoji="▶️",
    ),
    "ariadne_render_report": ToolRegistration(
        name="ariadne_render_report",
        schema=RENDER_REPORT_SCHEMA,
        handler=None,
        description="Render a walkthrough or professional report",
        emoji="📄",
    ),
}
