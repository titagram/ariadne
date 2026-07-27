"""JSON Schemas for Ariadne's registered Hades tools.

Each schema follows the JSON Schema 2020-12 dialect with Pydantic-style
type annotations that Hades renders for model selection.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

# ── ariadne_prepare_engagement ─────────────────────────────────────────


class PrepareEngagementInput(BaseModel):
    """Answers collected during the interactive contract Q/A."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization_attested: bool
    disclaimer_version: str
    profile: str
    target_host: str
    objectives: list[str]
    autonomy: str = "controlled"
    time_window_minutes: int = 60
    notes: str = ""


PREPARE_ENGAGEMENT_SCHEMA = PrepareEngagementInput.model_json_schema()

# ── ariadne_bind_engagement ─────────────────────────────────────────────


class BindEngagementInput(BaseModel):
    """Lock an engagement to a confirmed challenge."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    challenge_id: str
    session_id: str


BIND_ENGAGEMENT_SCHEMA = BindEngagementInput.model_json_schema()

# ── ariadne_status ──────────────────────────────────────────────────────


class StatusInput(BaseModel):
    """Request current engagement status."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    session_id: str | None = None


STATUS_SCHEMA = StatusInput.model_json_schema()

# ── ariadne_propose_plan ────────────────────────────────────────────────


class ProposePlanInput(BaseModel):
    """Request a bounded action plan for the current engagement."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    snapshot_hash: str
    hypothesis: str = ""
    session_id: str | None = None


PROPOSE_PLAN_SCHEMA = ProposePlanInput.model_json_schema()

# ── ariadne_execute_plan ────────────────────────────────────────────────


class ExecutePlanInput(BaseModel):
    """Execute an approved bounded action plan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: str
    session_id: str | None = None


EXECUTE_PLAN_SCHEMA = ExecutePlanInput.model_json_schema()

# ── ariadne_render_report ───────────────────────────────────────────────


class RenderReportInput(BaseModel):
    """Render a walkthrough or professional report."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    style: str = "walkthrough"
    session_id: str | None = None


RENDER_REPORT_SCHEMA = RenderReportInput.model_json_schema()

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
        handler=None,  # assigned by handlers module
        description="Initiate an engagement contract with collected answers",
        emoji="📋",
    ),
    "ariadne_bind_engagement": ToolRegistration(
        name="ariadne_bind_engagement",
        schema=BIND_ENGAGEMENT_SCHEMA,
        handler=None,
        description="Lock an engagement after user confirmation",
        emoji="🔒",
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
