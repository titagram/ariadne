"""JSON Schemas for Ariadne's registered Hades tools.

Each schema follows the OpenAI function-calling format so that
``tools.registry.get_definitions()`` wraps them correctly into
``{"type": "function", "function": {...}}`` tool definitions.

The schema maps directly to the ``function`` object:
  {"name": "...", "description": "...", "parameters": {...}}
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ObjectiveAnswer = (
    Literal["user_flag", "root_flag", "domain_admin", "proof"]
    | dict[str, str]
)


def _validate_objective_answers(
    values: list[ObjectiveAnswer],
) -> list[ObjectiveAnswer]:
    for value in values:
        if isinstance(value, dict) and (
            set(value) != {"kind", "description"}
            or value.get("kind") != "custom"
            or not value.get("description", "").strip()
        ):
            raise ValueError(
                "Custom objectives require exactly kind='custom' and a description"
            )
    return values


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

    profile: Literal["private-lab", "htb", "ctf"] = Field(
        ...,
        description=(
            "Environment profile. Must be one of: 'private-lab', 'htb', or 'ctf'."
        ),
    )
    target_host: str = Field(
        ...,
        description="Target host IP address or FQDN (e.g. '192.168.2.148').",
    )
    objectives: list[ObjectiveAnswer] = Field(
        ...,
        min_length=1,
        description=(
            "List of objective kinds. Each must be one of: 'user_flag', "
            "'root_flag', 'domain_admin', 'proof', or a custom objective "
            "object with kind and description."
        ),
    )

    _validate_objectives = field_validator("objectives")(
        _validate_objective_answers
    )
    autonomy: Literal["controlled", "full"] = Field(
        default="controlled",
        description="Autonomy mode: 'controlled' (default) or 'full'.",
    )
    intensity: Literal["low", "normal", "high"] = Field(
        default="normal",
        description="Operational intensity selected in the engagement contract.",
    )
    exclusions: list[str] = Field(
        default_factory=list,
        max_length=50,
        description="Explicitly excluded techniques, services, or actions.",
    )
    time_window_minutes: int = Field(
        default=60,
        ge=1,
        le=1440,
        description="Maximum engagement duration in minutes.",
    )
    notes: str = Field(
        default="",
        max_length=4000,
        description="Optional free-text notes for the engagement.",
    )


PREPARE_ENGAGEMENT_SCHEMA = _build_schema(
    PrepareEngagementInput,
    "Present one trusted Hades summary confirmation, then lock and activate an "
    "engagement from the collected profile, target, objectives, intensity, "
    "exclusions, and bounded limits. Consent is never supplied as tool input.",
)


class AmendEngagementInput(BaseModel):
    """One targeted amendment to the active immutable engagement version."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    add_targets: list[str] = Field(default_factory=list, max_length=20)
    objectives: list[ObjectiveAnswer] | None = None
    intensity: Literal["low", "normal", "high"] | None = None
    exclusions: list[str] | None = Field(default=None, max_length=50)
    candidate_id: str = Field(default="", max_length=100)
    reason: str = Field(..., min_length=1, max_length=1000)

    @model_validator(mode="after")
    def _requires_change(self) -> AmendEngagementInput:
        if not (
            self.add_targets
            or self.objectives is not None
            or self.intensity is not None
            or self.exclusions is not None
        ):
            raise ValueError("An amendment must change at least one contract field")
        return self

    @field_validator("objectives")
    @classmethod
    def _validate_amended_objectives(
        cls,
        values: list[ObjectiveAnswer] | None,
    ) -> list[ObjectiveAnswer] | None:
        return None if values is None else _validate_objective_answers(values)


AMEND_ENGAGEMENT_SCHEMA = _build_schema(
    AmendEngagementInput,
    "Propose a targeted amendment to the active engagement. Hades displays one "
    "trusted summary confirmation, then Ariadne creates a linked immutable version.",
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
    "snapshot hash from ariadne_prepare_engagement. Curated in-policy plans are "
    "durably auto-approved in every autonomy mode; only real manual boundaries "
    "receive trusted Hades consent.",
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
    include_flags: bool | None = Field(
        default=None,
        description=(
            "Include captured CTF flags. Defaults to true for HTB/CTF "
            "engagements and false for other profiles."
        ),
    )
    include_secrets: bool = Field(
        default=False,
        description="Include unredacted secrets. Defaults to redacted.",
    )


RENDER_REPORT_SCHEMA = _build_schema(
    RenderReportInput,
    "Render a walkthrough or professional report for the current engagement. "
    "Use 'walkthrough' for a step-by-step narrative or 'professional' for an "
    "executive-format report.",
)


class RunEngagementInput(BaseModel):
    """Advance autonomously until completion or a typed boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_steps: int = Field(
        default=30,
        ge=1,
        le=100,
        description="Safety bound for deterministic plan/execute iterations.",
    )


RUN_ENGAGEMENT_SCHEMA = _build_schema(
    RunEngagementInput,
    "Advance the active engagement autonomously until objectives and reports "
    "complete or a true policy/scope/runtime/user-choice boundary is reached.",
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
    "ariadne_amend_engagement": ToolRegistration(
        name="ariadne_amend_engagement",
        schema=AMEND_ENGAGEMENT_SCHEMA,
        handler=None,
        description="Create a consented immutable engagement amendment",
        emoji="🧾",
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
    "ariadne_run": ToolRegistration(
        name="ariadne_run",
        schema=RUN_ENGAGEMENT_SCHEMA,
        handler=None,
        description="Run the engagement autonomously until complete or blocked",
        emoji="🧭",
    ),
    "ariadne_render_report": ToolRegistration(
        name="ariadne_render_report",
        schema=RENDER_REPORT_SCHEMA,
        handler=None,
        description="Render a walkthrough or professional report",
        emoji="📄",
    ),
}
