"""Playbook schema, catalog, and workflow context models.

A playbook declares a reusable, versioned activity that the planner may
select to execute a specific step of a penetration-test engagement.
Every playbook is validated at load time: no shell strings, no unregistered
fields, and every action names an adapter operation rather than an argument
vector.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict

from ariadne.core.engagement import EngagementSnapshot
from ariadne.core.enums import EngagementState
from ariadne.core.errors import WorkflowConfigurationError
from ariadne.core.observations import Asset, Hypothesis, Observation
from ariadne.core.policy import EffectivePolicy

# ── Models ────────────────────────────────────────────────────────────────────


class PlaybookAction(BaseModel):
    """A single adapter operation inside a playbook.

    ``adapter`` names the registered adapter (e.g. ``nmap``, ``httpx``).
    ``operation`` is the adapter-specific operation name.
    ``inputs`` are passed to the adapter as keyword arguments.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    adapter: str
    operation: str
    inputs: dict[str, Any] = {}


class PlaybookLimits(BaseModel):
    """Resource limits declared by a playbook.

    All fields are optional — ``None`` means the playbook places no
    restriction on that dimension.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_rate: int | None = None
    max_concurrency: int | None = None
    max_attempts: int | None = None
    max_duration_seconds: int | None = None
    max_output_bytes: int | None = None


class Trigger(BaseModel):
    """A condition that makes a playbook eligible for selection."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: str
    types: tuple[str, ...] = ()


class Playbook(BaseModel):
    """A versioned, reusable playbook in the workflow catalog.

    Every playbook references adapter operations rather than raw commands.
    The ``limits`` field declares the playbook's own resource bounds, which
    the planner intersects with the effective policy.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    version: int
    stage: str
    triggers: tuple[Trigger, ...]
    required_evidence_types: frozenset[str]
    capabilities: frozenset[str]
    actions: tuple[PlaybookAction, ...]
    limits: PlaybookLimits
    stop_conditions: tuple[str, ...]
    success_emits: tuple[str, ...]
    next_playbooks: tuple[str, ...]
    report_sections: tuple[str, ...]


class WorkflowContext(BaseModel):
    """Context passed to the catalog to determine eligible playbooks."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    snapshot: EngagementSnapshot
    state: EngagementState
    observations: tuple[Observation, ...]
    assets: tuple[Asset, ...]
    effective_policy: EffectivePolicy


class PlanningContext(WorkflowContext):
    """Extended context for building a concrete action plan from a playbook."""

    hypothesis: Hypothesis
    now: datetime


# ── Catalog ───────────────────────────────────────────────────────────────────


class WorkflowCatalog(BaseModel):
    """A catalog of validated, loadable playbooks.

    ``load`` reads every ``.yaml``/``.yml`` file in a directory, validates
    each against the playbook schema, and rejects any file that contains a
    ``shell`` key, an unregistered adapter, or malformed structure.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    playbooks: Mapping[str, Playbook]

    @classmethod
    def load(cls, directory: Path) -> WorkflowCatalog:
        """Load and validate all playbooks from *directory*.

        Args:
            directory: Filesystem path to a directory of ``.yaml``/``.yml``
                playbook files.

        Returns:
            A :class:`WorkflowCatalog` with all valid playbooks keyed by id.

        Raises:
            WorkflowConfigurationError: If any file is unreadable, contains
                malformed YAML, includes a ``shell`` key, or fails Pydantic
                validation.
        """
        playbooks: dict[str, Playbook] = {}

        if not directory.is_dir():
            raise WorkflowConfigurationError(
                f"Workflow directory does not exist: {directory}"
            )

        for path in sorted(directory.iterdir()):
            if path.suffix not in (".yaml", ".yml"):
                continue
            if path.name == "workflow.schema.json":
                continue

            for _, raw in enumerate(cls._read_file(path)):
                cls._reject_shell_keys(raw, path)
                cls._reject_extra_keys(raw, path)
                playbook = cls._parse_playbook(raw, path)

                if playbook.id in playbooks:
                    raise WorkflowConfigurationError(
                        f"Duplicate playbook id {playbook.id!r} in {path}"
                    )
                playbooks[playbook.id] = playbook

        return cls(playbooks=playbooks)

    # ── Internal helpers ─────────────────────────────────────────────────

    @staticmethod
    def _read_file(path: Path) -> list[dict[str, Any]]:
        """Read and parse a YAML playbook file.

        Returns a list of playbook dicts.  A file may contain:
        - a single mapping (one playbook), or
        - a sequence of mappings (multiple playbooks), or
        - ``---``-separated YAML documents (each a playbook).
        """
        try:
            raw = path.read_text(encoding="utf-8")
            documents = list(yaml.safe_load_all(raw))
        except (OSError, yaml.YAMLError) as exc:
            raise WorkflowConfigurationError(
                f"Failed to read or parse {path}: {exc}"
            ) from exc

        # Filter out None documents (trailing --- produces a None).
        documents = [d for d in documents if d is not None]

        if not documents:
            raise WorkflowConfigurationError(
                f"Playbook file {path} is empty or contains no playbook data"
            )

        # Flatten: a document that is itself a list of playbooks.
        result: list[dict[str, Any]] = []
        for doc in documents:
            if isinstance(doc, list):
                result.extend(doc)
            elif isinstance(doc, dict):
                result.append(doc)
            else:
                raise WorkflowConfigurationError(
                    f"Playbook file {path} contains unexpected "
                    f"YAML type: {type(doc).__name__}"
                )
        return result

    @staticmethod
    def _reject_shell_keys(data: dict[str, Any], path: Path) -> None:
        """Reject any action that contains a ``shell`` key."""
        actions = data.get("actions", [])
        if not isinstance(actions, list):
            return
        for i, action in enumerate(actions):
            if isinstance(action, dict) and "shell" in action:
                raise WorkflowConfigurationError(
                    f"Playbook {path} action[{i}] contains a 'shell' key "
                    f"which is forbidden. Use adapter operations instead."
                )

    @staticmethod
    def _reject_extra_keys(data: dict[str, Any], path: Path) -> None:
        """Reject top-level keys that are not recognised playbook fields."""
        known = {
            "id", "version", "stage", "triggers", "required_evidence_types",
            "capabilities", "actions", "limits", "stop_conditions",
            "success_emits", "next_playbooks", "report_sections",
        }
        extra = set(data) - known
        if extra:
            raise WorkflowConfigurationError(
                f"Playbook {path} has unknown keys: {sorted(extra)}"
            )

    @staticmethod
    def _parse_playbook(raw: dict[str, Any], path: Path) -> Playbook:
        """Attempt Pydantic validation of a raw playbook dict."""
        try:
            return Playbook.model_validate(raw)
        except Exception as exc:
            raise WorkflowConfigurationError(
                f"Playbook validation failed for {path}: {exc}"
            ) from exc

    def eligible(self, context: WorkflowContext) -> tuple[Playbook, ...]:
        """Return playbooks that are eligible given *context*.

        A playbook is eligible when:
        - its ``stage`` matches the current engagement state's stage;
        - all ``required_evidence_types`` exist in the context's
          observations;
        - every capability is present and allowed in the effective policy.

        Args:
            context: The current engagement workflow context.

        Returns:
            A tuple of eligible :class:`Playbook` instances.
        """
        result: list[Playbook] = []
        for playbook in self.playbooks.values():
            if not self._stage_matches(playbook, context):
                continue
            if not self._evidence_met(playbook, context):
                continue
            if not self._policy_allows(playbook, context):
                continue
            result.append(playbook)
        return tuple(result)

    @staticmethod
    def _stage_matches(playbook: Playbook, context: WorkflowContext) -> bool:
        """A simple stage-vs-state heuristic: match on stage name."""
        return playbook.stage == context.state.value

    @staticmethod
    def _evidence_met(playbook: Playbook, context: WorkflowContext) -> bool:
        """Check that every required evidence type exists in observations."""
        if not playbook.required_evidence_types:
            return True
        observed_types = {o.source for o in context.observations}
        return playbook.required_evidence_types.issubset(observed_types)

    @staticmethod
    def _policy_allows(playbook: Playbook, context: WorkflowContext) -> bool:
        """Check that every playbook capability is present and allowed."""
        for cap in playbook.capabilities:
            rule = context.effective_policy.capabilities.get(cap)
            if rule is None or not rule.allowed:
                return False
        return True
