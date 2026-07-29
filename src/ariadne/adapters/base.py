"""Tool adapter protocol and base types.

Defines the ``ToolAdapter`` protocol that every concrete adapter must
satisfy, along with the shared types used by its methods: planned
actions, adapter context, tool probes, execution classifications, and
cleanup results.

``ToolAdapter`` is a structural ``Protocol`` — a concrete adapter needs
only to implement all the methods with the correct signatures.  No
explicit inheritance is required.

Adapters are the bridge between Ariadne's bounded execution model and
real security tools.  Each adapter:
1. **Probes** for the tool's presence and version.
2. **Plans** a ``ProcessSpec`` from a typed action + engagement context.
3. **Executes** via the runtime (typically ``ProcessRunner`` or Docker).
4. **Parses** raw output into structured ``Observation`` objects.
5. **Classifies** the result (success, evidence, etc.).
6. **Collects** artifacts as evidence records.
7. **Cleans up** temporary files or resources.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, Protocol, runtime_checkable
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from ariadne.core.engagement import TargetSpec
from ariadne.core.errors import AdapterError  # noqa: F401 — re-exported for adapter SDK users
from ariadne.core.observations import Observation
from ariadne.core.workflow import PlaybookLimits
from ariadne.runtime.process import ProcessResult, ProcessSpec


class Runtime(Protocol):
    """Protocol for execution runtimes that can run ``ProcessSpec``.

    Concrete implementations include ``ProcessRunner`` (direct host
    execution) and ``DockerRuntime`` (container-based execution).
    """

    async def run(self, spec: ProcessSpec) -> ProcessResult:
        """Execute *spec* and return a bounded result."""
        ...


class ToolProbe(BaseModel):
    """Result of probing a tool's availability in the runtime."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    available: bool
    version: str | None = None
    path: str | None = None


class PlannedAction(BaseModel):
    """A typed, planned operation for a tool adapter."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    operation: str
    inputs: dict[str, object] = Field(default_factory=dict)


class AdapterContext(BaseModel):
    """Execution context passed to an adapter during planning."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    target: TargetSpec
    snapshot_hash: str
    engagement_id: UUID
    adapter_name: str
    run_root: Path | None = None
    cwd: Path | None = None
    environment: dict[str, str] = Field(default_factory=dict)
    limits: PlaybookLimits = Field(default_factory=PlaybookLimits)
    capabilities: tuple[str, ...] = ()
    action_digest: str = ""


class ExecutionClassification(BaseModel):
    """Classification of a tool execution result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: str  # e.g. "success", "failure", "partial", "unknown"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    summary: str = ""


class CleanupResult(BaseModel):
    """Result of adapter cleanup."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    success: bool
    details: str = ""


@runtime_checkable
class ToolAdapter(Protocol):
    """Protocol that every Ariadne tool adapter must satisfy.

    All methods except ``plan`` are async.  Adapters are expected to be
    stateless (or store state only for the duration of one action cycle).
    """

    name: ClassVar[str]

    async def probe(self, runtime: Runtime) -> ToolProbe:
        """Check whether the tool is available in *runtime*."""
        ...

    def plan(
        self,
        action: PlannedAction,
        context: AdapterContext,
    ) -> ProcessSpec:
        """Build a ``ProcessSpec`` from a typed action and engagement context.

        This method is synchronous because it only validates inputs and
        constructs data; it does not perform I/O.
        """
        ...

    async def execute(
        self,
        spec: ProcessSpec,
        runtime: Runtime,
    ) -> ProcessResult:
        """Execute the planned *spec* via *runtime*."""
        ...

    def parse(
        self,
        result: ProcessResult,
    ) -> tuple[Observation, ...]:
        """Parse raw *result* output into structured observations.

        This method is synchronous because parsing is CPU-bound, not I/O.
        """
        ...

    def classify(
        self,
        result: ProcessResult,
        observations: tuple[Observation, ...],
    ) -> ExecutionClassification:
        """Classify the execution outcome given the result and observations."""
        ...

    async def collect(
        self,
        result: ProcessResult,
        collector: object,
    ) -> tuple[str, ...]:
        """Collect evidence artifacts.

        *collector* is an opaque ``EvidenceCollector`` protocol defined
        by the evidence module (Task 17+).  For now, it is typed as
        ``object`` so that adapters can be authored without the evidence
        module existing yet.
        """
        ...

    async def cleanup(
        self,
        context: AdapterContext,
    ) -> CleanupResult:
        """Clean up any temporary resources created by this adapter."""
        ...
