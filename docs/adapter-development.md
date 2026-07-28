# Ariadne Adapter Development Guide

This document describes how to create a new tool adapter for Ariadne. Each
adapter follows the `ToolAdapter` protocol defined in
`src/ariadne/adapters/base.py`.

---

## Adapter Protocol

Every adapter must implement the `ToolAdapter` protocol:

```python
class ToolAdapter(Protocol):
    name: ClassVar[str]

    async def probe(self, runtime: Runtime) -> ToolProbe: ...
    def plan(self, action: PlannedAction, context: AdapterContext) -> ProcessSpec: ...
    async def execute(self, spec: ProcessSpec, runtime: Runtime) -> ProcessResult: ...
    def parse(self, result: ProcessResult) -> tuple[Observation, ...]: ...
    def classify(self, result: ProcessResult, observations: tuple[Observation, ...]) -> ExecutionClassification: ...
    async def collect(self, result: ProcessResult, collector: object) -> tuple[str, ...]: ...
    async def cleanup(self, context: AdapterContext) -> CleanupResult: ...
```

No explicit inheritance is required — the protocol is structural. A concrete
adapter simply implements all the methods with the correct signatures.

### Method responsibilities

| Method      | Phase    | Sync/Async | Responsibility |
|-------------|----------|------------|----------------|
| `probe`     | Setup    | Async      | Check whether the tool is available in the runtime; return version info |
| `plan`      | Planning | Sync       | Build a `ProcessSpec` from a typed action and engagement context (no I/O) |
| `execute`   | Execution| Async      | Execute the planned `ProcessSpec` via the runtime |
| `parse`     | Output   | Sync       | Parse raw process output into structured `Observation` objects |
| `classify`  | Output   | Sync       | Classify the execution outcome (success, failure, partial, unknown) |
| `collect`   | Output   | Async      | Collect evidence artifacts from the run |
| `cleanup`   | Teardown | Async      | Remove temporary files or resources |

---

## Shared Types

### Runtime

```python
class Runtime(Protocol):
    async def run(self, spec: ProcessSpec) -> ProcessResult: ...
```

Concrete implementations: `ProcessRunner` (direct host execution) and
`DockerRuntime` (container-based execution).

### ToolProbe

```python
@dataclass
class ToolProbe:
    available: bool
    version: str | None = None
    path: str | None = None
```

### PlannedAction

```python
@dataclass
class PlannedAction:
    operation: str
    inputs: dict[str, object] = {}
```

### AdapterContext

```python
@dataclass
class AdapterContext:
    target: TargetSpec
    snapshot_hash: str
    engagement_id: UUID
    adapter_name: str
    cwd: Path | None = None
    environment: dict[str, str] = {}
```

### ProcessSpec and ProcessResult

Defined in `src/ariadne/runtime/process.py`:

```python
@dataclass(frozen=True)
class ProcessSpec:
    argv: tuple[str, ...]
    timeout: int = 300
    max_output_bytes: int = 10_000_000
    cwd: Path | None = None
    env: dict[str, str] | None = None

@dataclass(frozen=True)
class ProcessResult:
    exit_code: int
    stdout: str
    stderr: str
    duration: float
```

### Observation

```python
@dataclass
class Observation:
    type: str
    key: str
    value: object
    confidence: float = 1.0
    source: str = ""
```

### ExecutionClassification

```python
@dataclass
class ExecutionClassification:
    kind: str          # "success", "failure", "partial", "unknown"
    confidence: float  # 0.0–1.0
    summary: str = ""
```

### CleanupResult

```python
@dataclass
class CleanupResult:
    success: bool
    details: str = ""
```

---

## Adapter lifecycle

```
                    ┌──────────┐
                    │  probe   │
                    └────┬─────┘
                         ▼
                    ┌──────────┐
                    │  plan    │
                    └────┬─────┘
                         ▼
                    ┌──────────┐
                    │ execute  │
                    └────┬─────┘
                         ▼
              ┌──────────────────┐
              │  parse  classify │
              │  collect         │
              └──────────────────┘
                         ▼
                    ┌──────────┐
                    │ cleanup  │
                    └──────────┘
```

1. **Probe** — Called once at adapter registration to verify the tool is
   installed and reachable.
2. **Plan** — Constructs a `ProcessSpec` from the typed action. This is
   synchronous because it only validates inputs and builds data structures.
3. **Execute** — Sends the spec to the runtime (host or Docker) and awaits a
   bounded result.
4. **Parse** — Reads the stdout/stderr and produces structured `Observation`
   objects.
5. **Classify** — Interprets the exit code, output, and observations to
   determine success/failure.
6. **Collect** — Copies relevant output files into the evidence store.
7. **Cleanup** — Removes temporary files created during execution.

---

## Creating a new adapter

### 1. Create the module

```
src/ariadne/adapters/my_tool.py
```

### 2. Implement the protocol

```python
from __future__ import annotations

from typing import ClassVar

from ariadne.adapters.base import (
    AdapterContext,
    CleanupResult,
    ExecutionClassification,
    PlannedAction,
    Runtime,
    ToolAdapter,
    ToolProbe,
)
from ariadne.core.observations import Observation
from ariadne.runtime.process import ProcessResult, ProcessSpec


class MyToolAdapter:
    """Adapter for MyTool."""

    name: ClassVar[str] = "mytool"

    async def probe(self, runtime: Runtime) -> ToolProbe:
        spec = ProcessSpec(argv=("mytool", "--version"))
        result = await runtime.run(spec)
        return ToolProbe(
            available=result.exit_code == 0,
            version=result.stdout.strip() if result.exit_code == 0 else None,
        )

    def plan(
        self,
        action: PlannedAction,
        context: AdapterContext,
    ) -> ProcessSpec:
        argv = ["mytool", action.operation]
        argv.extend(str(v) for v in action.inputs.values())
        return ProcessSpec(argv=tuple(argv))

    async def execute(
        self,
        spec: ProcessSpec,
        runtime: Runtime,
    ) -> ProcessResult:
        return await runtime.run(spec)

    def parse(
        self,
        result: ProcessResult,
    ) -> tuple[Observation, ...]:
        observations: list[Observation] = []
        for line in result.stdout.strip().splitlines():
            if line:
                observations.append(
                    Observation(
                        type="mytool.result",
                        key=line.split()[0],
                        value=line,
                        source=self.name,
                    )
                )
        return tuple(observations)

    def classify(
        self,
        result: ProcessResult,
        observations: tuple[Observation, ...],
    ) -> ExecutionClassification:
        if result.exit_code == 0:
            return ExecutionClassification(
                kind="success",
                confidence=1.0,
                summary=f"Found {len(observations)} items",
            )
        return ExecutionClassification(
            kind="failure",
            confidence=0.9,
            summary=result.stderr[:200],
        )

    async def collect(
        self,
        result: ProcessResult,
        collector: object,
    ) -> tuple[str, ...]:
        # If the adapter produces files, collect them here
        return ()

    async def cleanup(
        self,
        context: AdapterContext,
    ) -> CleanupResult:
        return CleanupResult(success=True)
```

### 3. Register the adapter

Add the adapter to the adapter registry in `composition.py`:

```python
from ariadne.adapters.my_tool import MyToolAdapter

adapters = {
    "mytool": MyToolAdapter(),
}
```

### 4. Add policy tool entries

Add the tool to `allowed_tools` in `policies/base.yaml` for the relevant
capabilities:

```yaml
my.capability:
    allowed: true
    allowed_tools:
      - mytool
```

---

## Fixture requirements for testing

### Contract test structure

Create a contract test in `tests/contract/test_<adapter>_adapter.py`:

```python
from ariadne.adapters.base import ToolAdapter


def test_my_tool_conforms_to_adapter_protocol():
    from ariadne.adapters.my_tool import MyToolAdapter
    adapter = MyToolAdapter()
    assert isinstance(adapter, ToolAdapter)
```

### Unit test setup

Each adapter's unit test should:

1. Create a `TargetSpec` fixture:
   ```python
   @pytest.fixture
   def target() -> TargetSpec:
       return TargetSpec(host="10.10.10.10")
   ```

2. Create an `AdapterContext` fixture:
   ```python
   @pytest.fixture
   def context(target: TargetSpec) -> AdapterContext:
       return AdapterContext(
           target=target,
           snapshot_hash="abc123",
           engagement_id=uuid4(),
           adapter_name="mytool",
       )
   ```

3. Test plan produces expected argv shapes.

4. Test parse handles both clean and malformed output.

5. Test classify correctly distinguishes success from failure exit codes.

6. Test probe returns `ToolProbe(available=True/False)` based on mock runtime.

7. Test cleanup returns success even when there is nothing to clean.

### Mock runtime

Use a simple mock runtime for unit tests:

```python
class MockRuntime:
    def __init__(self, exit_code: int = 0, stdout: str = "", stderr: str = ""):
        self._exit_code = exit_code
        self._stdout = stdout
        self._stderr = stderr

    async def run(self, spec: ProcessSpec) -> ProcessResult:
        return ProcessResult(
            exit_code=self._exit_code,
            stdout=self._stdout,
            stderr=self._stderr,
            duration=0.1,
        )
```
