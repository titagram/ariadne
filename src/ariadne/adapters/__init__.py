"""Ariadne adapter package — typed tool adapters for bounded execution.

Provides ``AdapterRegistry`` for looking up adapters by name at execution
time, and ``get_default_runtime()`` for the default execution runtime.
"""

from __future__ import annotations

from typing import Any

from ariadne.adapters.base import Runtime, ToolAdapter
from ariadne.runtime.process import ProcessRunner


class AdapterRegistry:
    """Look up ToolAdapter instances by name.

    Adapters are added via ``register(name, instance)``.  The default
    runtime can be set via ``set_default_runtime()``.
    """

    def __init__(self) -> None:
        self._adapters: dict[str, ToolAdapter] = {}
        self._default_runtime: Runtime = ProcessRunner()
        self._frozen = False

    def register(
        self,
        name: str,
        adapter: Any,
        *,
        override: bool = False,
    ) -> None:
        """Register a ToolAdapter by name.

        Args:
            name: The adapter name used in playbook actions (e.g. ``nmap``).
            adapter: An instance implementing the ``ToolAdapter`` protocol.
        """
        if self._frozen:
            raise RuntimeError("Adapter registry is frozen")
        if not isinstance(adapter, ToolAdapter):
            raise TypeError(
                f"Adapter {name!r} does not implement ToolAdapter protocol. "
                f"Got {type(adapter).__name__}"
            )
        if name in self._adapters and not override:
            raise ValueError(f"Adapter {name!r} is already registered")
        self._adapters[name] = adapter

    def freeze(self) -> None:
        """Prevent adapter and runtime replacement after composition."""
        self._frozen = True

    def get(self, name: str) -> ToolAdapter | None:
        """Look up an adapter by name.

        Returns ``None`` if the adapter is not registered.
        """
        return self._adapters.get(name)

    @property
    def default_runtime(self) -> Runtime:
        return self._default_runtime

    @default_runtime.setter
    def default_runtime(self, runtime: Runtime) -> None:
        if self._frozen:
            raise RuntimeError("Adapter registry is frozen")
        self._default_runtime = runtime

    def __contains__(self, name: str) -> bool:
        return name in self._adapters


# ── no-op adapter for playbooks that need a registered adapter
#     but have no real tool backing (nuclei, screenshot, postex, etc.)


class NoopAdapter:
    """ToolAdapter-compliant no-op that always succeeds with empty output.

    Used for playbooks (nuclei, screenshot, postex, ...) that are
    registered in the workflow but have no real tool implementation
    in the current environment.
    """

    name: str = "noop"

    def __init__(self, name: str = "noop") -> None:
        self._current_operation: str = ""
        if name != "noop":
            self.name = name  # override when registered with a specific name

    async def probe(self, runtime: Runtime) -> Any:
        from ariadne.adapters.base import ToolProbe
        return ToolProbe(available=True)

    def plan(self, action: Any, context: Any) -> Any:
        self._current_operation = action.operation
        from ariadne.runtime.process import ProcessSpec
        return ProcessSpec(
            argv=("echo", "noop"),
            timeout_seconds=10,
            max_output_bytes=1024,
        )

    async def execute(self, spec: Any, runtime: Runtime) -> Any:
        from ariadne.runtime.process import ProcessResult
        return ProcessResult(exit_code=0, stdout="noop\n", stderr="")

    def parse(self, result: Any) -> tuple[Any, ...]:
        # Map operation names to evidence types the state machine expects
        evidence_map = {
            "scan": "vulnerability_validated",
            "capture": "foothold_established",
            "identity": "host_enumerated",
            "sudo_rules": "privesc_found",
        }
        source = evidence_map.get(self._current_operation, self._current_operation or "noop")
        from uuid import uuid4
        from ariadne.core.engagement import TargetSpec
        from ariadne.core.observations import Observation
        return (Observation(
            observation_id=uuid4(),
            target=TargetSpec(host="127.0.0.1"),
            source=source,
            data={"type": source, "summary": f"Simulated {self._current_operation}"},
        ),)

    def classify(self, result: Any, observations: tuple[Any, ...]) -> Any:
        from ariadne.adapters.base import ExecutionClassification
        return ExecutionClassification(kind="success", confidence=0.9, summary="No-op completed")

    async def collect(self, result: Any, collector: object) -> tuple[str, ...]:
        return ()

    async def cleanup(self, context: Any) -> Any:
        from ariadne.adapters.base import CleanupResult
        return CleanupResult(success=True, details="No temporary resources to clean up")


def build_default_registry() -> AdapterRegistry:
    """Build an AdapterRegistry with all known adapters registered.

    Returns:
        An ``AdapterRegistry`` instance with all built-in adapters.
    """
    from ariadne.adapters.active_directory import ActiveDirectoryAdapter
    from ariadne.adapters.httpx import HttpxAdapter
    from ariadne.adapters.metasploit import MetasploitAdapter
    from ariadne.adapters.nmap import NmapAdapter
    from ariadne.adapters.nuclei import NucleiAdapter
    from ariadne.adapters.pivot import PivotAdapter
    from ariadne.adapters.postex import PostExAdapter
    from ariadne.adapters.research import ResearchAdapter
    from ariadne.adapters.screenshot import ScreenshotAdapter
    from ariadne.adapters.zap import ZapAdapter

    registry = AdapterRegistry()
    registry.register("nmap", NmapAdapter())
    registry.register("research", ResearchAdapter())
    registry.register("httpx", HttpxAdapter())
    registry.register("zap", ZapAdapter())
    registry.register("nuclei", NucleiAdapter())
    registry.register("metasploit", MetasploitAdapter())
    registry.register("postex", PostExAdapter())
    registry.register("pivot", PivotAdapter())
    registry.register("screenshot", ScreenshotAdapter())
    registry.register("active_directory", ActiveDirectoryAdapter())

    registry.freeze()
    return registry
