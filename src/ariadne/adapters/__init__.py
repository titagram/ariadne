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


def build_default_registry() -> AdapterRegistry:
    """Build an AdapterRegistry with all known adapters registered.

    Returns:
        An ``AdapterRegistry`` instance with all built-in adapters.
    """
    from ariadne.adapters.active_directory import ActiveDirectoryAdapter
    from ariadne.adapters.curl import CurlAdapter
    from ariadne.adapters.httpx import HttpxAdapter
    from ariadne.adapters.katana import KatanaAdapter
    from ariadne.adapters.metasploit import MetasploitAdapter
    from ariadne.adapters.nmap import NmapAdapter
    from ariadne.adapters.nuclei import NucleiAdapter
    from ariadne.adapters.pcap import PcapAdapter
    from ariadne.adapters.pivot import PivotAdapter
    from ariadne.adapters.postex import PostExAdapter
    from ariadne.adapters.research import ResearchAdapter
    from ariadne.adapters.screenshot import ScreenshotAdapter
    from ariadne.adapters.ssh import SshAdapter
    from ariadne.adapters.zap import ZapAdapter

    registry = AdapterRegistry()
    registry.register("curl", CurlAdapter())
    registry.register("nmap", NmapAdapter())
    registry.register("research", ResearchAdapter())
    registry.register("httpx", HttpxAdapter())
    registry.register("katana", KatanaAdapter())
    registry.register("zap", ZapAdapter())
    registry.register("nuclei", NucleiAdapter())
    registry.register("pcap", PcapAdapter())
    registry.register("metasploit", MetasploitAdapter())
    registry.register("postex", PostExAdapter())
    registry.register("pivot", PivotAdapter())
    registry.register("screenshot", ScreenshotAdapter())
    registry.register("ssh", SshAdapter())
    registry.register("active_directory", ActiveDirectoryAdapter())

    registry.freeze()
    return registry
