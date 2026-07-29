from __future__ import annotations

import pytest

from ariadne.adapters import AdapterRegistry, build_default_registry
from ariadne.adapters.nmap import NmapAdapter
from ariadne.adapters.research import ResearchAdapter


def test_duplicate_registration_requires_explicit_override() -> None:
    registry = AdapterRegistry()
    registry.register("nmap", NmapAdapter())

    with pytest.raises(ValueError, match="already registered"):
        registry.register("nmap", ResearchAdapter())

    replacement = NmapAdapter()
    registry.register("nmap", replacement, override=True)
    assert registry.get("nmap") is replacement


def test_frozen_registry_rejects_registration_and_runtime_replacement() -> None:
    registry = AdapterRegistry()
    registry.register("nmap", NmapAdapter())
    registry.freeze()

    with pytest.raises(RuntimeError, match="frozen"):
        registry.register("research", ResearchAdapter())
    with pytest.raises(RuntimeError, match="frozen"):
        registry.default_runtime = object()  # type: ignore[assignment]


def test_default_registry_is_frozen() -> None:
    registry = build_default_registry()

    with pytest.raises(RuntimeError, match="frozen"):
        registry.register("nmap", NmapAdapter(), override=True)
