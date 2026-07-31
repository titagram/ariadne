"""Composition ownership tests for run-scoped Kali runtimes."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from ariadne.composition import ServiceContainer
from ariadne.core.engagement import (
    EngagementConstraints,
    EngagementSnapshot,
    Objective,
    TargetSpec,
)
from ariadne.core.enums import AutonomyMode, EnvironmentProfile
from ariadne.runtime.docker import KaliRuntimeUnavailableError, OnDemandKaliRuntime
from ariadne.runtime.process import ProcessSpec


def _snapshot() -> EngagementSnapshot:
    return EngagementSnapshot(
        engagement_id=uuid4(),
        revision=1,
        previous_snapshot_hash=None,
        snapshot_hash="a" * 64,
        confirmed_at=datetime.now(UTC),
        authorization_attested=True,
        disclaimer_version="1.0",
        profile=EnvironmentProfile.PRIVATE_LAB,
        autonomy=AutonomyMode.FULL,
        targets=(TargetSpec(host="192.0.2.10"),),
        objectives=(Objective(kind="proof"),),
        constraints=EngagementConstraints(),
    )


def test_kali_runtime_factory_reuses_one_owner_for_same_snapshot_and_run(
    tmp_path: Path,
) -> None:
    """One run receives one runtime owner even when actions look it up twice."""
    created: list[object] = []

    def factory(snapshot: EngagementSnapshot, run_root: Path) -> object:
        del snapshot, run_root
        runtime = object()
        created.append(runtime)
        return runtime

    services = ServiceContainer(profile_name="test", kali_runtime_factory=factory)
    snapshot = _snapshot()
    run_root = tmp_path / "run"

    first = services.kali_runtime_factory(snapshot, run_root)
    second = services.kali_runtime_factory(snapshot, run_root)

    assert first is second
    assert created == [first]


def test_kali_runtime_factory_keeps_distinct_runs_isolated(tmp_path: Path) -> None:
    """A second run cannot inherit mutable lifecycle state from the first."""
    created: list[object] = []

    def factory(snapshot: EngagementSnapshot, run_root: Path) -> object:
        del snapshot, run_root
        runtime = object()
        created.append(runtime)
        return runtime

    services = ServiceContainer(profile_name="test", kali_runtime_factory=factory)
    snapshot = _snapshot()

    first = services.kali_runtime_factory(snapshot, tmp_path / "run-one")
    second = services.kali_runtime_factory(snapshot, tmp_path / "run-two")

    assert first is not second
    assert created == [first, second]


def test_cached_runtime_cannot_replace_an_active_callback(tmp_path: Path) -> None:
    """Repeated production lookups retain the callback binding's lifecycle owner."""
    services = ServiceContainer(profile_name="test")
    snapshot = _snapshot()
    run_root = tmp_path / "run"

    first = services.kali_runtime_factory(snapshot, run_root)
    second = services.kali_runtime_factory(snapshot, run_root)

    assert isinstance(first, OnDemandKaliRuntime)
    assert second is first
    asyncio.run(
        first._configure_metasploit_callback(  # noqa: SLF001
            ProcessSpec(
                argv=("msfconsole",),
                environment={
                    "ARIADNE_MSF_CALLBACK_ADVERTISED_ADDRESS": "198.51.100.5",
                    "ARIADNE_MSF_CALLBACK_PUBLISHED_PORT": "4444",
                    "ARIADNE_MSF_CALLBACK_LISTENER_BIND_ADDRESS": "0.0.0.0",
                    "ARIADNE_MSF_CALLBACK_LISTENER_PORT": "4444",
                },
                timeout_seconds=10,
            )
        )
    )

    with pytest.raises(KaliRuntimeUnavailableError, match="cannot change"):
        asyncio.run(
            second._configure_metasploit_callback(  # noqa: SLF001
                ProcessSpec(
                    argv=("msfconsole",),
                    environment={
                        "ARIADNE_MSF_CALLBACK_ADVERTISED_ADDRESS": "198.51.100.6",
                        "ARIADNE_MSF_CALLBACK_PUBLISHED_PORT": "5555",
                        "ARIADNE_MSF_CALLBACK_LISTENER_BIND_ADDRESS": "0.0.0.0",
                        "ARIADNE_MSF_CALLBACK_LISTENER_PORT": "5555",
                    },
                    timeout_seconds=10,
                )
            )
        )


def test_kali_runtime_factory_evicts_only_when_run_is_released(tmp_path: Path) -> None:
    created: list[object] = []

    def factory(snapshot: EngagementSnapshot, run_root: Path) -> object:
        del snapshot, run_root
        runtime = object()
        created.append(runtime)
        return runtime

    services = ServiceContainer(profile_name="test", kali_runtime_factory=factory)
    snapshot = _snapshot()
    run_root = tmp_path / "run"

    first = services.kali_runtime_factory(snapshot, run_root)
    assert services.kali_runtime_factory.release(snapshot, run_root) is first  # type: ignore[attr-defined]
    second = services.kali_runtime_factory(snapshot, run_root)

    assert second is not first
    assert created == [first, second]
