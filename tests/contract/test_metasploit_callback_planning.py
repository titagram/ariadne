"""Production planner coverage for explicitly attested MSF callbacks."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ariadne.adapters import build_default_registry
from ariadne.adapters.base import ProcessResult, ProcessSpec
from ariadne.composition import build_services
from ariadne.core.planner import Planner
from ariadne.core.workflow import WorkflowCatalog
from ariadne.execution.contracts import ExecutionContractRegistry, ExecutionCoordinator
from ariadne.hades_adapter import handlers as handler_module
from ariadne.hades_adapter.commands import AriadneCommand
from ariadne.hades_adapter.consent import ConsentDecision
from ariadne.hades_adapter.handlers import (
    handle_execute_plan,
    handle_prepare_engagement,
    handle_propose_plan,
)
from ariadne.hades_adapter.registration import _handler_for
from ariadne.hades_adapter.session import ChallengeLedger
from ariadne.runtime.docker import OnDemandKaliRuntime
from ariadne.runtime.preflight import CallbackAddressAttestation
from ariadne.store.run_store import ArtifactInput, Event, RunStore


class _AcceptingConsent:
    async def request_contract(self, summary: object) -> ConsentDecision:
        del summary
        return ConsentDecision.ACCEPT


class _OfflineDockerRuntime:
    """Command runtime for a deterministic Kali/Compose replay."""

    def __init__(self, *, session_opened: bool = True) -> None:
        self.calls: list[ProcessSpec] = []
        self.session_opened = session_opened

    async def run(self, spec: ProcessSpec) -> ProcessResult:
        self.calls.append(spec)
        command = " ".join(spec.argv)
        if " image inspect " in f" {command} ":
            image_ref = spec.argv[-1]
            return ProcessResult(
                exit_code=0,
                stdout=image_ref.rsplit("sha256:", 1)[1] + "\n",
                stderr="",
            )
        if "msfconsole" in spec.argv:
            stdout = (
                "Command shell session 1 opened"
                if self.session_opened
                else "Exploit completed, but no session was created"
            )
            return ProcessResult(exit_code=0, stdout=stdout, stderr="")
        return ProcessResult(exit_code=0, stdout="", stderr="")


async def _prepared_command(tmp_path: Path) -> tuple[AriadneCommand, str, str]:
    command = AriadneCommand(
        ledger=ChallengeLedger(),
        store=RunStore(base_path=tmp_path),
    )
    session_id = "metasploit-callback-planning"
    prepared = await handle_prepare_engagement(
        {
            "profile": "htb",
            "target_host": "192.0.2.19",
            "objectives": ["proof"],
            "autonomy": "full",
        },
        session_id=session_id,
        ariadne_command=command,
        consent_gateway=_AcceptingConsent(),
    )
    assert prepared["status"] == "active", prepared
    return command, session_id, prepared["snapshot_hash"]


def _persist_checked_candidate(
    command: AriadneCommand,
    session_id: str,
    *,
    callback: dict[str, object] | None,
    callback_attestation: dict[str, object] | None,
) -> None:
    binding = command.get_session_binding(session_id)
    assert binding is not None and binding.engagement_id is not None
    run = command.store.open(binding.engagement_id)
    assert run is not None

    candidate: dict[str, object] = {
        "candidate_id": "cve-2099-0001-msf",
        "cve_id": "CVE-2099-0001",
        "product": "Example Server",
        "version": "1.2.3",
        "validation_status": "validated",
        "compatible": True,
        "sources": ["vendor", "nvd", "metasploit"],
        "source_urls": ["https://example.invalid/CVE-2099-0001"],
        "evidence": [{"sha256": "a" * 64, "source": "vendor"}],
        "applicability_evidence": ["observed-version=1.2.3"],
        "metasploit_modules": ["exploit/multi/http/example_server"],
        "check_supported": True,
        "requires_reverse_callback": True,
    }
    if callback is not None:
        candidate["callback"] = callback
    if callback_attestation is not None:
        candidate["callback_attestation"] = callback_attestation

    research_raw = json.dumps(
        {
            "type": "metasploit_candidate",
            "fingerprint": {"product": "Example Server", "version": "1.2.3", "port": 8080},
            "candidates": [candidate],
        },
        sort_keys=True,
    ).encode()
    research = command.store.add_bytes(
        run,
        data=research_raw,
        metadata=ArtifactInput(
            media_type="application/json",
            evidence_type="research_complete",
            source_name="research",
            maximum_bytes=16_384,
        ),
    )
    command.store.append_event(
        run,
        Event(
            event_type="evidence_collected",
            payload={
                "asset": "192.0.2.19",
                "artifact": research.path.name,
                "evidence_id": "research-cve-2099-0001",
                "sha256": research.sha256,
                "adapter": "research",
                "source": "research:investigate",
                "evidence_type": "research_complete",
                "execution_classification": "success",
                "observation_data": json.loads(research_raw),
            },
            timestamp=datetime.now(UTC),
        ),
    )

    check_raw = b'{"module":"exploit/multi/http/example_server","check_status":"vulnerable"}'
    check = command.store.add_bytes(
        run,
        data=check_raw,
        metadata=ArtifactInput(
            media_type="application/json",
            evidence_type="metasploit_check_vulnerable",
            source_name="metasploit",
            maximum_bytes=16_384,
        ),
    )
    command.store.append_event(
        run,
        Event(
            event_type="evidence_collected",
            payload={
                "asset": "192.0.2.19",
                "artifact": check.path.name,
                "evidence_id": "check-cve-2099-0001",
                "sha256": hashlib.sha256(check_raw).hexdigest(),
                "adapter": "metasploit",
                "source": "metasploit:check",
                "evidence_type": "metasploit_check_vulnerable",
                "execution_classification": "success",
                "observation_data": {
                    "type": "metasploit_check_vulnerable",
                    "module": "exploit/multi/http/example_server",
                    "check_status": "vulnerable",
                },
            },
            timestamp=datetime.now(UTC),
        ),
    )
    command.store.append_event(
        run,
        Event(
            event_type="plan_executed",
            payload={
                "plan_id": "checked-module-plan",
                "playbook_id": "validation.metasploit-check.v1",
                "status": "executed",
            },
            timestamp=datetime.now(UTC),
        ),
    )


@pytest.mark.asyncio
async def test_verified_reverse_callback_is_bound_into_the_production_msf_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The planner freshly attests callback ownership instead of trusting the dossier."""
    command, session_id, snapshot_hash = await _prepared_command(tmp_path)
    callback = {
        "advertised_address": "198.51.100.7",
        "published_port": 4444,
        "listener_bind_address": "0.0.0.0",
        "listener_port": 4444,
    }
    _persist_checked_candidate(
        command,
        session_id,
        callback=callback,
        callback_attestation={
            "address": "198.51.100.7",
            "target": "192.0.2.19",
            "source": "macos:route-get+ifconfig",
            "interface": "utun7",
            "route_sha256": "b" * 64,
            "ownership_sha256": "c" * 64,
        },
    )
    fresh = CallbackAddressAttestation(
        address="198.51.100.7",
        target="192.0.2.19",
        source="linux:ip-route-get+ip-addr",
        interface="tun0",
        route_sha256="d" * 64,
        ownership_sha256="e" * 64,
    )
    calls: list[tuple[str, str]] = []

    def _attest(**kwargs: object) -> CallbackAddressAttestation:
        calls.append((str(kwargs["advertised_address"]), str(kwargs["target"])))
        assert kwargs["command_runner"] is None
        return fresh

    monkeypatch.setattr(handler_module, "attest_callback_address", _attest)
    catalog = WorkflowCatalog.load(Path(__file__).parents[2] / "workflows")

    proposed = await handle_propose_plan(
        {"snapshot_hash": snapshot_hash, "hypothesis": "checked exploit"},
        session_id=session_id,
        ariadne_command=command,
        planner=Planner(catalog),
        catalog=catalog,
    )

    assert proposed["status"] == "plan_auto_approved"
    record = command.get_plan_record(proposed["plan_id"])
    assert record is not None
    action = record.plan.actions[0]
    assert action.adapter == "metasploit"
    assert action.operation == "run_module"
    assert action.inputs["callback"] == callback
    assert action.inputs["callback_attestation"] == {
        "address": "198.51.100.7",
        "target": "192.0.2.19",
        "source": "linux:ip-route-get+ip-addr",
        "interface": "tun0",
        "route_sha256": "d" * 64,
        "ownership_sha256": "e" * 64,
    }
    assert action.inputs["check_evidence_id"] == "check-cve-2099-0001"
    assert calls == [("198.51.100.7", "192.0.2.19")]


@pytest.mark.asyncio
async def test_reverse_callback_candidate_without_attested_binding_blocks_before_msfconsole(
    tmp_path: Path,
) -> None:
    """Removing the attestation must block rather than infer Docker bridge state."""
    command, session_id, snapshot_hash = await _prepared_command(tmp_path)
    _persist_checked_candidate(
        command,
        session_id,
        callback=None,
        callback_attestation=None,
    )
    catalog = WorkflowCatalog.load(Path(__file__).parents[2] / "workflows")

    proposed = await handle_propose_plan(
        {"snapshot_hash": snapshot_hash, "hypothesis": "checked exploit"},
        session_id=session_id,
        ariadne_command=command,
        planner=Planner(catalog),
        catalog=catalog,
    )

    assert proposed["status"] == "blocked"
    assert proposed["boundary"] == "metasploit_callback"
    assert proposed["plan_id"] == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("session_opened", [True, False])
async def test_callback_plan_replays_through_guarded_ondemand_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    session_opened: bool,
) -> None:
    command, session_id, snapshot_hash = await _prepared_command(tmp_path)
    callback = {
        "advertised_address": "198.51.100.7",
        "published_port": 4444,
        "listener_bind_address": "0.0.0.0",
        "listener_port": 4444,
    }
    _persist_checked_candidate(
        command,
        session_id,
        callback=callback,
        callback_attestation={
            "address": "198.51.100.7",
            "target": "192.0.2.19",
            "source": "linux:ip-route-get+ip-addr",
            "interface": "tun0",
            "route_sha256": "a" * 64,
            "ownership_sha256": "b" * 64,
        },
    )
    monkeypatch.setattr(
        handler_module,
        "attest_callback_address",
        lambda **_: CallbackAddressAttestation(
            address="198.51.100.7",
            target="192.0.2.19",
            source="linux:ip-route-get+ip-addr",
            interface="tun0",
            route_sha256="c" * 64,
            ownership_sha256="d" * 64,
        ),
    )
    catalog = WorkflowCatalog.load(Path(__file__).parents[2] / "workflows")
    proposed = await handle_propose_plan(
        {"snapshot_hash": snapshot_hash, "hypothesis": "checked exploit"},
        session_id=session_id,
        ariadne_command=command,
        planner=Planner(catalog),
        catalog=catalog,
    )
    assert proposed["status"] == "plan_auto_approved"

    docker_runtime = _OfflineDockerRuntime(session_opened=session_opened)
    binding = command.get_session_binding(session_id)
    assert binding is not None and binding.engagement_id is not None
    run = command.store.open(binding.engagement_id)
    assert run is not None
    runtime = OnDemandKaliRuntime(
        snapshot=run.snapshot,
        run_root=run.path,
        command_runtime=docker_runtime,
        docker_locator=lambda _: "/usr/local/bin/docker",
        kali_image_ref=(
            "ariadne-kali@sha256:38348d7ab556982555ffcea3fcfd0aa9ffaa30286ce4fcc3802cb92aa2c15b67"
        ),
        netguard_image_ref=(
            "ariadne-netguard@sha256:0da048944617b30d54d330d8fd983924ccc2bef45205e901f467229808a95789"
        ),
    )
    result = await handle_execute_plan(
        {"plan_id": proposed["plan_id"]},
        session_id=session_id,
        ariadne_command=command,
        adapter_registry=build_default_registry(),
        runtime=runtime,
        execution_contract_registry=ExecutionContractRegistry.curated(),
        execution_coordinator=ExecutionCoordinator(1),
        catalog=catalog,
    )

    assert result["status"] == ("executed" if session_opened else "partial")
    assert any("msfconsole" in spec.argv for spec in docker_runtime.calls)
    events = command.store.read_events(run)
    sources = {
        event.get("payload", {}).get("observation_data", {}).get("type")
        for event in events
        if event.get("event_type") == "evidence_collected"
    }
    assert ("exploit_succeeded" if session_opened else "exploit_no_session") in sources
    assert "foothold_established" not in sources


@pytest.mark.asyncio
async def test_callback_binding_can_be_supplied_by_trusted_composition_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command, session_id, snapshot_hash = await _prepared_command(tmp_path)
    _persist_checked_candidate(command, session_id, callback=None, callback_attestation=None)
    monkeypatch.setattr(
        handler_module,
        "attest_callback_address",
        lambda **_: CallbackAddressAttestation(
            address="198.51.100.7",
            target="192.0.2.19",
            source="linux:ip-route-get+ip-addr",
            interface="tun0",
            route_sha256="e" * 64,
            ownership_sha256="f" * 64,
        ),
    )
    catalog = WorkflowCatalog.load(Path(__file__).parents[2] / "workflows")
    proposed = await handle_propose_plan(
        {"snapshot_hash": snapshot_hash, "hypothesis": "checked exploit"},
        session_id=session_id,
        ariadne_command=command,
        planner=Planner(catalog),
        catalog=catalog,
        callback_binding={
            "advertised_address": "198.51.100.7",
            "published_port": 4444,
            "listener_bind_address": "0.0.0.0",
            "listener_port": 4444,
        },
    )

    assert proposed["status"] == "plan_auto_approved"
    record = command.get_plan_record(proposed["plan_id"])
    assert record is not None
    action = record.plan.actions[0]
    assert action.inputs["callback"] == {
        "advertised_address": "198.51.100.7",
        "published_port": 4444,
        "listener_bind_address": "0.0.0.0",
        "listener_port": 4444,
    }


@pytest.mark.asyncio
async def test_build_services_exposes_bounded_callback_to_installed_handler(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ARIADNE_MSF_CALLBACK_ADVERTISED_ADDRESS", "198.51.100.7")
    monkeypatch.setenv("ARIADNE_MSF_CALLBACK_PUBLISHED_PORT", "4444")
    monkeypatch.setenv("ARIADNE_MSF_CALLBACK_LISTENER_BIND_ADDRESS", "0.0.0.0")
    monkeypatch.setenv("ARIADNE_MSF_CALLBACK_LISTENER_PORT", "4444")
    services = build_services("test", store=RunStore(base_path=tmp_path))
    assert services.callback_binding == {
        "advertised_address": "198.51.100.7",
        "published_port": 4444,
        "listener_bind_address": "0.0.0.0",
        "listener_port": 4444,
    }
    session_id = "composition-callback"
    prepared = await handle_prepare_engagement(
        {
            "profile": "htb",
            "target_host": "192.0.2.19",
            "objectives": ["proof"],
            "autonomy": "full",
        },
        session_id=session_id,
        ariadne_command=services.command,
        consent_gateway=_AcceptingConsent(),
    )
    assert prepared["status"] == "active", prepared
    _persist_checked_candidate(
        services.command,
        session_id,
        callback=None,
        callback_attestation=None,
    )
    monkeypatch.setattr(
        handler_module,
        "attest_callback_address",
        lambda **_: CallbackAddressAttestation(
            address="198.51.100.7",
            target="192.0.2.19",
            source="linux:ip-route-get+ip-addr",
            interface="tun0",
            route_sha256="1" * 64,
            ownership_sha256="2" * 64,
        ),
    )
    propose = _handler_for("ariadne_propose_plan", services)
    proposed = json.loads(
        await propose(
            {"snapshot_hash": prepared["snapshot_hash"], "hypothesis": "checked exploit"},
            session_id=session_id,
        )
    )
    assert proposed["status"] == "plan_auto_approved"
    record = services.command.get_plan_record(proposed["plan_id"])
    assert record is not None
    assert record.plan.actions[0].inputs["callback"] == services.callback_binding
