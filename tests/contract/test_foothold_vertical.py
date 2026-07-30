from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from ariadne.adapters.base import AdapterContext, AdapterError, PlannedAction
from ariadne.adapters.curl import CurlAdapter
from ariadne.adapters.pcap import PcapAdapter
from ariadne.adapters.postex import PostExAdapter
from ariadne.adapters.ssh import SshAdapter
from ariadne.core.engagement import TargetSpec
from ariadne.core.planner import Plan
from ariadne.core.planner import PlannedAction as CorePlannedAction
from ariadne.core.policy import CapabilityRule, EffectivePolicy
from ariadne.core.workflow import PlaybookLimits
from ariadne.execution.contracts import (
    ExecutionContractRegistry,
    ExecutionEnvelope,
    GuardedRuntime,
    ProcessAuthorizationError,
)
from ariadne.runtime.process import ProcessResult


def _context(
    tmp_path: Path,
    adapter: str,
    *,
    action_digest: str = "b" * 64,
) -> AdapterContext:
    return AdapterContext(
        target=TargetSpec(host="192.0.2.10"),
        snapshot_hash="a" * 64,
        engagement_id=UUID("00000000-0000-0000-0000-000000000001"),
        adapter_name=adapter,
        run_root=tmp_path,
        cwd=tmp_path,
        action_digest=action_digest,
    )


def test_object_reference_probe_is_target_bound_and_download_is_persisted(
    tmp_path: Path,
) -> None:
    adapter = CurlAdapter()
    context = _context(tmp_path, "curl")
    probe = adapter.plan(
        PlannedAction(
            operation="probe_references",
            inputs={
                "urls": [
                    "http://192.0.2.10/data/0",
                    "http://192.0.2.10/data/1",
                ],
                "timeout": 20,
            },
        ),
        context,
    )

    assert probe.argv.count("--url") == 2
    assert probe.argv.count("--output") == 2
    probe_outputs = [
        Path(probe.argv[index + 1])
        for index, argument in enumerate(probe.argv)
        if argument == "--output"
    ]
    assert all(output.parent == tmp_path / "probes" for output in probe_outputs)
    probe_outputs[0].write_text("<html>No download here</html>")
    probe_outputs[1].write_text(
        "<button onclick=\"location.href='/download/1'\">Download</button>"
    )
    observations = adapter.parse_for_spec(
        ProcessResult(
            exit_code=0,
            stdout=(
                '{"url_effective":"http://192.0.2.10/data/0",'
                '"response_code":200,"content_type":"text/html",'
                '"size_download":29}\n'
                '{"url_effective":"http://192.0.2.10/data/1",'
                '"response_code":200,"content_type":"text/html",'
                '"size_download":64}\n'
            ),
            stderr="",
        ),
        context.target,
        probe,
    )

    assert len(observations) == 3
    assert observations[0].source == "web_object_reference"
    assert observations[0].data["download_candidate"] is False
    assert observations[2].source == "curl"
    assert observations[2].data["url"] == "http://192.0.2.10/download/1"

    verified_probe = adapter.plan(
        PlannedAction(
            operation="probe_references",
            inputs={"urls": ["http://192.0.2.10/download/1"], "timeout": 20},
        ),
        context,
    )
    verified_output = Path(
        verified_probe.argv[verified_probe.argv.index("--output") + 1]
    )
    verified_output.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 64)
    verified = adapter.parse_for_spec(
        ProcessResult(
            exit_code=0,
            stdout=(
                '{"url_effective":"http://192.0.2.10/download/1",'
                '"response_code":200,"content_type":"application/vnd.tcpdump.pcap",'
                '"size_download":68}\n'
            ),
            stderr="",
        ),
        context.target,
        verified_probe,
    )

    assert verified[0].source == "web_object_reference"
    assert verified[0].data["download_candidate"] is True

    download = adapter.plan(
        PlannedAction(
            operation="download",
            inputs={
                "url": "http://192.0.2.10/download/1",
                "expected_content_type": "application/vnd.tcpdump.pcap",
                "max_output": 2 * 1024 * 1024,
            },
        ),
        context,
    )
    output = Path(download.argv[download.argv.index("--output") + 1])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 64)
    downloaded = adapter.parse_for_spec(
        ProcessResult(
            exit_code=0,
            stdout=(
                '{"url_effective":"http://192.0.2.10/download/1",'
                '"response_code":200,"content_type":"application/vnd.tcpdump.pcap",'
                f'"size_download":{output.stat().st_size}}}\n'
            ),
            stderr="",
        ),
        context.target,
        download,
    )
    collected = asyncio.run(
        adapter.collect_for_spec(
            ProcessResult(exit_code=0, stdout="{}", stderr=""),
            download,
            object(),
        )
    )

    assert downloaded[0].source == "web_artifact"
    assert downloaded[0].data["sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()
    assert collected == (output.name,)


def test_object_reference_probe_rejects_another_target(tmp_path: Path) -> None:
    with pytest.raises(AdapterError, match="scope"):
        CurlAdapter().plan(
            PlannedAction(
                operation="probe_references",
                inputs={"urls": ["http://192.0.2.11/data/0"]},
            ),
            _context(tmp_path, "curl"),
        )


class _PcapRuntime:
    async def run(self, spec: object) -> ProcessResult:
        return ProcessResult(
            exit_code=0,
            stdout='USER\t"lab-user"\t\nPASS\t"not-for-evidence"\t\n',
            stderr="",
        )


def test_pcap_credentials_are_persisted_as_protected_references(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "artifacts" / "capture.pcap"
    artifact.parent.mkdir()
    artifact.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 64)
    adapter = PcapAdapter()
    spec = adapter.plan(
        PlannedAction(
            operation="extract_plaintext_credentials",
            inputs={
                "artifact": artifact.name,
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            },
        ),
        _context(tmp_path, "pcap"),
    )

    result = asyncio.run(adapter.execute(spec, _PcapRuntime()))
    observations = adapter.parse_for_spec(
        result,
        TargetSpec(host="192.0.2.10"),
        spec,
    )

    assert "not-for-evidence" not in result.stdout
    assert "not-for-evidence" not in json.dumps(spec.model_dump(mode="json"))
    assert observations[0].source == "credential_material"
    assert observations[0].data["secret_persisted"] is True
    assert observations[0].data["secret_storage"] == "protected_local_reference"
    secret = tmp_path / observations[0].data["credential_ref"]
    assert secret.read_text() == "not-for-evidence"
    assert secret.stat().st_mode & 0o777 == 0o600


def test_pcap_adapter_rejects_untracked_or_tampered_artifacts(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "artifacts" / "capture.pcap"
    artifact.parent.mkdir()
    artifact.write_bytes(b"pcap")
    with pytest.raises(AdapterError, match="digest"):
        PcapAdapter().plan(
            PlannedAction(
                operation="extract_plaintext_credentials",
                inputs={"artifact": artifact.name, "sha256": "0" * 64},
            ),
            _context(tmp_path, "pcap"),
        )


def test_ssh_uses_an_opaque_secret_reference_and_emits_hashed_user_proof(
    tmp_path: Path,
) -> None:
    secret = tmp_path / "secrets" / "credential.secret"
    secret.parent.mkdir()
    secret.write_text("not-for-argv")
    secret.chmod(0o600)
    adapter = SshAdapter()
    spec = adapter.plan(
        PlannedAction(
            operation="authenticate",
            inputs={
                "username": "lab-user",
                "credential_ref": "secrets/credential.secret",
                "port": 22,
            },
        ),
        _context(tmp_path, "ssh"),
    )

    assert spec.argv[0] == "ssh"
    assert "not-for-argv" not in json.dumps(spec.model_dump(mode="json"))
    assert spec.environment["ARIADNE_SECRET_FILE"] == str(secret)
    observations = adapter.parse_for_spec(
        ProcessResult(
            exit_code=0,
            stdout=(
                '{"uid":1000,"gid":1000,"username":"lab-user",'
                f'"user_flag_sha256":"{"1" * 64}"}}\n'
            ),
            stderr="",
        ),
        TargetSpec(host="192.0.2.10"),
        spec,
    )

    assert observations[0].source == "foothold_established"
    assert observations[0].data["objective_proof"] == {
        "kind": "user_flag",
        "description": "Target-local user objective was readable",
        "proof": "1" * 64,
    }


def test_ssh_rejects_a_secret_reference_outside_the_run(tmp_path: Path) -> None:
    with pytest.raises(AdapterError, match="credential"):
        SshAdapter().plan(
            PlannedAction(
                operation="authenticate",
                inputs={
                    "username": "lab-user",
                    "credential_ref": "../credential.secret",
                    "port": 22,
                },
            ),
            _context(tmp_path, "ssh"),
        )


def test_python_setuid_proof_is_evidence_driven_and_never_returns_the_flag(
    tmp_path: Path,
) -> None:
    secret = tmp_path / "secrets" / "credential.secret"
    secret.parent.mkdir()
    secret.write_text("not-for-output")
    secret.chmod(0o600)
    adapter = PostExAdapter()
    context = _context(tmp_path, "postex")
    spec = adapter.plan(
        PlannedAction(
            operation="capability_python_proof",
            inputs={
                "username": "lab-user",
                "credential_ref": "secrets/credential.secret",
                "port": 22,
                "interpreter": "/usr/bin/python3.8",
            },
        ),
        context,
    )

    assert "not-for-output" not in json.dumps(spec.model_dump(mode="json"))
    observations = adapter.parse_for_target(
        ProcessResult(
            exit_code=0,
            stdout=(
                '{"euid":0,"root_flag_sha256":"'
                + "2" * 64
                + '"}\n'
            ),
            stderr="",
        ),
        context.target,
    )

    assert observations[0].data["objective_proof"]["kind"] == "root_flag"
    assert observations[0].data["objective_proof"]["proof"] == "2" * 64


def test_python_setuid_proof_rejects_an_unvalidated_interpreter(
    tmp_path: Path,
) -> None:
    secret = tmp_path / "secrets" / "credential.secret"
    secret.parent.mkdir()
    secret.write_text("secret")
    with pytest.raises(AdapterError, match="interpreter"):
        PostExAdapter().plan(
            PlannedAction(
                operation="capability_python_proof",
                inputs={
                    "username": "lab-user",
                    "credential_ref": "secrets/credential.secret",
                    "interpreter": "/tmp/python",
                },
            ),
            _context(tmp_path, "postex"),
        )


class _RecordingRuntime:
    def __init__(self, result: ProcessResult | None = None) -> None:
        self.calls: list[object] = []
        self.result = result or ProcessResult(exit_code=0, stdout="", stderr="")

    async def run(self, spec: object) -> ProcessResult:
        self.calls.append(spec)
        return self.result


def _guarded_runtime(
    tmp_path: Path,
    *,
    adapter: str,
    operation: str,
    capability: str,
    tool: str,
    inputs: dict[str, object],
    runtime: _RecordingRuntime,
) -> GuardedRuntime:
    now = datetime.now(UTC)
    limits = PlaybookLimits(
        max_rate=10,
        max_concurrency=1,
        max_attempts=1,
        max_duration_seconds=120,
        max_output_bytes=10 * 1024 * 1024,
    )
    plan = Plan(
        plan_id=f"guarded-{adapter}-{operation}",
        snapshot_hash="a" * 64,
        target=TargetSpec(host="192.0.2.10"),
        hypothesis="target-bound synthetic foothold",
        playbook_id=f"test.{adapter}.{operation}.v1",
        capabilities=(capability,),
        actions=(
            CorePlannedAction(
                adapter=adapter,
                operation=operation,
                inputs=inputs,
            ),
        ),
        limits=limits,
        expected_evidence=(),
        stop_conditions=("timeout",),
        requires_manual_approval=False,
        manual_capabilities=(),
        approval_reasons=(),
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    policy = EffectivePolicy(
        name="guarded-vertical",
        version=1,
        capabilities={
            capability: CapabilityRule(
                allowed=True,
                max_rate=10,
                max_concurrency=1,
                max_attempts=1,
                max_duration_seconds=120,
                max_output_bytes=10 * 1024 * 1024,
                allowed_tools=frozenset({tool}),
            ),
        },
        source_digests=("policy-a",),
    )
    envelope = ExecutionEnvelope.from_plan(
        plan,
        action_index=0,
        run_root=tmp_path,
        policy_digests=("policy-a",),
    )
    return GuardedRuntime(
        runtime=runtime,
        envelope=envelope,
        contract=ExecutionContractRegistry.curated().require(adapter, operation),
        policy=policy,
    )


def test_guarded_runtime_authorizes_pcap_ssh_and_python_proof(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "artifacts" / "capture.pcap"
    artifact.parent.mkdir()
    artifact.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 64)
    secret = tmp_path / "secrets" / "credential.secret"
    secret.parent.mkdir()
    secret.write_text("opaque-secret")
    secret.chmod(0o600)

    cases = (
        (
            PcapAdapter(),
            "pcap",
            "extract_plaintext_credentials",
            "artifact.packet_inspection",
            "tshark",
            {
                "artifact": artifact.name,
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            },
        ),
        (
            SshAdapter(),
            "ssh",
            "authenticate",
            "foothold.ssh",
            "ssh",
            {
                "username": "lab-user",
                "credential_ref": "secrets/credential.secret",
                "port": 22,
            },
        ),
        (
            PostExAdapter(),
            "postex",
            "capability_python_proof",
            "privesc.linux.capabilities",
            "ssh",
            {
                "username": "lab-user",
                "credential_ref": "secrets/credential.secret",
                "port": 22,
                "interpreter": "/usr/bin/python3.8",
            },
        ),
    )

    for adapter, name, operation, capability, tool, inputs in cases:
        runtime = _RecordingRuntime()
        context = _context(tmp_path, name)
        spec = adapter.plan(PlannedAction(operation=operation, inputs=inputs), context)
        guard = _guarded_runtime(
            tmp_path,
            adapter=name,
            operation=operation,
            capability=capability,
            tool=tool,
            inputs=inputs,
            runtime=runtime,
        )
        guard.authorize_initial(spec)
        asyncio.run(adapter.execute(spec, guard))
        assert len(runtime.calls) == 1


def test_guarded_runtime_rejects_evidence_substitution(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "artifacts" / "capture.pcap"
    artifact.parent.mkdir()
    artifact.write_bytes(b"trusted-pcap")
    other_artifact = artifact.with_name("other.pcap")
    other_artifact.write_bytes(b"other-pcap")
    secret = tmp_path / "secrets" / "credential.secret"
    secret.parent.mkdir()
    secret.write_text("trusted-secret")
    secret.chmod(0o600)
    other_secret = secret.with_name("other.secret")
    other_secret.write_text("other-secret")
    other_secret.chmod(0o600)

    pcap_inputs = {
        "artifact": artifact.name,
        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
    }
    pcap_spec = PcapAdapter().plan(
        PlannedAction(
            operation="extract_plaintext_credentials",
            inputs=pcap_inputs,
        ),
        _context(tmp_path, "pcap"),
    )
    pcap_guard = _guarded_runtime(
        tmp_path,
        adapter="pcap",
        operation="extract_plaintext_credentials",
        capability="artifact.packet_inspection",
        tool="tshark",
        inputs=pcap_inputs,
        runtime=_RecordingRuntime(),
    )

    ssh_inputs = {
        "username": "lab-user",
        "credential_ref": "secrets/credential.secret",
        "port": 22,
    }
    ssh_spec = SshAdapter().plan(
        PlannedAction(operation="authenticate", inputs=ssh_inputs),
        _context(tmp_path, "ssh"),
    )
    ssh_guard = _guarded_runtime(
        tmp_path,
        adapter="ssh",
        operation="authenticate",
        capability="foothold.ssh",
        tool="ssh",
        inputs=ssh_inputs,
        runtime=_RecordingRuntime(),
    )

    postex_inputs = {
        **ssh_inputs,
        "interpreter": "/usr/bin/python3.8",
    }
    postex_spec = PostExAdapter().plan(
        PlannedAction(
            operation="capability_python_proof",
            inputs=postex_inputs,
        ),
        _context(tmp_path, "postex"),
    )
    postex_guard = _guarded_runtime(
        tmp_path,
        adapter="postex",
        operation="capability_python_proof",
        capability="privesc.linux.capabilities",
        tool="ssh",
        inputs=postex_inputs,
        runtime=_RecordingRuntime(),
    )

    tampered_specs = (
        (
            pcap_guard,
            pcap_spec.model_copy(
                update={
                    "argv": (
                        *pcap_spec.argv[:2],
                        str(other_artifact),
                        *pcap_spec.argv[3:],
                    )
                }
            ),
        ),
        (
            ssh_guard,
            ssh_spec.model_copy(
                update={
                    "environment": {
                        **ssh_spec.environment,
                        "ARIADNE_SECRET_FILE": str(other_secret),
                    }
                }
            ),
        ),
        (
            postex_guard,
            postex_spec.model_copy(
                update={
                    "argv": (
                        *postex_spec.argv[:-1],
                        postex_spec.argv[-1].replace(
                            "/usr/bin/python3.8",
                            "/usr/bin/python3.9",
                            1,
                        ),
                    )
                }
            ),
        ),
    )

    for guard, spec in tampered_specs:
        with pytest.raises(ProcessAuthorizationError):
            guard.authorize_initial(spec)
