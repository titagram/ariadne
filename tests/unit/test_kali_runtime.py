from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from ariadne.core.engagement import EngagementSnapshot, Objective, TargetSpec
from ariadne.core.enums import AutonomyMode, EnvironmentProfile
from ariadne.runtime.docker import (
    KaliRuntimeUnavailableError,
    LocalFirstRuntime,
    OnDemandKaliRuntime,
)
from ariadne.runtime.process import ProcessResult, ProcessSpec

_REVISION = "9979ce144c257f1c427a75604f8c0ffbc8293390"
_INDEX_SHA = "c8b69adb4b906eba5e9d9239f1d775d8175739a8bc263073243b0f0c129c74f9"


class _DockerCommandRuntime:
    def __init__(self, *, dirty_nuclei_template: bool = False) -> None:
        self.calls: list[ProcessSpec] = []
        self.dirty_nuclei_template = dirty_nuclei_template

    async def run(self, spec: ProcessSpec) -> ProcessResult:
        self.calls.append(spec)
        command = " ".join(spec.argv)
        if self.dirty_nuclei_template and "diff --quiet HEAD --" in command:
            return ProcessResult(exit_code=1, stdout="", stderr="")
        if "rev-parse HEAD" in command or "jq -r .revision" in command:
            stdout = f"{_REVISION}\n"
        elif "sha256sum" in command:
            stdout = f"{_INDEX_SHA}  catalog.index.json\n"
        elif "nuclei " in command and " -target " in command:
            stdout = '{"template-id":"CVE-2021-41773","host":"192.0.2.10"}\n'
        else:
            stdout = "ok\n"
        return ProcessResult(exit_code=0, stdout=stdout, stderr="")


def test_kali_starts_once_and_attests_pinned_nuclei_checkout(
    tmp_path,
) -> None:
    snapshot = EngagementSnapshot(
        engagement_id=uuid4(),
        revision=1,
        previous_snapshot_hash=None,
        snapshot_hash="0" * 64,
        confirmed_at=datetime.now(UTC),
        authorization_attested=True,
        disclaimer_version="1.0",
        profile=EnvironmentProfile.PRIVATE_LAB,
        autonomy=AutonomyMode.CONTROLLED,
        targets=(TargetSpec(host="192.0.2.10"),),
        objectives=(Objective(kind="proof"),),
    )
    command_runtime = _DockerCommandRuntime()
    runtime = OnDemandKaliRuntime(
        snapshot=snapshot,
        run_root=tmp_path,
        command_runtime=command_runtime,
        docker_locator=lambda _: "/usr/local/bin/docker",
    )
    spec = ProcessSpec(
        argv=(
            "nuclei",
            "-t",
            "/opt/nuclei-templates/http/cves/2021/CVE-2021-41773.yaml",
            "-target",
            "192.0.2.10",
            "-json",
            "-rate-limit",
            "1",
            "-timeout",
            "10",
        ),
        timeout_seconds=30,
        max_output_bytes=4096,
    )

    inspection = asyncio.run(runtime.inspect_tool("nuclei"))
    first = asyncio.run(runtime.run(spec))
    second = asyncio.run(runtime.run(spec))

    assert inspection == ("ok", "ok", "ok", "local_help")
    assert first.exit_code == second.exit_code == 0
    assert (tmp_path / "workspace").is_dir()
    assert (tmp_path / "workspace" / "home").is_dir()
    assert (tmp_path / "artifacts").is_dir()
    commands = [" ".join(call.argv) for call in command_runtime.calls]
    compose_up = next(
        call
        for call in command_runtime.calls
        if " up --build --detach --wait " in " ".join(call.argv)
    )
    assert sum(" up --build --detach --wait " in call for call in commands) == 1
    assert compose_up.environment["KALI_BASE_REF"].startswith("sha256:")
    assert compose_up.environment["NETGUARD_BASE_REF"].startswith("sha256:")
    assert sum("rev-parse HEAD" in call for call in commands) == 2
    assert sum("test -f" in call for call in commands) == 2
    assert sum("diff --quiet HEAD --" in call for call in commands) == 2
    assert sum(" nuclei " in call and " -target " in call for call in commands) == 2


def test_kali_rejects_a_modified_selected_nuclei_template(tmp_path) -> None:
    snapshot = EngagementSnapshot(
        engagement_id=uuid4(),
        revision=1,
        previous_snapshot_hash=None,
        snapshot_hash="0" * 64,
        confirmed_at=datetime.now(UTC),
        authorization_attested=True,
        disclaimer_version="1.0",
        profile=EnvironmentProfile.PRIVATE_LAB,
        autonomy=AutonomyMode.CONTROLLED,
        targets=(TargetSpec(host="192.0.2.10"),),
        objectives=(Objective(kind="proof"),),
    )
    runtime = OnDemandKaliRuntime(
        snapshot=snapshot,
        run_root=tmp_path,
        command_runtime=_DockerCommandRuntime(dirty_nuclei_template=True),
        docker_locator=lambda _: "/usr/local/bin/docker",
    )
    spec = ProcessSpec(
        argv=(
            "nuclei",
            "-t",
            "/opt/nuclei-templates/http/cves/2021/CVE-2021-41773.yaml",
            "-target",
            "192.0.2.10",
            "-json",
            "-rate-limit",
            "1",
            "-timeout",
            "10",
        ),
        timeout_seconds=30,
        max_output_bytes=4096,
    )

    with pytest.raises(KaliRuntimeUnavailableError, match="modified"):
        asyncio.run(runtime.run(spec))


def test_research_runtime_routes_each_tool_without_eager_kali() -> None:
    local = _DockerCommandRuntime()
    kali = _DockerCommandRuntime()
    runtime = LocalFirstRuntime(
        local_runtime=local,
        kali_runtime=kali,
        kali_executables=frozenset({"msfconsole"}),
        local_locator=lambda executable: (
            f"/usr/bin/{executable}"
            if executable in {"curl", "searchsploit"}
            else None
        ),
    )

    inspection = asyncio.run(runtime.inspect_tool("searchsploit"))
    asyncio.run(
        runtime.run(
            ProcessSpec(
                argv=("curl", "--version"),
                timeout_seconds=10,
                max_output_bytes=4096,
            )
        )
    )
    asyncio.run(
        runtime.run(
            ProcessSpec(
                argv=("msfconsole", "--version"),
                timeout_seconds=10,
                max_output_bytes=4096,
            )
        )
    )

    assert inspection == (
        "/usr/bin/searchsploit",
        "ok",
        "ok",
        "local_help",
    )
    assert [call.argv[0] for call in local.calls] == [
        "searchsploit",
        "searchsploit",
        "curl",
    ]
    assert [call.argv[0] for call in kali.calls] == ["msfconsole"]
