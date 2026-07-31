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
_PINNED_KALI_REF = (
    "ariadne-kali@sha256:38348d7ab556982555ffcea3fcfd0aa9ffaa30286ce4fcc3802cb92aa2c15b67"
)
_PINNED_NETGUARD_REF = (
    "ariadne-netguard@sha256:0da048944617b30d54d330d8fd983924ccc2bef45205e901f467229808a95789"
)


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


class _PinnedImageCommandRuntime(_DockerCommandRuntime):
    def __init__(self, *, fail_startup: bool = False) -> None:
        super().__init__()
        self.fail_startup = fail_startup

    async def run(self, spec: ProcessSpec) -> ProcessResult:
        command = " ".join(spec.argv)
        if " image inspect " in f" {command} ":
            self.calls.append(spec)
            image_ref = spec.argv[-1]
            return ProcessResult(
                exit_code=0,
                stdout=image_ref.rsplit("sha256:", 1)[1] + "\n",
                stderr="",
            )
        if " up --no-build --detach --wait " in f" {command} " and self.fail_startup:
            self.calls.append(spec)
            return ProcessResult(
                exit_code=1,
                stdout="compose startup failed: netguard unhealthy\n",
                stderr="",
            )
        return await super().run(spec)


class _SearchSploitPackageVersionRuntime(_PinnedImageCommandRuntime):
    async def run(self, spec: ProcessSpec) -> ProcessResult:
        argv = spec.argv
        if argv[-2:] == ("searchsploit", "--version"):
            self.calls.append(spec)
            return ProcessResult(
                exit_code=2,
                stdout="",
                stderr="Usage: searchsploit [options] term\n",
            )
        if argv[-2:] == ("which", "searchsploit"):
            self.calls.append(spec)
            return ProcessResult(
                exit_code=0,
                stdout="/usr/bin/searchsploit\n",
                stderr="",
            )
        if argv[-3:] == ("dpkg-query", "-S", "/usr/bin/searchsploit"):
            self.calls.append(spec)
            return ProcessResult(
                exit_code=0,
                stdout="exploitdb: /usr/bin/searchsploit\n",
                stderr="",
            )
        if "dpkg-query" in argv and "-W" in argv:
            self.calls.append(spec)
            return ProcessResult(
                exit_code=0,
                stdout="20260709-0kali1\n",
                stderr="",
            )
        if argv[-2:] == ("searchsploit", "--help"):
            self.calls.append(spec)
            return ProcessResult(
                exit_code=2,
                stdout=(
                    "Usage: searchsploit [options] term\n"
                    "Options:\n  -h, --help  Show this help screen\n"
                ),
                stderr="",
            )
        return await super().run(spec)


class _ZapProbeCommandRuntime(_PinnedImageCommandRuntime):
    async def run(self, spec: ProcessSpec) -> ProcessResult:
        argv = spec.argv
        if argv[-2:] == ("which", "zaproxy"):
            self.calls.append(spec)
            return ProcessResult(
                exit_code=0,
                stdout="/usr/bin/zaproxy\n",
                stderr="",
            )
        if argv[-4:] == ("dpkg-query", "-W", "-f=${Version}\\n", "zaproxy"):
            self.calls.append(spec)
            return ProcessResult(
                exit_code=0,
                stdout="2.17.0-0kali1\n",
                stderr="",
            )
        return await super().run(spec)


def test_kali_reuses_locally_available_pinned_image_without_rebuild(tmp_path) -> None:
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
    command_runtime = _PinnedImageCommandRuntime()
    runtime = OnDemandKaliRuntime(
        snapshot=snapshot,
        run_root=tmp_path,
        command_runtime=command_runtime,
        docker_locator=lambda _: "/usr/local/bin/docker",
        kali_image_ref=_PINNED_KALI_REF,
        netguard_image_ref=_PINNED_NETGUARD_REF,
    )

    asyncio.run(runtime.inspect_tool("searchsploit"))

    commands = [" ".join(call.argv) for call in command_runtime.calls]
    compose_up = next(
        call for call in command_runtime.calls if " up " in f" {' '.join(call.argv)} "
    )
    assert any(" image inspect " in f" {command} " for command in commands)
    assert " up --no-build --detach --wait " in f" {' '.join(compose_up.argv)} "
    assert "--build" not in compose_up.argv
    assert compose_up.environment["ARIADNE_KALI_IMAGE"] == _PINNED_KALI_REF
    assert compose_up.environment["ARIADNE_NETGUARD_IMAGE"] == _PINNED_NETGUARD_REF


def test_kali_startup_is_bounded_by_the_tool_attempt_timeout(tmp_path) -> None:
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
    command_runtime = _PinnedImageCommandRuntime()
    runtime = OnDemandKaliRuntime(
        snapshot=snapshot,
        run_root=tmp_path,
        command_runtime=command_runtime,
        docker_locator=lambda _: "/usr/local/bin/docker",
        kali_image_ref=_PINNED_KALI_REF,
        netguard_image_ref=_PINNED_NETGUARD_REF,
    )

    asyncio.run(
        runtime.run(
            ProcessSpec(
                argv=(
                    "nuclei",
                    "-t",
                    "/opt/nuclei-templates/http/cves/example.yaml",
                    "-target",
                    "192.0.2.10",
                ),
                timeout_seconds=7,
                max_output_bytes=4096,
            )
        )
    )

    compose_up = next(
        call for call in command_runtime.calls if " up " in f" {' '.join(call.argv)} "
    )
    assert compose_up.timeout_seconds <= 7


def test_kali_uses_package_metadata_when_tool_has_no_version_flag(tmp_path) -> None:
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
        command_runtime=_SearchSploitPackageVersionRuntime(),
        docker_locator=lambda _: "/usr/local/bin/docker",
        kali_image_ref=_PINNED_KALI_REF,
        netguard_image_ref=_PINNED_NETGUARD_REF,
    )

    assert asyncio.run(runtime.inspect_tool("searchsploit")) == (
        "/usr/bin/searchsploit",
        "20260709-0kali1",
        "Usage: searchsploit [options] term\nOptions:\n  -h, --help  Show this help screen",
        "local_help",
    )


def test_kali_zap_probe_uses_package_metadata_within_total_budget(
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
    command_runtime = _ZapProbeCommandRuntime()
    runtime = OnDemandKaliRuntime(
        snapshot=snapshot,
        run_root=tmp_path,
        command_runtime=command_runtime,
        docker_locator=lambda _: "/usr/local/bin/docker",
        kali_image_ref=_PINNED_KALI_REF,
        netguard_image_ref=_PINNED_NETGUARD_REF,
    )

    inspection = asyncio.run(
        runtime.inspect_tool(
            "zaproxy",
            version_args=("-version",),
            help_args=("-help",),
        )
    )

    assert inspection == (
        "/usr/bin/zaproxy",
        "2.17.0-0kali1",
        "OWASP ZAP command line guidance: use -cmd for headless mode, "
        "-autorun for an Automation Framework plan, -version for version "
        "output, and -help for command options.",
        "official_provider",
    )
    probe_calls = [
        call
        for call in command_runtime.calls
        if call.argv[-2:] == ("which", "zaproxy")
        or call.argv[-4:] == ("dpkg-query", "-W", "-f=${Version}\\n", "zaproxy")
    ]
    assert sum(call.timeout_seconds for call in probe_calls) <= 15
    assert not any(
        call.argv[-2:]
        in {
            ("zaproxy", "-version"),
            ("zaproxy", "-help"),
            ("zaproxy", "--help"),
        }
        for call in command_runtime.calls
    )


def test_kali_pins_approved_zap_alias_to_snapshot_target_without_external_dns(
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
    command_runtime = _PinnedImageCommandRuntime()
    runtime = OnDemandKaliRuntime(
        snapshot=snapshot,
        run_root=tmp_path,
        command_runtime=command_runtime,
        docker_locator=lambda _: "/usr/local/bin/docker",
        kali_image_ref=_PINNED_KALI_REF,
        netguard_image_ref=_PINNED_NETGUARD_REF,
    )
    spec = ProcessSpec(
        argv=("zaproxy", "-cmd", "-silent", "-autorun", "/dev/stdin"),
        environment={
            "ARIADNE_ZAP_HTTP_HOST": "vhost.example",
            "ARIADNE_ZAP_NETWORK_TARGET": "192.0.2.10",
        },
        stdin=b"env: {}\njobs: []\n",
        timeout_seconds=30,
        max_output_bytes=4096,
    )

    asyncio.run(runtime.run(spec))

    hosts_file = tmp_path / "workspace" / ".ariadne" / "zap-hosts"
    assert hosts_file.read_text() == "192.0.2.10 vhost.example\n"
    zap_call = next(call for call in command_runtime.calls if "zaproxy" in call.argv)
    java_options = next(
        value.removeprefix("JAVA_TOOL_OPTIONS=")
        for value in zap_call.argv
        if value.startswith("JAVA_TOOL_OPTIONS=")
    )
    assert "-Djdk.net.hosts.file=/workspace/.ariadne/zap-hosts" in java_options
    assert not any("ARIADNE_ZAP_HTTP_HOST=" in value for value in zap_call.argv)
    assert not any("ARIADNE_ZAP_NETWORK_TARGET=" in value for value in zap_call.argv)
    assert zap_call.environment["ARIADNE_ALLOW_TARGETS"].split() == [
        "192.0.2.10:22",
        "192.0.2.10:443",
        "192.0.2.10:80",
        "192.0.2.10:8080",
        "192.0.2.10:8443",
    ]


def test_kali_rejects_zap_alias_binding_to_non_snapshot_ip(tmp_path) -> None:
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
    command_runtime = _PinnedImageCommandRuntime()
    runtime = OnDemandKaliRuntime(
        snapshot=snapshot,
        run_root=tmp_path,
        command_runtime=command_runtime,
        docker_locator=lambda _: "/usr/local/bin/docker",
        kali_image_ref=_PINNED_KALI_REF,
        netguard_image_ref=_PINNED_NETGUARD_REF,
    )
    spec = ProcessSpec(
        argv=("zaproxy", "-cmd", "-silent", "-autorun", "/dev/stdin"),
        environment={
            "ARIADNE_ZAP_HTTP_HOST": "vhost.example",
            "ARIADNE_ZAP_NETWORK_TARGET": "192.0.2.11",
        },
        stdin=b"env: {}\njobs: []\n",
        timeout_seconds=30,
        max_output_bytes=4096,
    )

    with pytest.raises(KaliRuntimeUnavailableError, match="snapshot target"):
        asyncio.run(runtime.run(spec))

    assert command_runtime.calls == []


def test_kali_startup_error_includes_compose_stdout(tmp_path) -> None:
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
        command_runtime=_PinnedImageCommandRuntime(fail_startup=True),
        docker_locator=lambda _: "/usr/local/bin/docker",
        kali_image_ref=_PINNED_KALI_REF,
        netguard_image_ref=_PINNED_NETGUARD_REF,
    )

    with pytest.raises(
        KaliRuntimeUnavailableError,
        match="netguard unhealthy",
    ):
        asyncio.run(runtime.inspect_tool("searchsploit"))


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
        kali_image_ref="",
        netguard_image_ref="",
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
        kali_image_ref="",
        netguard_image_ref="",
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
            f"/usr/bin/{executable}" if executable in {"curl", "searchsploit"} else None
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
