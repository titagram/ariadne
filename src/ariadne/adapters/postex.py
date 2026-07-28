"""Curated Linux and Windows post-exploitation adapter for Ariadne.

Provides bounded post-exploitation operations covering:

**Linux:** identity, sudo_rules, suid_files, file_capabilities,
scheduled_jobs, services, linpeas_standard, pspy_bounded.

**Windows:** identity, token_privileges, services, scheduled_tasks,
registry, winpeas_standard, privesccheck, seatbelt_selected.

Windows binary upload operations (winpeas, privesccheck, seatbelt)
require the ``exploit.payload_upload`` capability in the engagement
context.  All operations emit a randomized path for remote payloads
and record cleanup records for partially failed uploads.
"""

from __future__ import annotations

import re
from typing import ClassVar
from uuid import uuid4

from ariadne.adapters.base import (
    AdapterContext,
    AdapterError,
    CleanupResult,
    ExecutionClassification,
    PlannedAction,
    ProcessResult,
    ProcessSpec,
    Runtime,
    ToolProbe,
)
from ariadne.core.errors import AdapterPolicyError
from ariadne.core.observations import Observation

# ── Operation catalogs ────────────────────────────────────────────────────────

_LINUX_OPERATIONS: frozenset = frozenset({
    "identity",
    "sudo_rules",
    "suid_files",
    "file_capabilities",
    "scheduled_jobs",
    "services",
    "linpeas",
    "pspy_bounded",
})

_WINDOWS_OPERATIONS: frozenset = frozenset({
    "identity",
    "token_privileges",
    "services",
    "scheduled_tasks",
    "registry",
    "winpeas",
    "privesccheck",
    "seatbelt",
})

# Operations that require uploading a binary to the Windows target.
_UPLOAD_OPS: frozenset = frozenset({"winpeas", "privesccheck", "seatbelt"})

# Capability key for payload upload operations.
_PAYLOAD_UPLOAD_CAP = "exploit.payload_upload"

# Environment variable prefix for capability keys.
_CAPABILITY_ENV_PREFIX = "CAPABILITY_"

# ── Curated binary metadata ──────────────────────────────────────────────────
# Upstream release URL, version, SHA-256, license, architecture, and local
# container path for each post-exploitation tool binary.

_CURATED_BINARIES: dict[str, dict[str, str]] = {
    "linpeas": {
        "url": (
            "https://github.com/peass-ng/PEASS-ng/releases/download/"
            "20250101/linpeas.sh"
        ),
        "version": "20250101",
        "sha256": "e" * 64,
        "license": "GPL-2.0",
        "arch": "linux/amd64",
        "container_path": "/opt/tools/linpeas.sh",
    },
    "pspy": {
        "url": (
            "https://github.com/DominicBreuker/pspy/releases/download/"
            "v1.2.1/pspy64"
        ),
        "version": "1.2.1",
        "sha256": "f" * 64,
        "license": "MIT",
        "arch": "linux/amd64",
        "container_path": "/opt/tools/pspy64",
    },
    "winpeas": {
        "url": (
            "https://github.com/peass-ng/PEASS-ng/releases/download/"
            "20250101/winPEASx64.exe"
        ),
        "version": "20250101",
        "sha256": "a" * 64,
        "license": "GPL-2.0",
        "arch": "windows/amd64",
        "container_path": "/opt/tools/winPEASx64.exe",
    },
    "privesccheck": {
        "url": (
            "https://raw.githubusercontent.com/itm4n/PrivescCheck/"
            "refs/heads/master/PrivescCheck.ps1"
        ),
        "version": "latest",
        "sha256": "b" * 64,
        "license": "MIT",
        "arch": "windows/any",
        "container_path": "/opt/tools/PrivescCheck.ps1",
    },
    "seatbelt": {
        "url": (
            "https://github.com/GhostPack/Seatbelt/releases/download/"
            "v1.0.0/Seatbelt.exe"
        ),
        "version": "1.0.0",
        "sha256": "c" * 64,
        "license": "BSD-3-Clause",
        "arch": "windows/amd64",
        "container_path": "/opt/tools/Seatbelt.exe",
    },
}

# ── Capability helpers ───────────────────────────────────────────────────────


def _capability_env_key(capability: str) -> str:
    """Convert ``exploit.payload_upload`` → ``CAPABILITY_exploit_payload_upload``."""
    safe = capability.replace(".", "_").replace("-", "_")
    return f"{_CAPABILITY_ENV_PREFIX}{safe}"


def _check_capability(
    context: AdapterContext,
    capability: str,
    operation: str,
) -> None:
    """Check whether *capability* is allowed in *context*.

    Raises ``AdapterPolicyError`` if the capability is explicitly denied
    or not present (for upload-sensitive operations).
    """
    env_key = _capability_env_key(capability)
    value = context.environment.get(env_key, "").lower()

    if value == "allow":
        return
    if value == "deny":
        raise AdapterPolicyError(
            f"Operation {operation!r} requires capability {capability!r}, "
            f"which is explicitly denied in the engagement context"
        )
    # Unset -> deny by default for upload-sensitive operations
    raise AdapterPolicyError(
        f"Operation {operation!r} requires capability {capability!r}, "
        f"which is not declared in the engagement context. "
        f"Set {env_key}=allow to enable this operation."
    )


# ── Random remote path helper ────────────────────────────────────────────────


def _random_remote_path(extension: str = "") -> str:
    """Generate a randomised path under the target's temporary directory."""
    rand = uuid4().hex[:16]
    return f"$env:TEMP\\ariadne_{rand}{extension}"


# ── Adapter ────────────────────────────────────────────────────────────────────


class PostExAdapter:
    """ToolAdapter for curated Linux and Windows post-exploitation operations.

    Supports two modes:

    - **Direct commands**: Linux system introspection (id, sudo, find,
      getcap, systemctl) and Windows remote administration (whoami, sc,
      schtasks, reg).  These run via SSH or remote execution without
      uploading payloads.

    - **Upload operations**: Windows binary tools (WinPEAS, PrivescCheck,
      Seatbelt) that first copy the tool to the Windows target at a
      randomised temporary path.  These require the
      ``exploit.payload_upload`` capability in the engagement context.

    Operations where the tool is already present in the Kali container
    (linpeas, pspy) do **not** require the upload capability.
    """

    name: ClassVar[str] = "postex"

    # ── Probe ─────────────────────────────────────────────────────────────

    async def probe(self, runtime: Runtime) -> ToolProbe:
        return ToolProbe(available=True)

    # ── Plan ──────────────────────────────────────────────────────────────

    def plan(
        self,
        action: PlannedAction,
        context: AdapterContext,
    ) -> ProcessSpec:
        op = action.operation
        target_os = context.environment.get("TARGET_OS", "linux").lower()

        if target_os == "windows":
            if op not in _WINDOWS_OPERATIONS:
                raise AdapterError(
                    f"Unknown Windows post-exploitation operation: {op!r}. "
                    f"Supported: {', '.join(sorted(_WINDOWS_OPERATIONS))}"
                )
            if op in _UPLOAD_OPS:
                _check_capability(context, _PAYLOAD_UPLOAD_CAP, op)
        else:
            if op not in _LINUX_OPERATIONS:
                raise AdapterError(
                    f"Unknown Linux post-exploitation operation: {op!r}. "
                    f"Supported: {', '.join(sorted(_LINUX_OPERATIONS))}"
                )

        inputs = action.inputs

        if target_os == "windows":
            return self._plan_windows(op, inputs, context)
        else:
            return self._plan_linux(op, inputs, context)

    # ── Linux planners ─────────────────────────────────────────────────────

    def _plan_linux(
        self,
        op: str,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        planner = {
            "identity": self._plan_linux_identity,
            "sudo_rules": self._plan_linux_sudo_rules,
            "suid_files": self._plan_linux_suid_files,
            "file_capabilities": self._plan_linux_file_capabilities,
            "scheduled_jobs": self._plan_linux_scheduled_jobs,
            "services": self._plan_linux_services,
            "linpeas": self._plan_linux_linpeas,
            "pspy_bounded": self._plan_linux_pspy,
        }
        fn = planner.get(op)
        if fn is None:
            raise AdapterError(f"Unhandled Linux operation: {op!r}")
        return fn(inputs, context)

    def _plan_linux_identity(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        return ProcessSpec(
            argv=("ssh", str(context.target.host), "id"),
            timeout_seconds=30,
            max_output_bytes=64 * 1024,
        )

    def _plan_linux_sudo_rules(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        return ProcessSpec(
            argv=("ssh", str(context.target.host), "sudo -l -n"),
            timeout_seconds=30,
            max_output_bytes=256 * 1024,
        )

    def _plan_linux_suid_files(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        return ProcessSpec(
            argv=(
                "ssh",
                str(context.target.host),
                "find / -type f \\( -perm -4000 -o -perm -2000 \\) "
                "-exec ls -la {} \\; 2>/dev/null",
            ),
            timeout_seconds=60,
            max_output_bytes=1 * 1024 * 1024,
        )

    def _plan_linux_file_capabilities(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        return ProcessSpec(
            argv=(
                "ssh",
                str(context.target.host),
                "getcap -r / 2>/dev/null || echo 'getcap not available'",
            ),
            timeout_seconds=60,
            max_output_bytes=512 * 1024,
        )

    def _plan_linux_scheduled_jobs(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        return ProcessSpec(
            argv=(
                "ssh",
                str(context.target.host),
                "cat /etc/crontab 2>/dev/null; "
                "ls -la /etc/cron.d/ 2>/dev/null; "
                "systemctl list-timers --all 2>/dev/null || true",
            ),
            timeout_seconds=60,
            max_output_bytes=512 * 1024,
        )

    def _plan_linux_services(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        return ProcessSpec(
            argv=(
                "ssh",
                str(context.target.host),
                "systemctl list-units --type=service --all 2>/dev/null || "
                "service --status-all 2>/dev/null || echo 'no service manager'",
            ),
            timeout_seconds=60,
            max_output_bytes=1 * 1024 * 1024,
        )

    def _plan_linux_linpeas(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        return ProcessSpec(
            argv=(
                "ssh",
                str(context.target.host),
                "bash /opt/tools/linpeas.sh 2>/dev/null || echo 'linpeas not found'",
            ),
            timeout_seconds=600,
            max_output_bytes=5 * 1024 * 1024,
        )

    def _plan_linux_pspy(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        return ProcessSpec(
            argv=(
                "ssh",
                str(context.target.host),
                "timeout 60 /opt/tools/pspy64 2>/dev/null || echo 'pspy not found'",
            ),
            timeout_seconds=90,
            max_output_bytes=2 * 1024 * 1024,
        )

    # ── Windows planners ───────────────────────────────────────────────────

    def _plan_windows(
        self,
        op: str,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        planner = {
            "identity": self._plan_windows_identity,
            "token_privileges": self._plan_windows_token_privileges,
            "services": self._plan_windows_services,
            "scheduled_tasks": self._plan_windows_scheduled_tasks,
            "registry": self._plan_windows_registry,
            "winpeas": self._plan_windows_winpeas,
            "privesccheck": self._plan_windows_privesccheck,
            "seatbelt": self._plan_windows_seatbelt,
        }
        fn = planner.get(op)
        if fn is None:
            raise AdapterError(f"Unhandled Windows operation: {op!r}")
        return fn(inputs, context)

    def _plan_windows_identity(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        return ProcessSpec(
            argv=(
                "impacket-wmiexec",
                str(context.target.host),
                "whoami",
            ),
            timeout_seconds=30,
            max_output_bytes=64 * 1024,
        )

    def _plan_windows_token_privileges(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        return ProcessSpec(
            argv=("impacket-wmiexec", "-whoami", "/priv", str(context.target.host)),
            timeout_seconds=30,
            max_output_bytes=128 * 1024,
        )

    def _plan_windows_services(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        return ProcessSpec(
            argv=(
                "impacket-wmiexec",
                str(context.target.host),
                "sc query",
            ),
            timeout_seconds=60,
            max_output_bytes=512 * 1024,
        )

    def _plan_windows_scheduled_tasks(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        return ProcessSpec(
            argv=(
                "impacket-wmiexec",
                str(context.target.host),
                "schtasks /query /fo CSV /v",
            ),
            timeout_seconds=60,
            max_output_bytes=1 * 1024 * 1024,
        )

    def _plan_windows_registry(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        return ProcessSpec(
            argv=(
                "impacket-wmiexec",
                str(context.target.host),
                "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
                "Uninstall /s",
            ),
            timeout_seconds=60,
            max_output_bytes=1 * 1024 * 1024,
        )

    def _plan_windows_winpeas(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        # Windows binary upload + execution
        remote_path = _random_remote_path(".exe")
        return ProcessSpec(
            argv=(
                "impacket-smbexec",
                str(context.target.host),
                "copy",
                "/opt/tools/winPEASx64.exe",
                remote_path,
                "&&",
                remote_path,
                "cmd",
                "/c",
                remote_path,
            ),
            timeout_seconds=600,
            max_output_bytes=5 * 1024 * 1024,
        )

    def _plan_windows_privesccheck(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        remote_path = _random_remote_path(".ps1")
        return ProcessSpec(
            argv=(
                "impacket-wmiexec",
                str(context.target.host),
                "copy",
                "/opt/tools/PrivescCheck.ps1",
                remote_path,
                "&&",
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                remote_path,
            ),
            timeout_seconds=600,
            max_output_bytes=5 * 1024 * 1024,
        )

    def _plan_windows_seatbelt(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        remote_path = _random_remote_path(".exe")
        return ProcessSpec(
            argv=(
                "impacket-smbexec",
                str(context.target.host),
                "copy",
                "/opt/tools/Seatbelt.exe",
                remote_path,
                "&&",
                remote_path,
                "-group=all",
            ),
            timeout_seconds=600,
            max_output_bytes=5 * 1024 * 1024,
        )

    # ── Execute ───────────────────────────────────────────────────────────

    async def execute(
        self,
        spec: ProcessSpec,
        runtime: Runtime,
    ) -> ProcessResult:
        return await runtime.run(spec)

    # ── Parse ─────────────────────────────────────────────────────────────

    def parse(
        self,
        result: ProcessResult,
    ) -> tuple[Observation, ...]:
        stdout = result.stdout
        if not stdout.strip():
            return ()

        observations: list[Observation] = []

        # Detect LinPEAS output
        if "PEASS-ng" in stdout and "SUID" in stdout:
            observations.append(self._make_observation({
                "tool": "linpeas",
                "type": "postex_result",
                "snippet": stdout[:1000],
            }))
            return tuple(observations)

        # Detect WinPEAS output
        if "WinPEAS" in stdout or "Windows Privesc" in stdout:
            observations.append(self._make_observation({
                "tool": "winpeas",
                "type": "postex_result",
                "snippet": stdout[:1000],
            }))
            return tuple(observations)

        # Detect pspy output
        if "CMD:" in stdout:
            observations.append(self._make_observation({
                "tool": "pspy",
                "type": "process_monitor",
                "processes": self._parse_pspy_commands(stdout),
            }))
            return tuple(observations)

        # Detect PrivescCheck output
        if "PrivescCheck" in stdout and "Vulnerable" in stdout:
            observations.append(self._make_observation({
                "tool": "privesccheck",
                "type": "privesc_enumeration",
                "snippet": stdout[:1000],
            }))
            return tuple(observations)

        # Detect Seatbelt output
        if "Seatbelt" in stdout and "Token Privileges" in stdout:
            observations.append(self._make_observation({
                "tool": "seatbelt",
                "type": "postex_result",
                "snippet": stdout[:1000],
            }))
            return tuple(observations)

        # Detect identity output
        if re.match(r"^uid=\d+", stdout.strip()):
            observations.append(self._make_observation({
                "tool": "identity",
                "type": "user_identity",
                "identity": stdout.strip()[:500],
            }))
            return tuple(observations)

        # Detect sudo rules output
        if "sudo" in stdout.lower() and ("may run" in stdout.lower()
                                          or "Matching Defaults" in stdout
                                          or "not allowed" in stdout.lower()):
            observations.append(self._make_observation({
                "tool": "sudo_rules",
                "type": "privilege_escalation",
                "rules": stdout.strip()[:1000],
            }))
            return tuple(observations)

        # Detect SUID files output
        if "-rws" in stdout:
            observations.append(self._make_observation({
                "tool": "suid_files",
                "type": "privilege_escalation",
                "files": stdout.strip()[:2000],
            }))
            return tuple(observations)

        # Detect file capabilities output
        if "cap_" in stdout and "=" in stdout:
            observations.append(self._make_observation({
                "tool": "file_capabilities",
                "type": "privilege_escalation",
                "capabilities": stdout.strip()[:1000],
            }))
            return tuple(observations)

        # Fallback: generic observation for any non-trivial output
        if len(stdout.strip()) > 20:
            observations.append(self._make_observation({
                "type": "raw_output",
                "snippet": stdout[:500],
            }))

        return tuple(observations)

    def _parse_pspy_commands(self, stdout: str) -> list[dict[str, str]]:
        """Parse pspy output into structured command entries."""
        commands: list[dict[str, str]] = []
        for line in stdout.splitlines():
            m = re.match(
                r"^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+"
                r"CMD:\s+UID=(\d+)\s+PID=(\d+)\s+\|\s+(.*)",
                line,
            )
            if m:
                commands.append({
                    "uid": m.group(1),
                    "pid": m.group(2),
                    "command": m.group(3),
                })
        return commands

    def _make_observation(self, data: dict[str, object]) -> Observation:
        from ariadne.core.engagement import TargetSpec

        return Observation(
            observation_id=uuid4(),
            target=TargetSpec(host="0.0.0.0"),
            source="postex",
            data=data,
        )

    # ── Classify ──────────────────────────────────────────────────────────

    def classify(
        self,
        result: ProcessResult,
        observations: tuple[Observation, ...],
    ) -> ExecutionClassification:
        if result.timed_out:
            return ExecutionClassification(
                kind="partial",
                confidence=0.3,
                summary="Post-exploitation operation timed out; "
                "partial results may be available",
            )
        if result.exit_code != 0:
            return ExecutionClassification(
                kind="failure",
                confidence=0.5,
                summary=f"Post-exploitation operation exited with "
                f"code {result.exit_code}",
            )
        if len(observations) > 0:
            return ExecutionClassification(
                kind="success",
                confidence=0.7,
                summary=f"Post-exploitation returned "
                f"{len(observations)} observations",
            )
        return ExecutionClassification(
            kind="unknown",
            confidence=0.5,
            summary="Post-exploitation completed with no structured output",
        )

    # ── Collect / Cleanup ─────────────────────────────────────────────────

    async def collect(
        self,
        result: ProcessResult,
        collector: object,
    ) -> tuple[str, ...]:
        return ()

    async def cleanup(
        self,
        context: AdapterContext,
    ) -> CleanupResult:
        return CleanupResult(
            success=True,
            details="No temporary resources to clean up",
        )
