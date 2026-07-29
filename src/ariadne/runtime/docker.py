"""Docker Compose lifecycle for the Ariadne container stack.

Manages the pinned Kali, ZAP, and netguard containers. Engines the
lifecycle contract: ``prepare`` (build + up), ``exec`` (run a command
inside a service), and ``destroy`` (teardown).

Forward-reference types
-----------------------
``RuntimeHandle``, ``ProcessLimits``, and ``ProcessResult`` are defined
here as minimal Pydantic models so that ``DockerRuntime`` can be imported
and used before Task 13 introduces the canonical bounded-runner types.
Task 13 should re-export these or alias the canonical versions.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import platform
import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import yaml

from ariadne.adapters.base import Runtime
from ariadne.core.engagement import EngagementSnapshot

# ── Canonical types (re-exported from Task 13's process module) ──────────
# These were forward references before Task 13.  Now they're defined in
# runtime/process.py and re-exported here for backward compatibility.
from ariadne.runtime.process import ProcessLimits as ProcessLimits  # noqa: F811
from ariadne.runtime.process import ProcessResult as ProcessResult  # noqa: F811
from ariadne.runtime.process import ProcessRunner, ProcessSpec


@dataclass(frozen=True)
class RuntimeHandle:
    """Opaque handle representing a running container stack instance.

    Carries enough context for ``destroy()`` to tear down the correct
    stack (Compose project name, working directory, snapshot identity).
    """

    compose_dir: Path
    project_name: str
    snapshot: EngagementSnapshot


# ── DockerRuntime ────────────────────────────────────────────────────────

_COMPOSE_DIR: Final[Path] = Path(__file__).resolve().parent.parent.parent.parent / "containers"


class DockerRuntime:
    """Lifecycle manager for the Ariadne container stack.

    Every operation delegates to ``docker compose`` in the ``containers/``
    directory using the project name ``ariadne``.
    """

    def __init__(self, compose_dir: Path = _COMPOSE_DIR) -> None:
        self._compose_dir = compose_dir.resolve(strict=True)
        self._project_name = "ariadne"
        self._env = os.environ.copy()

    def prepare(self, snapshot: EngagementSnapshot) -> RuntimeHandle:
        """Build images and start the container stack for *snapshot*.

        Passes the snapshot's confirmed target addresses as the
        ``ARIADNE_ALLOW_TARGETS`` environment variable so that netguard
        generates the correct nftables allowlist.

        Returns a ``RuntimeHandle`` that must be passed to ``destroy()``
        for clean teardown.
        """
        targets = _targets_to_allowlist(snapshot)
        self._env["ARIADNE_ALLOW_TARGETS"] = targets

        # Bring the stack up (build if needed) and wait for readiness
        self._compose("up", "--build", "--detach", "--wait")

        return RuntimeHandle(
            compose_dir=self._compose_dir,
            project_name=self._project_name,
            snapshot=snapshot,
        )

    def exec(
        self,
        service: str,
        argv: tuple[str, ...],
        limits: ProcessLimits,
    ) -> ProcessResult:
        """Execute *argv* in *service* with given *limits*.

        Runs ``docker compose exec -T <service> <argv...>``.
        """
        cmd: list[str] = ["exec", "-T", service]
        cmd.extend(argv)

        try:
            result = subprocess.run(
                self._compose_cmd(cmd),
                capture_output=True,
                text=True,
                timeout=limits.timeout_seconds,
                env=self._env,
            )
        except subprocess.TimeoutExpired as exc:
            stdout: str = ""
            stderr: str = ""
            if isinstance(exc.stdout, bytes):
                stdout = exc.stdout.decode("utf-8", errors="replace")
            elif exc.stdout is not None:
                stdout = exc.stdout
            if isinstance(exc.stderr, bytes):
                stderr = exc.stderr.decode("utf-8", errors="replace")
            elif exc.stderr is not None:
                stderr = exc.stderr
            return ProcessResult(
                exit_code=-1,
                stdout=stdout,
                stderr=stderr,
                timed_out=True,
            )

        stdout = result.stdout[: limits.max_output_bytes]
        stderr = result.stderr[: limits.max_output_bytes]

        return ProcessResult(
            exit_code=result.returncode,
            stdout=stdout,
            stderr=stderr,
        )

    def destroy(self, handle: RuntimeHandle) -> None:
        """Tear down the container stack identified by *handle*."""
        self._compose("down", "--volumes", "--remove-orphans")

    # ── Internal helpers ────────────────────────────────────────────────

    def _compose_cmd(self, args: list[str]) -> list[str]:
        return [
            "docker",
            "compose",
            "-f",
            str(self._compose_dir / "compose.yaml"),
            "-p",
            self._project_name,
            *args,
        ]

    def _compose(self, *args: str) -> None:
        cmd = self._compose_cmd(list(args))
        subprocess.run(cmd, check=True, capture_output=True, timeout=120, env=self._env)


class KaliRuntimeUnavailableError(RuntimeError):
    """Docker/Kali is required but unavailable or fails attestation."""


class LocalFirstRuntime:
    """Route each subprocess locally when available, otherwise to Kali."""

    def __init__(
        self,
        *,
        local_runtime: Runtime,
        kali_runtime: Runtime,
        kali_executables: frozenset[str],
        local_locator: Callable[[str], str | None] = shutil.which,
    ) -> None:
        self._local_runtime = local_runtime
        self._kali_runtime = kali_runtime
        self._kali_executables = kali_executables
        self._local_locator = local_locator

    async def run(self, spec: ProcessSpec) -> ProcessResult:
        executable = spec.argv[0]
        if self._local_locator(executable) is not None:
            return await self._local_runtime.run(spec)
        if executable in self._kali_executables:
            return await self._kali_runtime.run(spec)
        raise KaliRuntimeUnavailableError(
            f"{executable} is unavailable locally and absent from the curated Kali manifest."
        )

    async def inspect_tool(
        self,
        executable: str,
    ) -> tuple[str, str, str, str]:
        local_path = self._local_locator(executable)
        if local_path is not None:
            version = await self._local_runtime.run(
                ProcessSpec(
                    argv=(executable, "--version"),
                    timeout_seconds=10,
                    max_output_bytes=4096,
                )
            )
            guidance = await self._local_runtime.run(
                ProcessSpec(
                    argv=(executable, "--help"),
                    timeout_seconds=10,
                    max_output_bytes=4096,
                )
            )
            version_text = (version.stdout or version.stderr).strip()
            guidance_text = (guidance.stdout or guidance.stderr).strip()
            if not version_text or not guidance_text:
                raise KaliRuntimeUnavailableError(
                    f"Bounded local version/help inspection failed for {executable}."
                )
            return (
                local_path,
                version_text[:4096],
                guidance_text[:4096],
                "local_help",
            )
        inspect = getattr(self._kali_runtime, "inspect_tool", None)
        if not callable(inspect):
            raise KaliRuntimeUnavailableError(
                "Kali runtime does not support bounded tool inspection."
            )
        return await inspect(executable)


class OnDemandKaliRuntime:
    """Async Runtime that starts the bounded Kali service on first use only."""

    def __init__(
        self,
        *,
        snapshot: EngagementSnapshot,
        run_root: Path,
        compose_dir: Path = _COMPOSE_DIR,
        command_runtime: Runtime | None = None,
        docker_locator: Callable[[str], str | None] = shutil.which,
        kali_image_ref: str | None = None,
        netguard_image_ref: str | None = None,
    ) -> None:
        self._snapshot = snapshot
        self._run_root = run_root.resolve()
        self._compose_dir = compose_dir.resolve()
        self._command_runtime = command_runtime or ProcessRunner()
        self._docker_locator = docker_locator
        self._docker_path = "docker"
        suffix = hashlib.sha256(str(self._run_root).encode()).hexdigest()[:12]
        self._project_name = f"ariadne-{suffix}"
        self._started = False
        self._start_lock = asyncio.Lock()
        self._planned_target_ports: set[tuple[str, str]] = set()
        manifest = yaml.safe_load((self._compose_dir / "tool-manifest.yaml").read_text())
        self._curated_executables = frozenset(
            str(value)
            for value in manifest.get("executables", ())
            if isinstance(value, str) and value.strip()
        )
        nuclei = manifest.get("nuclei_templates", {})
        self._nuclei_revision = str(nuclei.get("revision", ""))
        self._nuclei_index_sha256 = str(nuclei.get("index_sha256", ""))
        self._kali_base_ref = self._platform_image_digest("kalilinux/kali-rolling")
        self._netguard_base_ref = self._platform_image_digest("alpine")
        self._kali_image_ref = (
            self._platform_image_reference("ariadne-kali")
            if kali_image_ref is None
            else kali_image_ref
        )
        self._netguard_image_ref = (
            self._platform_image_reference("ariadne-netguard")
            if netguard_image_ref is None
            else netguard_image_ref
        )

    async def run(self, spec: ProcessSpec) -> ProcessResult:
        self._bind_planned_ports(spec)
        await self._ensure_started()
        if spec.argv[0] == "nuclei":
            await self._attest_nuclei(spec)
        command = [
            *self._compose_prefix(),
            "exec",
            "-T",
            "--workdir",
            "/workspace",
        ]
        for key, value in sorted(spec.environment.items()):
            command.extend(["-e", f"{key}={value}"])
        command.extend(["kali", *spec.argv])
        return await self._command_runtime.run(
            ProcessSpec(
                argv=tuple(command),
                cwd=self._compose_dir,
                environment=self._compose_environment(),
                timeout_seconds=spec.timeout_seconds,
                max_output_bytes=spec.max_output_bytes,
                stdin=spec.stdin,
            )
        )

    async def inspect_tool(
        self,
        executable: str,
    ) -> tuple[str, str, str, str]:
        """Collect bounded version/help from the installed container tool."""
        if executable not in self._curated_executables:
            raise KaliRuntimeUnavailableError(f"{executable} is not in the curated Kali manifest.")
        await self._ensure_started()
        location = await self._container_command(("which", executable))
        version = await self._container_command((executable, "--version"))
        guidance = await self._container_command((executable, "--help"))
        location_text = location.stdout.strip()
        version_text = (version.stdout or version.stderr).strip()
        guidance_text = (guidance.stdout or guidance.stderr).strip()
        if version.exit_code != 0 or not version_text:
            version_text = await self._installed_package_version(location_text)
        guidance_is_help = (
            not guidance.timed_out
            and bool(guidance_text)
            and (
                guidance.exit_code == 0
                or (
                    guidance.exit_code in {1, 2}
                    and re.search(r"(?im)^\s*usage\s*:", guidance_text) is not None
                    and "--help" in guidance_text
                )
            )
        )
        if (
            location.exit_code != 0
            or not location_text
            or not version_text
            or not guidance_is_help
        ):
            raise KaliRuntimeUnavailableError(
                f"Bounded version/help inspection failed for {executable}."
            )
        return (
            location_text,
            version_text[:4096],
            guidance_text[:4096],
            "local_help",
        )

    async def _installed_package_version(self, executable_path: str) -> str:
        if not executable_path:
            return ""
        owner = await self._container_command(
            ("dpkg-query", "-S", executable_path)
        )
        if owner.exit_code != 0 or not owner.stdout.strip():
            return ""
        package = owner.stdout.splitlines()[0].partition(":")[0].strip()
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", package):
            return ""
        version = await self._container_command(
            ("dpkg-query", "-W", "-f=${Version}\\n", package)
        )
        if version.exit_code != 0:
            return ""
        return version.stdout.strip()

    async def _ensure_started(self) -> None:
        if self._started:
            return
        async with self._start_lock:
            if self._started:
                return
            docker = self._docker_locator("docker")
            if docker is None:
                raise KaliRuntimeUnavailableError(
                    "Docker is not installed. Ariadne will not install it "
                    "without explicit user consent."
                )
            self._docker_path = docker
            self._run_root.joinpath("workspace", "home").mkdir(
                parents=True,
                exist_ok=True,
            )
            self._run_root.joinpath("artifacts").mkdir(exist_ok=True)
            version = await self._command_runtime.run(
                ProcessSpec(
                    argv=(docker, "version", "--format", "{{.Server.Version}}"),
                    cwd=self._compose_dir,
                    timeout_seconds=15,
                    max_output_bytes=64 * 1024,
                )
            )
            if version.exit_code != 0:
                raise KaliRuntimeUnavailableError(
                    "Docker is installed but its daemon is unavailable."
                )
            startup_mode = "--build"
            pinned_refs = (self._kali_image_ref, self._netguard_image_ref)
            if any(pinned_refs) and not all(pinned_refs):
                raise KaliRuntimeUnavailableError(
                    "The pinned Ariadne Docker image set is incomplete. "
                    "Kali and netguard must be pinned together."
                )
            if self._kali_image_ref and self._netguard_image_ref:
                await self._verify_local_image(
                    docker,
                    self._kali_image_ref,
                    label="Ariadne Kali",
                )
                await self._verify_local_image(
                    docker,
                    self._netguard_image_ref,
                    label="Ariadne netguard",
                )
                startup_mode = "--no-build"
            started = await self._command_runtime.run(
                ProcessSpec(
                    argv=(
                        *self._compose_prefix(docker=docker),
                        "up",
                        startup_mode,
                        "--detach",
                        "--wait",
                        "netguard",
                        "kali",
                    ),
                    cwd=self._compose_dir,
                    environment=self._compose_environment(),
                    timeout_seconds=600,
                    max_output_bytes=2 * 1024 * 1024,
                )
            )
            if started.exit_code != 0:
                detail = (started.stderr or started.stdout).strip()
                raise KaliRuntimeUnavailableError(
                    "The pinned Kali Docker service failed to start: " + detail[:500]
                )
            self._started = True

    async def _verify_local_image(
        self,
        docker: str,
        image_ref: str,
        *,
        label: str,
    ) -> None:
        inspected = await self._command_runtime.run(
            ProcessSpec(
                argv=(
                    docker,
                    "image",
                    "inspect",
                    "--format",
                    "{{.Id}}",
                    image_ref,
                ),
                cwd=self._compose_dir,
                timeout_seconds=15,
                max_output_bytes=64 * 1024,
            )
        )
        if inspected.exit_code != 0:
            detail = (inspected.stderr or inspected.stdout).strip()
            suffix = f": {detail[:500]}" if detail else ""
            raise KaliRuntimeUnavailableError(
                f"The pinned {label} image is not available locally{suffix}. "
                "Build the curated images during setup before starting the engagement."
            )
        expected_digest = image_ref.rsplit("@sha256:", 1)[-1]
        actual_digest = inspected.stdout.strip().removeprefix("sha256:")
        if actual_digest != expected_digest:
            raise KaliRuntimeUnavailableError(
                f"The local {label} image does not match its pinned digest: "
                f"expected {expected_digest}, got {actual_digest or 'unknown'}."
            )

    async def _attest_nuclei(self, spec: ProcessSpec) -> None:
        paths = tuple(
            spec.argv[index + 1] for index, token in enumerate(spec.argv[:-1]) if token == "-t"
        )
        if not paths:
            return
        revision = await self._container_command(
            ("git", "-C", "/opt/nuclei-templates", "rev-parse", "HEAD")
        )
        if revision.exit_code != 0 or revision.stdout.strip() != self._nuclei_revision:
            raise KaliRuntimeUnavailableError(
                "Nuclei template checkout does not match the pinned index "
                f"revision {self._nuclei_revision}."
            )
        mounted_index = "/opt/ariadne-catalog/nuclei/catalog.index.json"
        index_revision = await self._container_command(("jq", "-r", ".revision", mounted_index))
        index_digest = await self._container_command(("sha256sum", mounted_index))
        if (
            index_revision.exit_code != 0
            or index_revision.stdout.strip() != self._nuclei_revision
            or index_digest.exit_code != 0
            or index_digest.stdout.split(maxsplit=1)[0] != self._nuclei_index_sha256
        ):
            raise KaliRuntimeUnavailableError(
                "Mounted Nuclei index does not match the pinned runtime checkout."
            )
        template_root = "/opt/nuclei-templates/"
        for path in paths:
            if not path.startswith(template_root):
                raise KaliRuntimeUnavailableError(
                    f"Nuclei template is outside the pinned runtime checkout: {path}"
                )
            relative_path = path.removeprefix(template_root)
            if not relative_path or ".." in Path(relative_path).parts:
                raise KaliRuntimeUnavailableError(
                    f"Nuclei template path is invalid: {path}"
                )
            exists = await self._container_command(("test", "-f", path))
            if exists.exit_code != 0:
                raise KaliRuntimeUnavailableError(
                    f"Pinned Nuclei template is absent from runtime: {path}"
                )
            clean = await self._container_command(
                (
                    "git",
                    "-C",
                    "/opt/nuclei-templates",
                    "diff",
                    "--quiet",
                    "HEAD",
                    "--",
                    relative_path,
                )
            )
            if clean.exit_code != 0:
                raise KaliRuntimeUnavailableError(
                    f"Pinned Nuclei template was modified in runtime: {path}"
                )

    async def _container_command(
        self,
        argv: tuple[str, ...],
    ) -> ProcessResult:
        return await self._command_runtime.run(
            ProcessSpec(
                argv=(
                    *self._compose_prefix(),
                    "exec",
                    "-T",
                    "kali",
                    *argv,
                ),
                cwd=self._compose_dir,
                environment=self._compose_environment(),
                timeout_seconds=30,
                max_output_bytes=256 * 1024,
            )
        )

    def _compose_prefix(
        self,
        *,
        docker: str | None = None,
    ) -> tuple[str, ...]:
        return (
            docker or self._docker_path,
            "compose",
            "-f",
            str(self._compose_dir / "compose.yaml"),
            "-p",
            self._project_name,
        )

    def _compose_environment(self) -> dict[str, str]:
        environment = {
            "ARIADNE_ALLOW_TARGETS": _targets_to_allowlist(
                self._snapshot,
                self._planned_target_ports,
            ),
            "ARIADNE_RUN_DIR": str(self._run_root),
            "KALI_BASE_REF": self._kali_base_ref,
            "NETGUARD_BASE_REF": self._netguard_base_ref,
            "NUCLEI_TEMPLATES_REF": self._nuclei_revision,
        }
        if self._kali_image_ref:
            environment["ARIADNE_KALI_IMAGE"] = self._kali_image_ref
        if self._netguard_image_ref:
            environment["ARIADNE_NETGUARD_IMAGE"] = self._netguard_image_ref
        return environment

    def _bind_planned_ports(self, spec: ProcessSpec) -> None:
        """Add only ports explicitly present in the authorized ProcessSpec."""
        if self._started:
            return
        target = self._snapshot.targets[0].host
        if spec.argv[0] == "nmap" and "-p" in spec.argv:
            raw = spec.argv[spec.argv.index("-p") + 1]
            for port in raw.split(","):
                if re.fullmatch(r"\d+(?:-\d+)?", port):
                    self._planned_target_ports.add((target, port))
        if spec.argv[0] == "msfconsole":
            match = re.search(r"\bset RPORT (\d{1,5})\b", spec.argv[-1])
            if match is not None and 1 <= int(match.group(1)) <= 65535:
                self._planned_target_ports.add((target, match.group(1)))

    def _platform_image_digest(self, image_name: str) -> str:
        architecture = {
            "aarch64": "arm64",
            "arm64": "arm64",
            "x86_64": "amd64",
            "amd64": "amd64",
        }.get(platform.machine().casefold())
        if architecture is None:
            raise KaliRuntimeUnavailableError(
                f"Unsupported Docker architecture: {platform.machine()}"
            )
        lock = yaml.safe_load((self._compose_dir / "image-lock.yaml").read_text())
        for image in lock.get("images", ()):
            if (
                isinstance(image, dict)
                and image.get("image") == image_name
                and image.get("platform") == f"linux/{architecture}"
            ):
                digest = str(image.get("digest", ""))
                if re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                    return digest
        raise KaliRuntimeUnavailableError(
            f"No pinned {image_name} digest for linux/{architecture}"
        )

    def _platform_image_reference(self, image_name: str) -> str | None:
        architecture = {
            "aarch64": "arm64",
            "arm64": "arm64",
            "x86_64": "amd64",
            "amd64": "amd64",
        }.get(platform.machine().casefold())
        if architecture is None:
            return None
        lock = yaml.safe_load((self._compose_dir / "image-lock.yaml").read_text())
        for image in lock.get("images", ()):
            if (
                isinstance(image, dict)
                and image.get("image") == image_name
                and image.get("platform") == f"linux/{architecture}"
            ):
                digest = str(image.get("digest", ""))
                if re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                    return f"{image_name}@{digest}"
        return None


# ── Utility ──────────────────────────────────────────────────────────────


def _targets_to_allowlist(
    snapshot: EngagementSnapshot,
    planned_ports: set[tuple[str, str]] | None = None,
) -> str:
    """Convert snapshot targets to the ``ARIADNE_ALLOW_TARGETS`` format.

    Returns a space-separated ``ip:port`` list. In v1, known ports
    are derived from common service ports; a future task can enrich
    this from the snapshot's objective or a configured port list.

    For now, each target gets: 22, 80, 443, 8080, 8443 (common initial
    recon ports).
    """
    default_ports: Final[tuple[int, ...]] = (22, 80, 443, 8080, 8443)
    entries: set[tuple[str, str]] = set(planned_ports or ())
    for target in snapshot.targets:
        for port in default_ports:
            entries.add((target.host, str(port)))
    return " ".join(f"{target}:{port}" for target, port in sorted(entries))
