"""Fail-closed contracts between durable plans and subprocess runtimes."""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, NoReturn
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict

from ariadne.adapters.base import Runtime
from ariadne.core.canonical import canonical_digest
from ariadne.core.engagement import TargetSpec
from ariadne.core.planner import Plan, PlannedAction
from ariadne.core.policy import EffectivePolicy
from ariadne.core.workflow import PlaybookLimits
from ariadne.runtime.process import ProcessResult, ProcessSpec


class ProcessAuthorizationError(RuntimeError):
    """Raised before an uncontracted or over-budget process can run."""


class AuthorizationReason(StrEnum):
    CONTRACT_MISSING = "contract_missing"
    IMPLEMENTATION_MISMATCH = "implementation_mismatch"
    ACTION_DIGEST_MISMATCH = "action_digest_mismatch"
    TOOL_DENIED = "tool_denied"
    POLICY_MISMATCH = "policy_mismatch"
    TARGET_MISMATCH = "target_mismatch"
    TEMPLATE_INVALID = "template_invalid"
    PORTS_MISMATCH = "ports_mismatch"
    ENVIRONMENT_DENIED = "environment_denied"
    CWD_DENIED = "cwd_denied"
    STDIN_DENIED = "stdin_denied"
    RATE_LIMIT = "rate_limit"
    CONCURRENCY_LIMIT = "concurrency_limit"
    ATTEMPT_LIMIT = "attempt_limit"
    TIMEOUT_LIMIT = "timeout_limit"
    OUTPUT_LIMIT = "output_limit"
    INITIAL_SPEC_MISMATCH = "initial_spec_mismatch"


class ExecutionEnvelope(BaseModel):
    """Immutable binding from one durable action to its execution boundary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    plan_id: str
    action_index: int
    action_digest: str
    adapter: str
    operation: str
    capabilities: tuple[str, ...]
    exact_target: TargetSpec
    run_root: Path
    limits: PlaybookLimits
    policy_digests: tuple[str, ...]
    action_inputs: dict[str, Any]
    normalized_ports: str | None = None

    @classmethod
    def from_plan(
        cls,
        plan: Plan,
        *,
        action_index: int,
        run_root: Path,
        policy_digests: tuple[str, ...],
    ) -> ExecutionEnvelope:
        try:
            action = plan.actions[action_index]
        except IndexError as exc:
            raise ProcessAuthorizationError(
                f"Action index {action_index} is outside the durable plan"
            ) from exc
        return cls(
            plan_id=plan.plan_id,
            action_index=action_index,
            action_digest=canonical_digest(action),
            adapter=action.adapter,
            operation=action.operation,
            capabilities=plan.capabilities,
            exact_target=plan.target,
            run_root=run_root.resolve(),
            limits=plan.limits,
            policy_digests=policy_digests,
            action_inputs=dict(action.inputs),
            normalized_ports=(
                normalize_nmap_ports(action.operation, action.inputs)
                if action.adapter == "nmap"
                else None
            ),
        )

    def verify_action(self, action: PlannedAction) -> None:
        if canonical_digest(action) != self.action_digest:
            raise ProcessAuthorizationError(AuthorizationReason.ACTION_DIGEST_MISMATCH)


class ExecutionContract(BaseModel):
    """Curated semantic contract for one adapter operation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    adapter: str
    operation: str
    executable_ids: frozenset[str]
    implementation_id: str
    allowed_environment_keys: frozenset[str] = frozenset()
    allow_stdin: bool = False
    max_rate: int
    max_concurrency: int
    max_attempts: int
    max_duration_seconds: int
    max_output_bytes: int


class ExecutionContractRegistry:
    """Composition-owned registry of curated live execution contracts."""

    def __init__(
        self,
        contracts: Mapping[tuple[str, str], ExecutionContract],
    ) -> None:
        self._contracts = MappingProxyType(dict(contracts))

    @property
    def contracts(
        self,
    ) -> MappingProxyType[tuple[str, str], ExecutionContract]:
        return self._contracts

    @classmethod
    def curated(cls) -> ExecutionContractRegistry:
        def bounded(
            adapter: str,
            operations: tuple[str, ...],
            executable_ids: frozenset[str],
            implementation_id: str,
            *,
            allow_stdin: bool = False,
            allowed_environment_keys: frozenset[str] = frozenset(),
        ) -> list[ExecutionContract]:
            return [
                ExecutionContract(
                    adapter=adapter,
                    operation=operation,
                    executable_ids=executable_ids,
                    implementation_id=implementation_id,
                    allow_stdin=allow_stdin,
                    allowed_environment_keys=allowed_environment_keys,
                    max_rate=1000,
                    max_concurrency=5,
                    max_attempts=3,
                    max_duration_seconds=14_400,
                    max_output_bytes=100_000_000,
                )
                for operation in operations
            ]

        contracts = [
            ExecutionContract(
                adapter="research",
                operation="investigate",
                executable_ids=frozenset({"ping", "searchsploit", "curl", "msfconsole"}),
                implementation_id="ariadne.adapters.research.ResearchAdapter",
                allowed_environment_keys=frozenset({"ARIADNE_RESEARCH_FINGERPRINT"}),
                max_rate=1,
                max_concurrency=1,
                max_attempts=12,
                max_duration_seconds=300,
                max_output_bytes=10_485_760,
            ),
            *[
                ExecutionContract(
                    adapter="nmap",
                    operation=operation,
                    executable_ids=frozenset({"nmap"}),
                    implementation_id="ariadne.adapters.nmap.NmapAdapter",
                    max_rate=100,
                    max_concurrency=1,
                    max_attempts=2,
                    max_duration_seconds=600,
                    max_output_bytes=20_971_520,
                )
                for operation in (
                    "tcp_discovery",
                    "service_fingerprint",
                    "udp_targeted",
                )
            ],
            *bounded(
                "httpx",
                ("scan",),
                frozenset({"httpx-toolkit"}),
                "ariadne.adapters.httpx.HttpxAdapter",
                allow_stdin=True,
            ),
            *bounded(
                "curl",
                ("fetch", "probe_references", "download"),
                frozenset({"curl"}),
                "ariadne.adapters.curl.CurlAdapter",
            ),
            *bounded(
                "katana",
                ("crawl",),
                frozenset({"katana"}),
                "ariadne.adapters.katana.KatanaAdapter",
            ),
            *bounded(
                "zap",
                ("passive_scan", "active_scan", "spider"),
                frozenset({"zaproxy"}),
                "ariadne.adapters.zap.ZapAdapter",
                allow_stdin=True,
                allowed_environment_keys=frozenset(
                    {
                        "ARIADNE_ZAP_HTTP_HOST",
                        "ARIADNE_ZAP_NETWORK_TARGET",
                    }
                ),
            ),
            *bounded(
                "nuclei",
                ("scan",),
                frozenset({"nuclei"}),
                "ariadne.adapters.nuclei.NucleiAdapter",
            ),
            *bounded(
                "metasploit",
                ("search", "info", "check", "run_module"),
                frozenset({"msfconsole"}),
                "ariadne.adapters.metasploit.MetasploitAdapter",
            ),
            *bounded(
                "pcap",
                ("extract_plaintext_credentials",),
                frozenset({"tshark"}),
                "ariadne.adapters.pcap.PcapAdapter",
            ),
            *bounded(
                "ssh",
                ("authenticate",),
                frozenset({"ssh"}),
                "ariadne.adapters.ssh.SshAdapter",
                allowed_environment_keys=frozenset(
                    {
                        "ARIADNE_SECRET_FILE",
                        "DISPLAY",
                        "SSH_ASKPASS",
                        "SSH_ASKPASS_REQUIRE",
                    }
                ),
            ),
            *bounded(
                "screenshot",
                ("capture",),
                frozenset({"chromium"}),
                "ariadne.adapters.screenshot.ScreenshotAdapter",
            ),
            *bounded(
                "postex",
                (
                    "sudo_rules",
                    "suid_files",
                    "file_capabilities",
                    "scheduled_jobs",
                    "linpeas",
                    "pspy_bounded",
                    "capability_python_proof",
                ),
                frozenset({"ssh"}),
                "ariadne.adapters.postex.PostExAdapter",
                allowed_environment_keys=frozenset(
                    {
                        "ARIADNE_SECRET_FILE",
                        "DISPLAY",
                        "SSH_ASKPASS",
                        "SSH_ASKPASS_REQUIRE",
                    }
                ),
            ),
            # The immutable action inputs select an OS-specific executable
            # for these shared operations.  Runtime policy still requires the
            # exact executable to be explicitly allowed by that capability.
            *bounded(
                "postex",
                ("identity", "services"),
                frozenset({"ssh", "impacket-wmiexec"}),
                "ariadne.adapters.postex.PostExAdapter",
                allowed_environment_keys=frozenset(
                    {
                        "ARIADNE_SECRET_FILE",
                        "DISPLAY",
                        "SSH_ASKPASS",
                        "SSH_ASKPASS_REQUIRE",
                    }
                ),
            ),
            *bounded(
                "postex",
                (
                    "token_privileges",
                    "scheduled_tasks",
                    "registry",
                    "privesccheck",
                ),
                frozenset({"impacket-wmiexec"}),
                "ariadne.adapters.postex.PostExAdapter",
            ),
            *bounded(
                "postex",
                ("winpeas", "seatbelt"),
                frozenset({"impacket-smbexec"}),
                "ariadne.adapters.postex.PostExAdapter",
            ),
            *bounded(
                "pivot",
                ("start_tunnel",),
                frozenset({"ligolo-proxy", "chisel", "ssh"}),
                "ariadne.adapters.pivot.PivotAdapter",
            ),
            *bounded(
                "pivot",
                ("add_route", "remove_route"),
                frozenset({"ip"}),
                "ariadne.adapters.pivot.PivotAdapter",
            ),
            *bounded(
                "pivot",
                ("stop_tunnel",),
                frozenset({"pkill"}),
                "ariadne.adapters.pivot.PivotAdapter",
            ),
            *bounded(
                "active_directory",
                ("domain_discovery",),
                frozenset({"impacket-lookupsid"}),
                "ariadne.adapters.active_directory.ActiveDirectoryAdapter",
            ),
            *bounded(
                "active_directory",
                ("ldap_rootdse",),
                frozenset({"ldapsearch"}),
                "ariadne.adapters.active_directory.ActiveDirectoryAdapter",
            ),
            *bounded(
                "active_directory",
                ("smb_enumeration",),
                frozenset({"smbclient"}),
                "ariadne.adapters.active_directory.ActiveDirectoryAdapter",
            ),
            *bounded(
                "active_directory",
                ("kerberos_user_validation",),
                frozenset({"impacket-GetNPUsers"}),
                "ariadne.adapters.active_directory.ActiveDirectoryAdapter",
            ),
            *bounded(
                "active_directory",
                ("password_spray",),
                frozenset({"netexec"}),
                "ariadne.adapters.active_directory.ActiveDirectoryAdapter",
            ),
            *bounded(
                "active_directory",
                ("bloodhound_collection",),
                frozenset({"bloodhound-python"}),
                "ariadne.adapters.active_directory.ActiveDirectoryAdapter",
            ),
            *bounded(
                "active_directory",
                ("certipy_find", "certipy_relay"),
                frozenset({"certipy-ad"}),
                "ariadne.adapters.active_directory.ActiveDirectoryAdapter",
            ),
            *bounded(
                "active_directory",
                ("credential_dump",),
                frozenset({"impacket-secretsdump"}),
                "ariadne.adapters.active_directory.ActiveDirectoryAdapter",
            ),
            *bounded(
                "active_directory",
                ("ntlm_poisoning",),
                frozenset({"responder"}),
                "ariadne.adapters.active_directory.ActiveDirectoryAdapter",
            ),
            *bounded(
                "active_directory",
                ("ntlm_relay",),
                frozenset({"impacket-ntlmrelayx"}),
                "ariadne.adapters.active_directory.ActiveDirectoryAdapter",
            ),
            *bounded(
                "active_directory",
                ("ticket_manipulation",),
                frozenset({"impacket-ticketer"}),
                "ariadne.adapters.active_directory.ActiveDirectoryAdapter",
            ),
            *bounded(
                "active_directory",
                ("object_modification",),
                frozenset({"bloodyad"}),
                "ariadne.adapters.active_directory.ActiveDirectoryAdapter",
            ),
        ]
        return cls({(contract.adapter, contract.operation): contract for contract in contracts})

    def get(
        self,
        adapter: str,
        operation: str,
    ) -> ExecutionContract | None:
        return self._contracts.get((adapter, operation))

    def require(self, adapter: str, operation: str) -> ExecutionContract:
        contract = self.get(adapter, operation)
        if contract is None:
            raise ProcessAuthorizationError(
                f"No curated execution contract for {adapter}:{operation}"
            )
        return contract

    def verify_adapter(
        self,
        contract: ExecutionContract,
        adapter: object,
    ) -> None:
        implementation_id = f"{type(adapter).__module__}.{type(adapter).__qualname__}"
        if implementation_id != contract.implementation_id:
            raise ProcessAuthorizationError(AuthorizationReason.IMPLEMENTATION_MISMATCH)


class ExecutionCoordinator:
    """Shared composition-owned concurrency bound across plans."""

    def __init__(self, max_concurrency: int = 1) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be positive")
        self._semaphore = asyncio.Semaphore(max_concurrency)

    @asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        async with self._semaphore:
            yield


BlockCallback = Callable[
    [AuthorizationReason, ProcessSpec | None, int],
    None,
]


class GuardedRuntime:
    """Reauthorize every adapter subprocess against one immutable envelope."""

    def __init__(
        self,
        *,
        runtime: Runtime,
        envelope: ExecutionEnvelope,
        contract: ExecutionContract,
        policy: EffectivePolicy,
        coordinator: ExecutionCoordinator | None = None,
        clock: Callable[[], float] = time.monotonic,
        on_block: BlockCallback | None = None,
    ) -> None:
        if (contract.adapter, contract.operation) != (
            envelope.adapter,
            envelope.operation,
        ):
            raise ProcessAuthorizationError("Execution contract does not match the durable action")
        self._runtime = runtime
        self._envelope = envelope
        self._contract = contract
        self._policy = policy
        self._on_block = on_block
        self._coordinator = coordinator or ExecutionCoordinator()
        self._clock = clock
        self._started_at = clock()
        self._output_bytes = 0
        self._initial_digest: str | None = None
        self._attempts = 0

    @property
    def attempts(self) -> int:
        return self._attempts

    def authorize_initial(self, spec: ProcessSpec) -> None:
        self._authorize(spec, next_attempt=1)
        self._initial_digest = canonical_digest(spec)

    async def run(self, spec: ProcessSpec) -> ProcessResult:
        if self._initial_digest is None:
            self._deny("Initial ProcessSpec was not authorized", spec)
        next_attempt = self._attempts + 1
        self._authorize(spec, next_attempt=next_attempt)
        if self._attempts == 0 and canonical_digest(spec) != self._initial_digest:
            self._deny(
                "First runtime ProcessSpec differs from the authorized initial spec",
                spec,
            )
        self._prepare_runtime_workspace(spec)
        self._attempts = next_attempt
        async with self._coordinator.slot():
            result = await self._runtime.run(spec)
        self._output_bytes += len(result.stdout.encode()) + len(result.stderr.encode())
        return result

    def _authorize(self, spec: ProcessSpec, *, next_attempt: int) -> None:
        contract = self._contract
        envelope = self._envelope
        executable = spec.argv[0]
        attempts_bound = _tight_bound(
            envelope.limits.max_attempts,
            contract.max_attempts,
        )
        if next_attempt > attempts_bound:
            self._deny(AuthorizationReason.ATTEMPT_LIMIT, spec)
        elapsed = int(self._clock() - self._started_at)
        duration_bound = _tight_bound(
            envelope.limits.max_duration_seconds,
            contract.max_duration_seconds,
        )
        output_bound = _tight_bound(
            envelope.limits.max_output_bytes,
            contract.max_output_bytes,
        )
        if elapsed >= duration_bound or spec.timeout_seconds > (duration_bound - elapsed):
            self._deny(AuthorizationReason.TIMEOUT_LIMIT, spec)
        if (
            self._output_bytes >= output_bound
            or spec.max_output_bytes > output_bound - self._output_bytes
        ):
            self._deny(AuthorizationReason.OUTPUT_LIMIT, spec)
        if executable not in contract.executable_ids:
            self._deny(
                f"Executable/tool {executable!r} is outside the exact contract",
                spec,
            )
        if envelope.policy_digests != self._policy.source_digests:
            self._deny("Policy digests differ from the execution envelope", spec)
        if not envelope.capabilities:
            self._deny("Execution envelope has no capability", spec)

        for capability in envelope.capabilities:
            rule = self._policy.capabilities.get(capability)
            if rule is None or not rule.allowed:
                self._deny(
                    f"Capability {capability!r} is not allowed",
                    spec,
                )
            if not rule.allowed_tools or executable not in rule.allowed_tools:
                self._deny(
                    f"Executable/tool {executable!r} is not explicitly allowed for {capability!r}",
                    spec,
                )

        if spec.stdin is not None and not contract.allow_stdin:
            self._deny("stdin is denied by the execution contract", spec)
        unknown_env = set(spec.environment) - contract.allowed_environment_keys
        if unknown_env:
            self._deny(
                f"Unsafe environment keys: {sorted(unknown_env)}",
                spec,
            )
        if spec.cwd is not None and not _is_within(
            spec.cwd,
            envelope.run_root,
        ):
            self._deny("Process cwd escapes the engagement run root", spec)

        rate, concurrency = self._semantic_validate(spec)
        self._check_bound(
            "timeout",
            spec.timeout_seconds,
            envelope.limits.max_duration_seconds,
            contract.max_duration_seconds,
            spec,
        )
        self._check_bound(
            "output",
            spec.max_output_bytes,
            envelope.limits.max_output_bytes,
            contract.max_output_bytes,
            spec,
        )
        self._check_bound(
            "rate",
            rate,
            envelope.limits.max_rate,
            contract.max_rate,
            spec,
        )
        self._check_bound(
            "concurrency",
            concurrency,
            envelope.limits.max_concurrency,
            contract.max_concurrency,
            spec,
        )
        for capability in envelope.capabilities:
            rule = self._policy.capabilities[capability]
            for label, requested, maximum in (
                ("rate", rate, rule.max_rate),
                ("concurrency", concurrency, rule.max_concurrency),
                ("attempt", next_attempt, rule.max_attempts),
                ("timeout", spec.timeout_seconds, rule.max_duration_seconds),
                ("output", spec.max_output_bytes, rule.max_output_bytes),
            ):
                if maximum is not None and requested > maximum:
                    self._deny(
                        f"Requested {label} {requested} exceeds policy limit {maximum}",
                        spec,
                    )

    def _semantic_validate(self, spec: ProcessSpec) -> tuple[int, int]:
        if self._contract.adapter == "nmap":
            return self._validate_nmap(spec), 1
        if self._contract.adapter == "research":
            self._validate_research(spec)
            return 1, 1
        if self._contract.adapter == "httpx":
            return self._validate_httpx(spec)
        if self._contract.adapter == "curl":
            self._validate_curl(spec)
            return 1, 1
        if self._contract.adapter == "katana":
            return self._validate_katana(spec)
        if self._contract.adapter == "nuclei":
            return self._validate_nuclei(spec), 1
        if self._contract.adapter == "metasploit":
            self._validate_metasploit(spec)
            return 1, 1
        if self._contract.adapter == "zap":
            self._validate_zap(spec)
            return 1, 1
        if self._contract.adapter == "screenshot":
            self._validate_screenshot(spec)
            return 1, 1
        if self._contract.adapter == "pcap":
            self._validate_pcap(spec)
            return 1, 1
        if self._contract.adapter == "ssh":
            self._validate_ssh(spec)
            return 1, 1
        if self._contract.adapter == "postex":
            self._validate_postex(spec)
            return 1, 1
        if self._contract.adapter == "active_directory":
            self._validate_active_directory(spec)
            return 1, 1
        if self._contract.adapter == "pivot":
            self._deny("Pivot execution requires a dedicated scope boundary", spec)
        self._deny("Unsupported execution contract validator", spec)

    def _validate_httpx(self, spec: ProcessSpec) -> tuple[int, int]:
        argv = spec.argv
        http_host = self._envelope.action_inputs.get("http_host")
        expected_length = 11 if http_host is not None else 9
        if len(argv) != expected_length or argv[:2] != (
            "httpx-toolkit",
            "-p",
        ):
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        if argv[3:6] != ("-json", "-no-fallback", "-t") or argv[7] != "-timeout":
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        if not argv[2] or spec.stdin is None:
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        target = self._envelope.exact_target.host
        expected_stdin = f"https://{target}\nhttp://{target}\n".encode()
        if spec.stdin != expected_stdin:
            self._deny(AuthorizationReason.TARGET_MISMATCH, spec)
        if http_host is not None and (
            not isinstance(http_host, str) or argv[9:] != ("-H", f"Host: {http_host}")
        ):
            self._deny(AuthorizationReason.TARGET_MISMATCH, spec)
        try:
            threads = int(argv[6])
            timeout = int(argv[8])
        except (IndexError, ValueError):
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        if threads < 1 or timeout < 1:
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        return threads, 1

    def _validate_curl(self, spec: ProcessSpec) -> None:
        if self._contract.operation == "probe_references":
            self._validate_curl_probe(spec)
            return
        if self._contract.operation == "download":
            self._validate_curl_download(spec)
            return
        http_host = self._envelope.action_inputs.get("http_host")
        expected_length = 16 if http_host is not None else 14
        if (
            len(spec.argv) != expected_length
            or spec.argv[:5]
            != (
                "curl",
                "--silent",
                "--show-error",
                "--proto",
                "=http,https",
            )
            or spec.argv[5] != "--connect-timeout"
            or spec.argv[7] != "--max-time"
            or spec.argv[9] != "--max-filesize"
            or spec.argv[11] != "--compressed"
            or spec.stdin is not None
        ):
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        if http_host is None:
            if spec.argv[12] != "--url":
                self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        elif not isinstance(http_host, str) or spec.argv[12:15] != (
            "--header",
            f"Host: {http_host}",
            "--url",
        ):
            self._deny(AuthorizationReason.TARGET_MISMATCH, spec)
        self._validate_curl_numbers(
            spec.argv[6],
            spec.argv[8],
            spec.argv[10],
            max_timeout=30,
        )
        if int(spec.argv[10]) > 2 * 1024 * 1024:
            self._deny(AuthorizationReason.OUTPUT_LIMIT, spec)
        self._validate_exact_target_url(spec.argv[-1], spec)

    def _validate_curl_probe(self, spec: ProcessSpec) -> None:
        argv = spec.argv
        fixed = (
            "curl",
            "--silent",
            "--show-error",
            "--proto",
            "=http,https",
            "--connect-timeout",
        )
        if (
            argv[:6] != fixed
            or len(argv) < 17
            or argv[7] != "--max-time"
            or argv[9:13]
            != (
                "--max-filesize",
                str(2 * 1024 * 1024),
                "--write-out",
                "%{json}\\n",
            )
            or (len(argv) - 13) % 4 != 0
            or argv[13::4] != ("--output",) * len(argv[13::4])
            or argv[15::4] != ("--url",) * len(argv[15::4])
            or spec.stdin is not None
        ):
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        urls = argv[16::4]
        if not 1 <= len(urls) <= 8:
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        self._validate_curl_numbers(argv[6], argv[8], argv[10], max_timeout=30)
        allowed = (self._envelope.run_root / "probes").resolve()
        for index, (raw_output, url) in enumerate(zip(argv[14::4], urls, strict=True)):
            output = Path(raw_output).resolve()
            if (
                not output.is_relative_to(allowed)
                or re.fullmatch(
                    rf"webref_[0-9a-f]{{20}}_{index}\.body",
                    output.name,
                )
                is None
            ):
                self._deny(AuthorizationReason.CWD_DENIED, spec)
            self._validate_exact_target_url(url, spec)

    def _validate_curl_download(self, spec: ProcessSpec) -> None:
        argv = spec.argv
        if (
            len(argv) != 18
            or argv[:7]
            != (
                "curl",
                "--silent",
                "--show-error",
                "--fail",
                "--proto",
                "=http,https",
                "--connect-timeout",
            )
            or argv[8] != "--max-time"
            or argv[10] != "--max-filesize"
            or argv[12] != "--output"
            or argv[14:17] != ("--write-out", "%{json}\\n", "--url")
            or spec.stdin is not None
        ):
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        output = Path(argv[13]).resolve()
        allowed = (self._envelope.run_root / "artifacts").resolve()
        if (
            not output.is_relative_to(allowed)
            or re.fullmatch(r"web_[0-9a-f]{20}\.download", output.name) is None
        ):
            self._deny(AuthorizationReason.CWD_DENIED, spec)
        self._validate_curl_numbers(argv[7], argv[9], argv[11], max_timeout=60)
        if (
            self._envelope.limits.max_output_bytes is not None
            and int(argv[11]) > self._envelope.limits.max_output_bytes
        ):
            self._deny(AuthorizationReason.OUTPUT_LIMIT, spec)
        self._validate_exact_target_url(argv[17], spec)

    def _validate_curl_numbers(
        self,
        connect: str,
        timeout: str,
        maximum: str,
        *,
        max_timeout: int,
    ) -> None:
        try:
            connect_timeout = int(connect)
            request_timeout = int(timeout)
            max_bytes = int(maximum)
        except ValueError:
            self._deny(AuthorizationReason.TEMPLATE_INVALID, None)
        if (
            not 1 <= connect_timeout <= 10
            or not 1 <= request_timeout <= max_timeout
            or connect_timeout > request_timeout
            or not 1 <= max_bytes <= 10 * 1024 * 1024
        ):
            self._deny(AuthorizationReason.TEMPLATE_INVALID, None)

    def _validate_exact_target_url(self, value: str, spec: ProcessSpec) -> None:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname != self._envelope.exact_target.host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            self._deny(AuthorizationReason.TARGET_MISMATCH, spec)

    def _validate_katana(self, spec: ProcessSpec) -> tuple[int, int]:
        argv = spec.argv
        fixed_flags = {
            "-jc",
            "-fx",
            "-xhr",
            "-iqp",
            "-jsonl",
            "-omit-raw",
            "-omit-body",
            "-silent",
            "-duc",
        }
        valued_flags = {
            "-u",
            "-d",
            "-ct",
            "-mdp",
            "-c",
            "-p",
            "-rl",
            "-timeout",
            "-retry",
            "-cs",
            "-kf",
        }
        http_host = self._envelope.action_inputs.get("http_host")
        if http_host is not None:
            valued_flags.add("-H")
        if not argv or argv[0] != "katana" or spec.stdin is not None:
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        parsed: dict[str, str] = {}
        switches: set[str] = set()
        index = 1
        while index < len(argv):
            flag = argv[index]
            if flag in fixed_flags:
                switches.add(flag)
                index += 1
                continue
            if flag not in valued_flags or index + 1 >= len(argv):
                self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
            parsed[flag] = argv[index + 1]
            index += 2
        if set(parsed) != valued_flags or switches != fixed_flags:
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)

        target = self._envelope.exact_target.host
        expected_scope = (
            rf"^https?://{re.escape(target)}"
            r"(?::[0-9]+)?(?:/|$)"
        )
        seeds = parsed["-u"].split(",")
        if not 1 <= len(seeds) <= 10:
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        for seed in seeds:
            parsed_seed = urlsplit(seed)
            if (
                parsed_seed.scheme not in {"http", "https"}
                or parsed_seed.hostname != target
                or parsed_seed.username is not None
                or parsed_seed.password is not None
                or parsed_seed.fragment
            ):
                self._deny(AuthorizationReason.TARGET_MISMATCH, spec)
        try:
            depth = int(parsed["-d"])
            duration = int(parsed["-ct"].removesuffix("s"))
            max_pages = int(parsed["-mdp"])
            concurrency = int(parsed["-c"])
            parallelism = int(parsed["-p"])
            rate = int(parsed["-rl"])
            timeout = int(parsed["-timeout"])
            retries = int(parsed["-retry"])
        except ValueError:
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        if (
            not 1 <= depth <= 5
            or not 5 <= duration <= 300
            or not 1 <= max_pages <= 500
            or not 1 <= concurrency <= 4
            or parallelism != 1
            or not 1 <= rate <= 20
            or not 1 <= timeout <= 30
            or retries != 1
            or parsed["-cs"] != expected_scope
            or parsed["-kf"] != "all"
            or (
                http_host is not None
                and (not isinstance(http_host, str) or parsed["-H"] != f"Host: {http_host}")
            )
        ):
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        return rate, concurrency

    def _validate_nuclei(self, spec: ProcessSpec) -> int:
        argv = spec.argv
        target = self._envelope.exact_target.host
        if len(argv) < 11 or argv[:2] != ("nuclei", "-t"):
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        target_index = argv.index("-target") if "-target" in argv else -1
        template_args = argv[1:target_index]
        template_paths = template_args[1::2]
        http_host = self._envelope.action_inputs.get("http_host")
        if http_host is not None and not isinstance(http_host, str):
            self._deny(AuthorizationReason.TARGET_MISMATCH, spec)
        header_args = ("-H", f"Host: {http_host}") if isinstance(http_host, str) else ()
        json_index = target_index + 2 + len(header_args)
        if (
            target_index <= 2
            or argv.count("-target") != 1
            or len(template_args) % 2 != 0
            or template_args[::2] != ("-t",) * len(template_paths)
            or not 1 <= len(template_paths) <= 20
            or any(
                not path.startswith("/opt/nuclei-templates/")
                or not path.endswith(".yaml")
                or ".." in Path(path).parts
                for path in template_paths
            )
            or argv[target_index + 1 : json_index] != (target, *header_args)
            or argv[json_index] != "-json"
            or argv[json_index + 1] != "-rate-limit"
            or argv[json_index + 3] != "-timeout"
            or json_index + 5 != len(argv)
        ):
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        if argv[target_index + 1] != target:
            self._deny(AuthorizationReason.TARGET_MISMATCH, spec)
        try:
            rate = int(argv[json_index + 2])
            timeout = int(argv[json_index + 4])
        except (IndexError, ValueError):
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        if rate < 1 or timeout < 1:
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        return rate

    def _validate_zap(self, spec: ProcessSpec) -> None:
        if (
            spec.argv
            != ("zaproxy", "-cmd", "-silent", "-autorun", "/dev/stdin")
            or spec.stdin is None
        ):
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        try:
            automation = yaml.safe_load(spec.stdin)
            if not isinstance(automation, dict) or set(automation) != {"env", "jobs"}:
                self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
            env = automation["env"]
            if not isinstance(env, dict) or set(env) != {"contexts"}:
                self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
            contexts = env["contexts"]
            jobs = automation["jobs"]
        except (KeyError, TypeError, yaml.YAMLError, IndexError):
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        urls = contexts[0].get("urls") if contexts and isinstance(contexts[0], dict) else None
        if not isinstance(urls, list) or len(urls) != 1 or not isinstance(urls[0], str):
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        target = self._envelope.exact_target.host
        seed_url = self._envelope.action_inputs.get("url", f"https://{target}")
        if not isinstance(seed_url, str):
            self._deny(AuthorizationReason.TARGET_MISMATCH, spec)
        parsed_seed = urlsplit(seed_url)
        if (
            parsed_seed.scheme not in {"http", "https"}
            or parsed_seed.hostname != target
            or parsed_seed.username is not None
            or parsed_seed.password is not None
            or parsed_seed.fragment
        ):
            self._deny(AuthorizationReason.TARGET_MISMATCH, spec)
        http_host = self._envelope.action_inputs.get("http_host")
        if http_host is not None and not isinstance(http_host, str):
            self._deny(AuthorizationReason.TARGET_MISMATCH, spec)
        try:
            port = parsed_seed.port
        except ValueError:
            self._deny(AuthorizationReason.TARGET_MISMATCH, spec)
        scan_host = http_host if isinstance(http_host, str) else target
        scan_netloc = f"{scan_host}:{port}" if port is not None else scan_host
        target_url = f"{parsed_seed.scheme}://{scan_netloc}"
        parsed_target = urlsplit(urls[0])
        if (
            parsed_target.scheme != parsed_seed.scheme
            or parsed_target.hostname != scan_host
            or parsed_target.port != port
            or parsed_target.username is not None
            or parsed_target.password is not None
            or parsed_target.fragment
            or parsed_target.path not in {"", "/"}
            or parsed_target.query
        ):
            self._deny(AuthorizationReason.TARGET_MISMATCH, spec)
        include_path = f"{re.escape(target_url.rstrip('/'))}/.*"
        expected_context = {
            "name": "ariadne",
            "urls": [target_url],
            "includePaths": [include_path],
            "excludePaths": [],
        }
        if contexts != [expected_context]:
            self._deny(AuthorizationReason.TARGET_MISMATCH, spec)
        if not isinstance(jobs, list):
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        operation = self._contract.operation
        expected_environment = (
            {
                "ARIADNE_ZAP_HTTP_HOST": http_host,
                "ARIADNE_ZAP_NETWORK_TARGET": target,
            }
            if isinstance(http_host, str)
            else {}
        )
        if dict(spec.environment) != expected_environment:
            self._deny(AuthorizationReason.TARGET_MISMATCH, spec)
        scan_jobs = jobs
        expected_types = {
            "passive_scan": ["passiveScan-config", "spider"],
            "spider": ["passiveScan-config", "spider"],
            "active_scan": ["passiveScan-config", "spider", "activeScan"],
        }[operation]
        if [job.get("type") for job in scan_jobs if isinstance(job, dict)] != expected_types:
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        if len(scan_jobs) != len(expected_types):
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        for job, job_type in zip(scan_jobs, expected_types, strict=True):
            if not isinstance(job, dict) or set(job) != {"type", "parameters"}:
                self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
            parameters = job["parameters"]
            if not isinstance(parameters, dict):
                self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
            if job_type == "passiveScan-config":
                valid = parameters == {"maxAlertsPerRule": 10}
            elif job_type == "spider":
                valid = (
                    set(parameters) == {"maxDepth", "maxDuration"}
                    and _positive_int(parameters["maxDepth"], maximum=20)
                    and _positive_int(parameters["maxDuration"], maximum=60)
                )
            else:
                valid = set(parameters) == {"maxDuration"} and _positive_int(
                    parameters["maxDuration"], maximum=120
                )
            if not valid:
                self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)

    def _validate_metasploit(self, spec: ProcessSpec) -> None:
        if len(spec.argv) != 4 or spec.argv[:3] != ("msfconsole", "-q", "-x"):
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        commands = tuple(command.strip() for command in spec.argv[3].split(";") if command.strip())
        operation = self._contract.operation
        module_re = re.compile(r"^(?:exploit|auxiliary)/[a-z][a-z0-9_/]*[a-z0-9_]$")
        if operation == "search":
            valid = (
                len(commands) == 2
                and commands[0].startswith("search ")
                and commands[1] == "exit"
                and self._envelope.exact_target.host not in commands[0]
            )
        elif operation == "info":
            valid = (
                len(commands) == 2
                and commands[0].startswith("info ")
                and module_re.fullmatch(commands[0].removeprefix("info ")) is not None
                and commands[1] == "exit"
            )
        else:
            expected_terminal = "check" if operation == "check" else "run"
            valid = (
                len(commands) >= 4
                and commands[0].startswith("use ")
                and module_re.fullmatch(commands[0].removeprefix("use ")) is not None
                and commands[1] == f"set RHOSTS {self._envelope.exact_target.host}"
                and commands[-2:] == (expected_terminal, "exit")
            )
            for command in commands[2:-2]:
                if command.startswith("set RPORT "):
                    value = command.removeprefix("set RPORT ")
                    valid = valid and value.isdigit() and 1 <= int(value) <= 65535
                elif operation == "run_module" and command.startswith(
                    ("set PAYLOAD ", "set LHOST ")
                ):
                    value = command.split(" ", 2)[-1]
                    valid = (
                        valid
                        and bool(value)
                        and not re.search(
                            r"[;\r\n]",
                            value,
                        )
                    )
                else:
                    valid = False
        if not valid:
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)

    def _validate_screenshot(self, spec: ProcessSpec) -> None:
        target = self._envelope.exact_target.host
        output = next((item for item in spec.argv if item.startswith("--screenshot=")), "")
        profile = next((item for item in spec.argv if item.startswith("--user-data-dir=")), "")
        allowed = (self._envelope.run_root / "artifacts" / "screenshots").resolve()
        expected_prefix = (
            "chromium",
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--window-size=1280,720",
        )
        urls = {f"https://{target}", f"http://{target}"}
        if (
            not output
            or not profile
            or len(spec.argv) != 11
            or spec.argv[:6] != expected_prefix
            or spec.argv[6] != profile
            or spec.argv[7] != output
            or spec.argv[-1] not in urls
            or spec.argv[-3] != "--hide-scrollbars"
            or not spec.argv[-2].startswith("--virtual-time-budget=")
            or not Path(output.removeprefix("--screenshot=")).resolve().is_relative_to(allowed)
            or not Path(profile.removeprefix("--user-data-dir=")).resolve().is_relative_to(allowed)
        ):
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        try:
            budget = int(spec.argv[-2].removeprefix("--virtual-time-budget="))
        except ValueError:
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        if budget < 1:
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)

    def _validate_pcap(self, spec: ProcessSpec) -> None:
        from ariadne.adapters.pcap import _PCAP_FILTER

        artifact_name = self._envelope.action_inputs.get("artifact")
        expected_digest = self._envelope.action_inputs.get("sha256")
        if (
            not isinstance(artifact_name, str)
            or Path(artifact_name).name != artifact_name
            or not isinstance(expected_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None
        ):
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        expected_artifact = (self._envelope.run_root / "artifacts" / artifact_name).resolve()
        expected = (
            "tshark",
            "-r",
            str(expected_artifact),
            "-Y",
            _PCAP_FILTER,
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-E",
            "quote=d",
            "-E",
            "occurrence=f",
            "-e",
            "ftp.request.command",
            "-e",
            "ftp.request.arg",
            "-e",
            "http.authorization",
        )
        if (
            spec.argv != expected
            or spec.stdin is not None
            or not expected_artifact.is_file()
            or hashlib.sha256(expected_artifact.read_bytes()).hexdigest() != expected_digest
        ):
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)

    def _validate_ssh(self, spec: ProcessSpec) -> None:
        from ariadne.adapters.ssh import SSH_FOOTHOLD_COMMAND

        self._validate_credential_ssh(spec, SSH_FOOTHOLD_COMMAND)

    def _validate_credential_ssh(
        self,
        spec: ProcessSpec,
        remote_command: str,
    ) -> None:
        argv = spec.argv
        target = self._envelope.exact_target.host
        if (
            len(argv) != 16
            or argv[:8]
            != (
                "ssh",
                "-o",
                "BatchMode=no",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
            )
            or not argv[8].startswith("UserKnownHostsFile=")
            or argv[9:12] != ("-o", "ConnectTimeout=10", "-p")
            or argv[13] != "--"
            or argv[15] != remote_command
            or spec.stdin is not None
        ):
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        try:
            port = int(argv[12])
        except ValueError:
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        if not 1 <= port <= 65535:
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        destination = argv[14]
        username, separator, host = destination.rpartition("@")
        action_inputs = self._envelope.action_inputs
        expected_username = action_inputs.get("username")
        expected_ref = action_inputs.get("credential_ref")
        expected_port = action_inputs.get("port", 22)
        if (
            separator != "@"
            or host != target
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", username) is None
            or username != expected_username
            or port != expected_port
            or not isinstance(expected_ref, str)
            or not expected_ref
        ):
            self._deny(AuthorizationReason.TARGET_MISMATCH, spec)
        run_root = self._envelope.run_root.resolve()
        workspace = (run_root / "workspace").resolve()
        secrets = (run_root / "secrets").resolve()
        known_hosts = Path(argv[8].removeprefix("UserKnownHostsFile=")).resolve()
        helper = Path(str(spec.environment.get("SSH_ASKPASS", ""))).resolve()
        secret = Path(str(spec.environment.get("ARIADNE_SECRET_FILE", ""))).resolve()
        expected_helper = Path(__file__).resolve().parents[1] / "runtime" / "ssh_askpass.py"
        expected_secret = (run_root / expected_ref).resolve()
        if (
            set(spec.environment)
            != {
                "ARIADNE_SECRET_FILE",
                "DISPLAY",
                "SSH_ASKPASS",
                "SSH_ASKPASS_REQUIRE",
            }
            or spec.environment.get("DISPLAY") != "ariadne:0"
            or spec.environment.get("SSH_ASKPASS_REQUIRE") != "force"
            or spec.cwd is None
            or spec.cwd.resolve() != workspace
            or known_hosts != workspace / "known_hosts"
            or helper != workspace / "ariadne_ssh_askpass.py"
            or not helper.is_file()
            or helper.stat().st_mode & 0o077
            or helper.read_bytes() != expected_helper.read_bytes()
            or secret != expected_secret
            or not expected_secret.is_relative_to(secrets)
            or not secret.is_file()
            or secret.stat().st_mode & 0o077
        ):
            self._deny(AuthorizationReason.ENVIRONMENT_DENIED, spec)

    def _validate_postex(self, spec: ProcessSpec) -> None:
        target = self._envelope.exact_target.host
        operation = self._contract.operation
        linux_commands = {
            "identity": "id",
            "sudo_rules": "sudo -l -n",
            "suid_files": (
                "find / -type f \\( -perm -4000 -o -perm -2000 \\) -exec ls -la {} \\; 2>/dev/null"
            ),
            "file_capabilities": ("getcap -r / 2>/dev/null || echo 'getcap not available'"),
            "scheduled_jobs": (
                "cat /etc/crontab 2>/dev/null; "
                "ls -la /etc/cron.d/ 2>/dev/null; "
                "systemctl list-timers --all 2>/dev/null || true"
            ),
            "services": (
                "systemctl list-units --type=service --all 2>/dev/null || "
                "service --status-all 2>/dev/null || echo 'no service manager'"
            ),
            "linpeas": ("bash /opt/tools/linpeas.sh 2>/dev/null || echo 'linpeas not found'"),
            "pspy_bounded": ("timeout 60 /opt/tools/pspy64 2>/dev/null || echo 'pspy not found'"),
        }
        if spec.argv[0] == "ssh":
            if spec.environment:
                if operation == "capability_python_proof":
                    from ariadne.adapters.postex import (
                        python_capability_proof_command,
                    )

                    remote = spec.argv[-1]
                    interpreter = remote.split(" ", 1)[0]
                    if (
                        interpreter != self._envelope.action_inputs.get("interpreter")
                        or re.fullmatch(
                            r"/(?:usr/(?:local/)?)?bin/python(?:3(?:\.\d+)?)?",
                            interpreter,
                        )
                        is None
                    ):
                        self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
                    self._validate_credential_ssh(
                        spec,
                        python_capability_proof_command(interpreter),
                    )
                    return
                expected = linux_commands.get(operation)
                if expected is None:
                    self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
                self._validate_credential_ssh(spec, expected)
                return
            if spec.argv != ("ssh", target, linux_commands.get(operation, "")):
                self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
            return
        windows_commands = {
            "identity": ("impacket-wmiexec", target, "whoami"),
            "token_privileges": (
                "impacket-wmiexec",
                "-whoami",
                "/priv",
                target,
            ),
            "services": ("impacket-wmiexec", target, "sc query"),
            "scheduled_tasks": (
                "impacket-wmiexec",
                target,
                "schtasks /query /fo CSV /v",
            ),
            "registry": (
                "impacket-wmiexec",
                target,
                ("reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall /s"),
            ),
        }
        if operation in windows_commands:
            if spec.argv != windows_commands[operation]:
                self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
            return
        self._validate_postex_upload(spec, target, operation)

    def _validate_postex_upload(
        self,
        spec: ProcessSpec,
        target: str,
        operation: str,
    ) -> None:
        expected = {
            "winpeas": (
                "impacket-smbexec",
                "/opt/tools/winPEASx64.exe",
                ".exe",
                ("&&", "cmd", "/c"),
            ),
            "privesccheck": (
                "impacket-wmiexec",
                "/opt/tools/PrivescCheck.ps1",
                ".ps1",
                ("&&", "powershell", "-ExecutionPolicy", "Bypass", "-File"),
            ),
            "seatbelt": (
                "impacket-smbexec",
                "/opt/tools/Seatbelt.exe",
                ".exe",
                ("&&",),
            ),
        }.get(operation)
        if expected is None:
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        executable, local_path, extension, middle = expected
        if len(spec.argv) < 6:
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        remote = spec.argv[4]
        if not re.fullmatch(
            rf"\$env:TEMP\\ariadne_[0-9a-f]{{16}}{re.escape(extension)}",
            remote,
        ):
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        if spec.argv[:4] != (executable, target, "copy", local_path):
            self._deny(AuthorizationReason.TARGET_MISMATCH, spec)
        expected_argv = (
            (executable, target, "copy", local_path, remote)
            + middle
            + ((remote, "-group=all") if operation == "seatbelt" else (remote,))
        )
        if spec.argv != expected_argv:
            self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)

    def _validate_active_directory(self, spec: ProcessSpec) -> None:
        if spec.argv[0] == "responder":
            self._deny("Responder requires an explicit interface boundary", spec)
        target = self._envelope.exact_target.host
        operation = self._contract.operation
        argv = spec.argv
        valid = False
        if operation == "domain_discovery":
            valid = argv == ("impacket-lookupsid", "-no-pass", target, "500")
        elif operation == "ldap_rootdse":
            valid = argv == (
                "ldapsearch",
                "-H",
                f"ldap://{target}",
                "-x",
                "-s",
                "base",
                "-b",
                "",
                "objectClass=*",
            )
        elif operation == "smb_enumeration":
            valid = argv == ("smbclient", "-L", f"//{target}/", "-N")
        elif operation == "kerberos_user_validation":
            valid = (
                len(argv) == 7
                and argv[:3] == ("impacket-GetNPUsers", "-no-pass", "-dc-ip")
                and argv[3] == target
                and argv[4] == "-usersfile"
                and bool(argv[5])
                and argv[6].endswith("/")
                and len(argv[6]) > 1
            )
        elif operation == "bloodhound_collection":
            valid = (
                len(argv) == 8
                and argv[0] == "bloodhound-python"
                and argv[1] == "-d"
                and bool(argv[2])
                and argv[3:] == ("-dc", target, "-ns", target, "--zip")
            )
        elif operation == "certipy_find":
            valid = (
                len(argv) == 10
                and argv[:2] == ("certipy-ad", "find")
                and argv[2] == "-u"
                and argv[4] == "-p"
                and argv[6:9] == ("-dc-ip", target, "-target")
                and bool(argv[9])
            )
        elif operation == "password_spray":
            valid = (
                len(argv) == 10
                and argv[:3] == ("netexec", "smb", target)
                and argv[3] == "-d"
                and bool(argv[4])
                and argv[5] == "-u"
                and bool(argv[6])
                and argv[7] == "-p"
                and argv[9] == "--continue-on-success"
            )
        elif operation == "credential_dump":
            valid = argv == ("impacket-secretsdump", target)
        elif operation == "ntlm_relay":
            valid = argv == ("impacket-ntlmrelayx", "-t", f"smb://{target}")
        elif operation == "ticket_manipulation":
            valid = (
                len(argv) == 9
                and argv[0:2] == ("impacket-ticketer", "-nthash")
                and argv[3] == "-domain"
                and bool(argv[4])
                and argv[5] == "-user"
                and bool(argv[6])
                and argv[7:9] == ("-dc-ip", target)
            )
        elif operation == "object_modification":
            valid = (
                len(argv) == 11
                and argv[:3] == ("bloodyad", "-d", target)
                and argv[3] == "-u"
                and argv[5] == "-p"
                and argv[7] == "--target"
                and argv[9] == "--action"
            )
        elif operation == "certipy_relay":
            valid = (
                len(argv) == 12
                and argv[:2] == ("certipy-ad", "req")
                and argv[2] == "-u"
                and argv[4] == "-p"
                and argv[6] == "-ca"
                and argv[8] == "-template"
                and argv[10:12] == ("-dc-ip", target)
            )
        if not valid:
            reason = (
                AuthorizationReason.TARGET_MISMATCH
                if target not in " ".join(argv)
                else AuthorizationReason.TEMPLATE_INVALID
            )
            self._deny(reason, spec)

    def _prepare_runtime_workspace(self, spec: ProcessSpec) -> None:
        """Create only an already-authorized adapter's narrow output directory."""
        if self._contract.adapter != "screenshot":
            return
        output = next(
            item.removeprefix("--screenshot=")
            for item in spec.argv
            if item.startswith("--screenshot=")
        )
        Path(output).parent.mkdir(parents=True, exist_ok=True)

    def _validate_nmap(self, spec: ProcessSpec) -> int:
        argv = spec.argv
        target = self._envelope.exact_target.host
        if len(argv) < 2 or argv[-2:] != ("--", target):
            self._deny(
                "Nmap template must end with the exact target after --",
                spec,
            )
        if argv.count(target) != 1:
            self._deny("Nmap target must appear exactly once", spec)
        if argv[1:3] != ("-n", "-Pn"):
            self._deny("Nmap template is missing fixed safe flags", spec)
        for required in ("--max-rate", "-p", "-oX", "--"):
            if argv.count(required) != 1:
                self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
        if "-oX" not in argv:
            self._deny("Nmap XML stdout output is required", spec)
        output_index = argv.index("-oX")
        if output_index + 1 >= len(argv) or argv[output_index + 1] != "-":
            self._deny("Nmap output must be XML on stdout", spec)
        if "--max-rate" not in argv:
            self._deny("Nmap max-rate is required", spec)
        rate_index = argv.index("--max-rate")
        try:
            rate = int(argv[rate_index + 1])
        except (IndexError, ValueError):
            self._deny("Nmap max-rate must be an integer", spec)
        if rate < 1:
            self._deny("Nmap max-rate must be positive", spec)
        port_index = argv.index("-p")
        if port_index + 1 >= len(argv) or argv[port_index + 1] != self._envelope.normalized_ports:
            self._deny(AuthorizationReason.PORTS_MISMATCH, spec)

        scan_flags = set(argv) & {"-sS", "-sT", "-sU"}
        scan_flag_count = sum(argv.count(flag) for flag in ("-sS", "-sT", "-sU"))
        operation = self._contract.operation
        if operation == "udp_targeted":
            expected_scan = scan_flag_count == 1 and scan_flags == {"-sU"} and "-sV" not in argv
        elif operation == "service_fingerprint":
            expected_scan = scan_flag_count == 1 and scan_flags <= {"-sS", "-sT"} and "-sV" in argv
        else:
            expected_scan = (
                scan_flag_count == 1 and scan_flags <= {"-sS", "-sT"} and "-sV" not in argv
            )
        if not expected_scan:
            self._deny("Nmap scan flags do not match the operation", spec)

        allowed_flags = {
            "-n",
            "-Pn",
            "-sS",
            "-sT",
            "-sU",
            "-sV",
            "--max-rate",
            "-p",
            "-oX",
            "--",
        }
        value_flags = {"--max-rate", "-p", "-oX"}
        index = 1
        while index < len(argv) - 2:
            token = argv[index]
            if token not in allowed_flags:
                self._deny(
                    f"Nmap template contains extra destination or token {token!r}",
                    spec,
                )
            index += 2 if token in value_flags else 1
        if index != len(argv) - 2:
            self._deny("Nmap template has an incomplete flag/value pair", spec)
        return rate

    def _validate_research(self, spec: ProcessSpec) -> None:
        target = self._envelope.exact_target.host
        if spec.argv[0] == "ping":
            if spec.argv != ("ping", "-c", "1", "-W", "3", target):
                self._deny(
                    "Ping template must contain the exact target once",
                    spec,
                )
            return
        if spec.argv[0] == "searchsploit":
            if (
                len(spec.argv) not in {3, 4}
                or spec.argv[1] != "--json"
                or not all(part.strip() for part in spec.argv[2:])
            ):
                self._deny(
                    "Searchsploit template requires a structured product query",
                    spec,
                )
            if target in spec.argv:
                self._deny(
                    "Searchsploit query must not contain the engagement target",
                    spec,
                )
            return
        if spec.argv[0] == "curl":
            fixed = (
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "15",
            )
            if len(spec.argv) != 7 or spec.argv[:6] != fixed:
                self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
            url = urlsplit(spec.argv[-1])
            if (
                url.scheme != "https"
                or url.username is not None
                or url.password is not None
                or url.port not in {None, 443}
                or url.hostname
                not in {
                    "httpd.apache.org",
                    "nginx.org",
                    "www.openssh.com",
                    "services.nvd.nist.gov",
                    "www.cisa.gov",
                }
                or target in spec.argv[-1]
            ):
                self._deny(AuthorizationReason.TARGET_MISMATCH, spec)
            return
        if spec.argv[0] == "msfconsole":
            commands = (
                tuple(command.strip() for command in spec.argv[3].split(";") if command.strip())
                if len(spec.argv) == 4
                else ()
            )
            if (
                len(spec.argv) != 4
                or spec.argv[:3] != ("msfconsole", "-q", "-x")
                or target in spec.argv[3]
                or len(commands) != 2
                or commands[1] != "exit"
            ):
                self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
            if commands[0].startswith("search "):
                if "type:exploit" not in commands[0]:
                    self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
            elif commands[0].startswith("info "):
                module = commands[0].removeprefix("info ")
                if (
                    re.fullmatch(
                        r"(?:exploit|auxiliary)/[a-z][a-z0-9_/]*[a-z0-9_]",
                        module,
                    )
                    is None
                ):
                    self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
            else:
                self._deny(AuthorizationReason.TEMPLATE_INVALID, spec)
            return
        self._deny("Research executable is outside the contract", spec)

    def _check_bound(
        self,
        label: str,
        requested: int,
        plan_bound: int | None,
        contract_bound: int,
        spec: ProcessSpec,
    ) -> None:
        maximum = _tight_bound(plan_bound, contract_bound)
        if requested > maximum:
            self._deny(
                f"Requested {label} {requested} exceeds limit {maximum}",
                spec,
            )

    def _deny(
        self,
        reason: AuthorizationReason | str,
        spec: ProcessSpec | None,
    ) -> NoReturn:
        stable = _stable_reason(reason)
        if self._on_block is not None:
            self._on_block(stable, spec, self._attempts)
        raise ProcessAuthorizationError(stable.value)


def _tight_bound(plan_bound: int | None, contract_bound: int) -> int:
    return (
        contract_bound
        if plan_bound is None
        else min(
            plan_bound,
            contract_bound,
        )
    )


def _positive_int(value: object, *, maximum: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= maximum


def _is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def normalize_nmap_ports(
    operation: str,
    inputs: Mapping[str, Any],
) -> str:
    ports = inputs.get("ports", ())
    if not ports and operation == "service_fingerprint":
        ports = ("22,80,443,445,3389,8080,8443",)
    if not ports:
        raise ProcessAuthorizationError(AuthorizationReason.PORTS_MISMATCH)
    if isinstance(ports, str):
        raw_port_str = ports
    elif isinstance(ports, (list, tuple)):
        if any(isinstance(port, bool) or not isinstance(port, (int, str)) for port in ports):
            raise ProcessAuthorizationError(AuthorizationReason.PORTS_MISMATCH)
        raw_port_str = ",".join(str(port) for port in ports)
    else:
        raise ProcessAuthorizationError(AuthorizationReason.PORTS_MISMATCH)

    normalized: list[str] = []
    for token in raw_port_str.split(","):
        if not token or token != token.strip():
            raise ProcessAuthorizationError(AuthorizationReason.PORTS_MISMATCH)
        bounds = token.split("-")
        if len(bounds) == 1:
            if not bounds[0].isdigit():
                raise ProcessAuthorizationError(AuthorizationReason.PORTS_MISMATCH)
            port = int(bounds[0])
            if not 1 <= port <= 65535:
                raise ProcessAuthorizationError(AuthorizationReason.PORTS_MISMATCH)
            normalized.append(str(port))
            continue
        if len(bounds) != 2 or not all(bound.isdigit() for bound in bounds):
            raise ProcessAuthorizationError(AuthorizationReason.PORTS_MISMATCH)
        low, high = (int(bound) for bound in bounds)
        if not 1 <= low <= high <= 65535:
            raise ProcessAuthorizationError(AuthorizationReason.PORTS_MISMATCH)
        capped_high = min(high, low + 199)
        normalized.append(f"{low}-{capped_high}")
    return ",".join(normalized)


def _stable_reason(
    reason: AuthorizationReason | str,
) -> AuthorizationReason:
    if isinstance(reason, AuthorizationReason):
        return reason
    lowered = reason.lower()
    for needle, code in (
        ("implementation", AuthorizationReason.IMPLEMENTATION_MISMATCH),
        ("tool", AuthorizationReason.TOOL_DENIED),
        ("digest", AuthorizationReason.ACTION_DIGEST_MISMATCH),
        ("target", AuthorizationReason.TARGET_MISMATCH),
        ("port", AuthorizationReason.PORTS_MISMATCH),
        ("environment", AuthorizationReason.ENVIRONMENT_DENIED),
        ("cwd", AuthorizationReason.CWD_DENIED),
        ("stdin", AuthorizationReason.STDIN_DENIED),
        ("rate", AuthorizationReason.RATE_LIMIT),
        ("concurrency", AuthorizationReason.CONCURRENCY_LIMIT),
        ("attempt", AuthorizationReason.ATTEMPT_LIMIT),
        ("timeout", AuthorizationReason.TIMEOUT_LIMIT),
        ("output", AuthorizationReason.OUTPUT_LIMIT),
        ("policy", AuthorizationReason.POLICY_MISMATCH),
        ("initial", AuthorizationReason.INITIAL_SPEC_MISMATCH),
    ):
        if needle in lowered:
            return code
    return AuthorizationReason.TEMPLATE_INVALID
