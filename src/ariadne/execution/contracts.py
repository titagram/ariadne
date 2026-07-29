"""Fail-closed contracts between durable plans and subprocess runtimes."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, NoReturn

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
            normalized_ports=(
                normalize_nmap_ports(action.operation, action.inputs)
                if action.adapter == "nmap"
                else None
            ),
        )

    def verify_action(self, action: PlannedAction) -> None:
        if canonical_digest(action) != self.action_digest:
            raise ProcessAuthorizationError(
                AuthorizationReason.ACTION_DIGEST_MISMATCH
            )


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
        contracts = [
            ExecutionContract(
                adapter="research",
                operation="investigate",
                executable_ids=frozenset({"ping", "searchsploit"}),
                implementation_id="ariadne.adapters.research.ResearchAdapter",
                max_rate=1,
                max_concurrency=1,
                max_attempts=1,
                max_duration_seconds=60,
                max_output_bytes=1_048_576,
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
        ]
        return cls({
            (contract.adapter, contract.operation): contract
            for contract in contracts
        })

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
        implementation_id = (
            f"{type(adapter).__module__}.{type(adapter).__qualname__}"
        )
        if implementation_id != contract.implementation_id:
            raise ProcessAuthorizationError(
                AuthorizationReason.IMPLEMENTATION_MISMATCH
            )


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
            raise ProcessAuthorizationError(
                "Execution contract does not match the durable action"
            )
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
        self._attempts = next_attempt
        async with self._coordinator.slot():
            result = await self._runtime.run(spec)
        self._output_bytes += len(result.stdout.encode()) + len(
            result.stderr.encode()
        )
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
        if elapsed >= duration_bound or spec.timeout_seconds > (
            duration_bound - elapsed
        ):
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
                    f"Executable/tool {executable!r} is not explicitly allowed "
                    f"for {capability!r}",
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
                        f"Requested {label} {requested} exceeds policy "
                        f"limit {maximum}",
                        spec,
                    )

    def _semantic_validate(self, spec: ProcessSpec) -> tuple[int, int]:
        if self._contract.adapter == "nmap":
            return self._validate_nmap(spec), 1
        if self._contract.adapter == "research":
            self._validate_research(spec)
            return 1, 1
        self._deny("Unsupported execution contract validator", spec)

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
        if (
            port_index + 1 >= len(argv)
            or argv[port_index + 1] != self._envelope.normalized_ports
        ):
            self._deny(AuthorizationReason.PORTS_MISMATCH, spec)

        scan_flags = set(argv) & {"-sS", "-sT", "-sU"}
        scan_flag_count = sum(
            argv.count(flag) for flag in ("-sS", "-sT", "-sU")
        )
        operation = self._contract.operation
        if operation == "udp_targeted":
            expected_scan = (
                scan_flag_count == 1
                and scan_flags == {"-sU"}
                and "-sV" not in argv
            )
        elif operation == "service_fingerprint":
            expected_scan = (
                scan_flag_count == 1
                and scan_flags <= {"-sS", "-sT"}
                and "-sV" in argv
            )
        else:
            expected_scan = (
                scan_flag_count == 1
                and scan_flags <= {"-sS", "-sT"}
                and "-sV" not in argv
            )
        if not expected_scan:
            self._deny("Nmap scan flags do not match the operation", spec)

        allowed_flags = {
            "-n", "-Pn", "-sS", "-sT", "-sU", "-sV",
            "--max-rate", "-p", "-oX", "--",
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
            if len(spec.argv) != 2 or not spec.argv[1].strip():
                self._deny(
                    "Searchsploit template requires one product query",
                    spec,
                )
            if target in spec.argv:
                self._deny(
                    "Searchsploit query must not contain the engagement target",
                    spec,
                )
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
    return contract_bound if plan_bound is None else min(
        plan_bound,
        contract_bound,
    )


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
        if any(
            isinstance(port, bool) or not isinstance(port, (int, str))
            for port in ports
        ):
            raise ProcessAuthorizationError(
                AuthorizationReason.PORTS_MISMATCH
            )
        raw_port_str = ",".join(str(port) for port in ports)
    else:
        raise ProcessAuthorizationError(AuthorizationReason.PORTS_MISMATCH)

    normalized: list[str] = []
    for token in raw_port_str.split(","):
        if not token or token != token.strip():
            raise ProcessAuthorizationError(
                AuthorizationReason.PORTS_MISMATCH
            )
        bounds = token.split("-")
        if len(bounds) == 1:
            if not bounds[0].isdigit():
                raise ProcessAuthorizationError(
                    AuthorizationReason.PORTS_MISMATCH
                )
            port = int(bounds[0])
            if not 1 <= port <= 65535:
                raise ProcessAuthorizationError(
                    AuthorizationReason.PORTS_MISMATCH
                )
            normalized.append(str(port))
            continue
        if len(bounds) != 2 or not all(
            bound.isdigit() for bound in bounds
        ):
            raise ProcessAuthorizationError(
                AuthorizationReason.PORTS_MISMATCH
            )
        low, high = (int(bound) for bound in bounds)
        if not 1 <= low <= high <= 65535:
            raise ProcessAuthorizationError(
                AuthorizationReason.PORTS_MISMATCH
            )
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
