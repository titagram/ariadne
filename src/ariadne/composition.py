from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ariadne.adapters import AdapterRegistry, build_default_registry
from ariadne.adapters.base import Runtime
from ariadne.core.engagement import EngagementSnapshot
from ariadne.core.planner import Planner
from ariadne.core.workflow import WorkflowCatalog
from ariadne.execution.contracts import (
    ExecutionContractRegistry,
    ExecutionCoordinator,
)
from ariadne.hades_adapter.commands import AriadneCommand
from ariadne.hades_adapter.consent import (
    ConsentGateway,
    UnavailableConsentGateway,
    load_hades_consent_gateway,
)
from ariadne.hades_adapter.session import ChallengeLedger
from ariadne.knowledge import (
    KnowledgeIndex,
    LocalToolProbe,
    RuntimeVerificationStore,
    ToolCardVerifier,
)
from ariadne.runtime.docker import OnDemandKaliRuntime
from ariadne.store.paths import ariadne_home
from ariadne.store.run_store import RunStore

_DEFAULT_WORKFLOW_DIR = Path(__file__).resolve().parent.parent.parent / "workflows"
_DEFAULT_KNOWLEDGE_DIR = Path(__file__).resolve().parent.parent.parent / "knowledge"


class _RunScopedKaliRuntimeFactory:
    """Keep one mutable Kali lifecycle owner for each immutable run."""

    def __init__(
        self,
        factory: Callable[[EngagementSnapshot, Path], Runtime],
    ) -> None:
        self._factory = factory
        self._runtimes: dict[tuple[str, Path], Runtime] = {}

    def __call__(self, snapshot: EngagementSnapshot, run_root: Path) -> Runtime:
        resolved_root = run_root.resolve()
        key = (snapshot.snapshot_hash, resolved_root)
        runtime = self._runtimes.get(key)
        if runtime is None:
            runtime = self._factory(snapshot, resolved_root)
            self._runtimes[key] = runtime
        return runtime


def _default_kali_runtime(
    snapshot: EngagementSnapshot,
    run_root: Path,
) -> Runtime:
    return OnDemandKaliRuntime(snapshot=snapshot, run_root=run_root)


@dataclass(frozen=True)
class ServiceContainer:
    profile_name: str
    ledger: ChallengeLedger = field(default_factory=ChallengeLedger)
    store: RunStore = field(default_factory=RunStore)
    catalog: WorkflowCatalog | None = None
    adapter_registry: AdapterRegistry = field(default_factory=build_default_registry)
    consent_gateway: ConsentGateway = field(default_factory=UnavailableConsentGateway)
    execution_contract_registry: ExecutionContractRegistry = field(
        default_factory=ExecutionContractRegistry.curated
    )
    execution_coordinator: ExecutionCoordinator = field(
        default_factory=lambda: ExecutionCoordinator(max_concurrency=1)
    )
    tool_card_verifier: ToolCardVerifier | None = None
    kali_runtime_factory: Callable[
        [EngagementSnapshot, Path],
        Runtime,
    ] = _default_kali_runtime
    command: AriadneCommand = field(init=False)
    planner: Planner = field(init=False)

    def __post_init__(self) -> None:
        """Load the workflow catalog if not provided."""
        self.adapter_registry.freeze()
        object.__setattr__(
            self,
            "kali_runtime_factory",
            _RunScopedKaliRuntimeFactory(self.kali_runtime_factory),
        )
        if self.catalog is None:
            wf_dir = _DEFAULT_WORKFLOW_DIR
            object.__setattr__(
                self,
                "catalog",
                WorkflowCatalog.load(wf_dir) if wf_dir.is_dir() else WorkflowCatalog(playbooks={}),
            )
        cat = self.catalog if self.catalog is not None else WorkflowCatalog(playbooks={})
        object.__setattr__(self, "planner", Planner(catalog=cat))
        object.__setattr__(
            self,
            "command",
            AriadneCommand(ledger=self.ledger, store=self.store),
        )
        if self.tool_card_verifier is None and _DEFAULT_KNOWLEDGE_DIR.is_dir():
            knowledge_root = ariadne_home(self.store.base_path) / "knowledge-runtime"
            object.__setattr__(
                self,
                "tool_card_verifier",
                ToolCardVerifier(
                    index=KnowledgeIndex.load(_DEFAULT_KNOWLEDGE_DIR),
                    probe=LocalToolProbe(),
                    store=RuntimeVerificationStore(knowledge_root),
                ),
            )


def build_services(profile_name: str) -> ServiceContainer:
    return ServiceContainer(
        profile_name=profile_name,
        consent_gateway=load_hades_consent_gateway(),
    )


def register(ctx: object) -> None:
    from ariadne.hades_adapter.registration import register_plugin

    register_plugin(ctx, build_services(getattr(ctx, "profile_name", "default")))
