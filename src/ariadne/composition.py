from dataclasses import dataclass, field
from pathlib import Path

from ariadne.adapters import AdapterRegistry, build_default_registry
from ariadne.core.planner import Planner
from ariadne.core.workflow import WorkflowCatalog
from ariadne.execution.contracts import ExecutionContractRegistry
from ariadne.hades_adapter.commands import AriadneCommand
from ariadne.hades_adapter.consent import (
    ConsentGateway,
    UnavailableConsentGateway,
    load_hades_consent_gateway,
)
from ariadne.hades_adapter.session import ChallengeLedger
from ariadne.store.run_store import RunStore

_DEFAULT_WORKFLOW_DIR = (
    Path(__file__).resolve().parent.parent.parent / "workflows"
)


@dataclass(frozen=True)
class ServiceContainer:
    profile_name: str
    ledger: ChallengeLedger = field(default_factory=ChallengeLedger)
    store: RunStore = field(default_factory=RunStore)
    catalog: WorkflowCatalog | None = None
    adapter_registry: AdapterRegistry = field(default_factory=build_default_registry)
    consent_gateway: ConsentGateway = field(
        default_factory=UnavailableConsentGateway
    )
    execution_contract_registry: ExecutionContractRegistry = field(
        default_factory=ExecutionContractRegistry.curated
    )
    command: AriadneCommand = field(init=False)
    planner: Planner = field(init=False)

    def __post_init__(self) -> None:
        """Load the workflow catalog if not provided."""
        if self.catalog is None:
            wf_dir = _DEFAULT_WORKFLOW_DIR
            object.__setattr__(
                self, "catalog", WorkflowCatalog.load(wf_dir) if wf_dir.is_dir()
                else WorkflowCatalog(playbooks={})
            )
        cat = self.catalog if self.catalog is not None else WorkflowCatalog(playbooks={})
        object.__setattr__(self, "planner", Planner(catalog=cat))
        object.__setattr__(
            self,
            "command",
            AriadneCommand(ledger=self.ledger, store=self.store),
        )


def build_services(profile_name: str) -> ServiceContainer:
    return ServiceContainer(
        profile_name=profile_name,
        consent_gateway=load_hades_consent_gateway(),
    )


def register(ctx: object) -> None:
    from ariadne.hades_adapter.registration import register_plugin

    register_plugin(ctx, build_services(getattr(ctx, "profile_name", "default")))
