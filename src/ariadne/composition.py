from dataclasses import dataclass, field

from ariadne.hades_adapter.commands import AriadneCommand
from ariadne.hades_adapter.session import ChallengeLedger
from ariadne.store.run_store import RunStore


@dataclass(frozen=True)
class ServiceContainer:
    profile_name: str
    ledger: ChallengeLedger = field(default_factory=ChallengeLedger)
    store: RunStore = field(default_factory=RunStore)

    @property
    def command(self) -> AriadneCommand:
        return AriadneCommand(ledger=self.ledger, store=self.store)


def build_services(profile_name: str) -> ServiceContainer:
    return ServiceContainer(profile_name=profile_name)


def register(ctx: object) -> None:
    from ariadne.hades_adapter.registration import register_plugin

    register_plugin(ctx, build_services(getattr(ctx, "profile_name", "default")))
