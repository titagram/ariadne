from dataclasses import dataclass


@dataclass(frozen=True)
class ServiceContainer:
    profile_name: str


def build_services(profile_name: str) -> ServiceContainer:
    return ServiceContainer(profile_name=profile_name)


def register(ctx: object) -> None:
    from ariadne.hades_adapter.registration import register_plugin

    register_plugin(ctx, build_services(getattr(ctx, "profile_name", "default")))
