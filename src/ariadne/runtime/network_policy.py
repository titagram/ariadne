"""Network policy generation for Ariadne's netguard egress firewall.

Produces nftables-compatible allowlist entries from an engagement
snapshot's confirmed targets. The policy is used as the
``ARIADNE_ALLOW_TARGETS`` environment variable injected into the
netguard container at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ariadne.core.engagement import EngagementSnapshot, TargetSpec

# Default ports to allow during initial reconnaissance.
# A future task can make this configurable per engagement or objective.
_DEFAULT_PORTS: tuple[int, ...] = (22, 80, 443, 8080, 8443)


@dataclass(frozen=True)
class AllowlistEntry:
    """A single allowlisted target address and port combination."""

    host: str
    port: int


@dataclass(frozen=True)
class TargetAllowlist:
    """The complete egress allowlist derived from a snapshot's scope."""

    entries: tuple[AllowlistEntry, ...] = field(default_factory=tuple)

    @property
    def count(self) -> int:
        return len(self.entries)

    def to_nftables_rules(self) -> list[str]:
        """Generate nftables ``accept`` rules for every entry."""
        rules: list[str] = []
        for e in self.entries:
            rules.append(
                f"ip daddr {e.host} tcp dport {e.port} accept"
            )
            rules.append(
                f"ip daddr {e.host} udp dport {e.port} accept"
            )
        return rules

    def to_env_var(self) -> str:
        """Serialize to the ``ARIADNE_ALLOW_TARGETS`` env-var format."""
        return " ".join(f"{e.host}:{e.port}" for e in self.entries)


class NetworkPolicy:
    """Generates egress allowlists from engagement snapshots."""

    def __init__(self, ports: tuple[int, ...] = _DEFAULT_PORTS) -> None:
        self._ports = ports

    def build_allowlist(self, snapshot: EngagementSnapshot) -> TargetAllowlist:
        """Build a ``TargetAllowlist`` from *snapshot*'s confirmed targets.

        Each target is expanded across the configured port tuple.
        """
        entries: list[AllowlistEntry] = []
        for target in snapshot.targets:
            for port in self._ports:
                entries.append(AllowlistEntry(host=target.host, port=port))
        return TargetAllowlist(entries=tuple(entries))

    def build_allowlist_from_targets(
        self,
        targets: tuple[TargetSpec, ...],
    ) -> TargetAllowlist:
        """Build an allowlist from raw target specs (no snapshot needed)."""
        entries: list[AllowlistEntry] = []
        for target in targets:
            for port in self._ports:
                entries.append(AllowlistEntry(host=target.host, port=port))
        return TargetAllowlist(entries=tuple(entries))
