"""Curated Active Directory adapter for Ariadne.

Provides bounded Active Directory discovery and exploitation operations:

**Discovery operations:** (no capability required)
- domain_discovery        — bounded Impacket SID lookup
- ldap_rootdse            — ldapsearch RootDSE
- smb_enumeration         — smbclient share listing
- kerberos_user_validation — Kerbrute user enumeration
- bloodhound_collection   — BloodHound/SharpHound collection
- certipy_find            — Certipy AD CS discovery (read-only)

**High-impact operations:** (each requires an explicit capability)
- password_spray          — ad.password_spray
- credential_dump         — ad.credential_dump
- ntlm_poisoning          — ad.ntlm_poisoning
- ntlm_relay              — ad.ntlm_relay
- ticket_manipulation     — ad.ticket_manipulation
- object_modification     — ad.object_modification
- certipy_relay           — ad.adcs_abuse

High-impact operations are never implicitly discoverable; they require the
exact capability key in the engagement context environment.
"""

from __future__ import annotations

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

_DISCOVERY_OPERATIONS: frozenset = frozenset({
    "domain_discovery",
    "ldap_rootdse",
    "smb_enumeration",
    "kerberos_user_validation",
    "bloodhound_collection",
    "certipy_find",
})

# Each high-impact operation requires its own capability.
_HIGH_IMPACT_OPS: dict[str, str] = {
    "password_spray": "ad.password_spray",
    "credential_dump": "ad.credential_dump",
    "ntlm_poisoning": "ad.ntlm_poisoning",
    "ntlm_relay": "ad.ntlm_relay",
    "ticket_manipulation": "ad.ticket_manipulation",
    "object_modification": "ad.object_modification",
    "certipy_relay": "ad.adcs_abuse",
}

_ALL_OPERATIONS: frozenset = frozenset(
    _DISCOVERY_OPERATIONS | set(_HIGH_IMPACT_OPS.keys())
)

# Environment variable prefix for capability keys.
_CAPABILITY_ENV_PREFIX = "CAPABILITY_"

# ── Capability helpers ───────────────────────────────────────────────────────


def _capability_env_key(capability: str) -> str:
    """Convert ``ad.password_spray`` → ``CAPABILITY_ad_password_spray``."""
    safe = capability.replace(".", "_").replace("-", "_")
    return f"{_CAPABILITY_ENV_PREFIX}{safe}"


def _check_capability(
    context: AdapterContext,
    capability: str,
    operation: str,
) -> None:
    """Check whether *capability* is allowed in *context*.

    Raises ``AdapterPolicyError`` if the capability is explicitly denied
    or not present.
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
    # Unset -> deny by default for high-impact operations
    raise AdapterPolicyError(
        f"Operation {operation!r} requires capability {capability!r}, "
        f"which is not declared in the engagement context. "
        f"Set {env_key}=allow to enable this operation."
    )


# ── Adapter ────────────────────────────────────────────────────────────────────


class ActiveDirectoryAdapter:
    """ToolAdapter for curated Active Directory operations.

    Separates discovery (read-only, no capability required) from high-impact
    operations (each with an explicit capability gate).  No generic ``ad.attack``
    switch is provided.
    """

    name: ClassVar[str] = "active_directory"

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

        if op not in _ALL_OPERATIONS:
            raise AdapterError(
                f"Unknown AD operation: {op!r}. "
                f"Supported: {', '.join(sorted(_ALL_OPERATIONS))}"
            )

        # Check capability for high-impact operations
        if op in _HIGH_IMPACT_OPS:
            _check_capability(context, _HIGH_IMPACT_OPS[op], op)

        inputs = action.inputs
        domain = context.environment.get("DOMAIN", "")

        # Dispatch to planner
        if op == "domain_discovery":
            return self._plan_domain_discovery(inputs, context, domain)
        elif op == "ldap_rootdse":
            return self._plan_ldap_rootdse(inputs, context)
        elif op == "smb_enumeration":
            return self._plan_smb_enumeration(inputs, context)
        elif op == "kerberos_user_validation":
            return self._plan_kerberos_user_validation(inputs, context, domain)
        elif op == "bloodhound_collection":
            return self._plan_bloodhound_collection(inputs, context, domain)
        elif op == "certipy_find":
            return self._plan_certipy_find(inputs, context, domain)
        elif op == "password_spray":
            return self._plan_password_spray(inputs, context, domain)
        elif op == "credential_dump":
            return self._plan_credential_dump(inputs, context)
        elif op == "ntlm_poisoning":
            return self._plan_ntlm_poisoning(inputs, context)
        elif op == "ntlm_relay":
            return self._plan_ntlm_relay(inputs, context)
        elif op == "ticket_manipulation":
            return self._plan_ticket_manipulation(inputs, context, domain)
        elif op == "object_modification":
            return self._plan_object_modification(inputs, context)
        elif op == "certipy_relay":
            return self._plan_certipy_relay(inputs, context, domain)
        else:
            raise AdapterError(f"Unhandled AD operation: {op!r}")

    # ── Discovery planners ─────────────────────────────────────────────────

    def _plan_domain_discovery(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
        domain: str,
    ) -> ProcessSpec:
        return ProcessSpec(
            argv=(
                "impacket-lookupsid",
                "-no-pass",
                str(context.target.host),
                "500",
            ),
            timeout_seconds=30,
            max_output_bytes=256 * 1024,
        )

    def _plan_ldap_rootdse(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        return ProcessSpec(
            argv=("ldapsearch", "-H", f"ldap://{context.target.host}",
                   "-x", "-s", "base", "-b", "", "objectClass=*"),
            timeout_seconds=30,
            max_output_bytes=512 * 1024,
        )

    def _plan_smb_enumeration(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        return ProcessSpec(
            argv=("smbclient", "-L", f"//{context.target.host}/",
                   "-N"),  # no password
            timeout_seconds=30,
            max_output_bytes=256 * 1024,
        )

    def _plan_kerberos_user_validation(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
        domain: str,
    ) -> ProcessSpec:
        userlist = str(inputs.get("userlist", "/opt/tools/userlist.txt"))
        return ProcessSpec(
            argv=(
                "impacket-GetNPUsers",
                "-no-pass",
                "-dc-ip",
                str(context.target.host),
                "-usersfile",
                userlist,
                f"{domain or 'contoso.local'}/",
            ),
            timeout_seconds=300,
            max_output_bytes=1 * 1024 * 1024,
        )

    def _plan_bloodhound_collection(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
        domain: str,
    ) -> ProcessSpec:
        return ProcessSpec(
            argv=("bloodhound-python", "-d", domain or "contoso.local",
                   "-dc", str(context.target.host),
                   "-ns", str(context.target.host),
                   "--zip"),
            timeout_seconds=600,
            max_output_bytes=10 * 1024 * 1024,
        )

    def _plan_certipy_find(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
        domain: str,
    ) -> ProcessSpec:
        return ProcessSpec(
            argv=("certipy-ad", "find", "-u", str(inputs.get("username", "")),
                   "-p", str(inputs.get("password", "")),
                   "-dc-ip", str(context.target.host),
                   "-target", domain or "contoso.local"),
            timeout_seconds=120,
            max_output_bytes=2 * 1024 * 1024,
        )

    # ── High-impact planners ───────────────────────────────────────────────

    def _plan_password_spray(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
        domain: str,
    ) -> ProcessSpec:
        password = str(inputs.get("password", ""))
        userlist = str(inputs.get("userlist", "/opt/tools/userlist.txt"))
        return ProcessSpec(
            argv=("netexec", "smb", str(context.target.host),
                   "-d", domain or "contoso.local",
                   "-u", userlist,
                   "-p", password,
                   "--continue-on-success"),
            timeout_seconds=600,
            max_output_bytes=1 * 1024 * 1024,
        )

    def _plan_credential_dump(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        return ProcessSpec(
            argv=("impacket-secretsdump", str(context.target.host)),
            timeout_seconds=600,
            max_output_bytes=10 * 1024 * 1024,
        )

    def _plan_ntlm_poisoning(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        return ProcessSpec(
            argv=("responder", "-I", str(inputs.get("interface", "eth0")),
                   "-A"),  # analyze mode
            timeout_seconds=60,
            max_output_bytes=1 * 1024 * 1024,
        )

    def _plan_ntlm_relay(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        target = str(inputs.get("relay_target", ""))
        return ProcessSpec(
            argv=(
                "impacket-ntlmrelayx",
                "-t",
                target or f"smb://{context.target.host}",
            ),
            timeout_seconds=300,
            max_output_bytes=2 * 1024 * 1024,
        )

    def _plan_ticket_manipulation(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
        domain: str,
    ) -> ProcessSpec:
        return ProcessSpec(
            argv=("impacket-ticketer", "-nthash",
                   str(inputs.get("nthash", "")),
                   "-domain", domain or "contoso.local",
                   "-user", str(inputs.get("username", "Administrator")),
                   "-dc-ip", str(context.target.host)),
            timeout_seconds=60,
            max_output_bytes=512 * 1024,
        )

    def _plan_object_modification(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
    ) -> ProcessSpec:
        return ProcessSpec(
            argv=("bloodyad", "-d", str(context.target.host),
                   "-u", str(inputs.get("username", "")),
                   "-p", str(inputs.get("password", "")),
                   "--target", str(inputs.get("target_user", "")),
                   "--action", str(inputs.get("action", "add"))),
            timeout_seconds=120,
            max_output_bytes=512 * 1024,
        )

    def _plan_certipy_relay(
        self,
        inputs: dict[str, object],
        context: AdapterContext,
        domain: str,
    ) -> ProcessSpec:
        ca = str(inputs.get("ca", f"{domain}\\{domain}-DC01-CA"))
        template = str(inputs.get("template", "VulnTemplate"))
        return ProcessSpec(
            argv=("certipy-ad", "req", "-u", str(inputs.get("username", "")),
                   "-p", str(inputs.get("password", "")),
                   "-ca", ca,
                   "-template", template,
                   "-dc-ip", str(context.target.host)),
            timeout_seconds=120,
            max_output_bytes=1 * 1024 * 1024,
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

        # Detect domain discovery output
        if (
            "DSGETDC" in stdout
            or "Dom Name:" in stdout
            or "Domain SID" in stdout
        ):
            observations.append(self._make_observation({
                "tool": "domain_discovery",
                "type": "domain_info",
                "snippet": stdout[:1000],
            }))
            return tuple(observations)

        # Detect LDAP RootDSE output
        if "rootDomainNamingContext" in stdout or "namingContexts" in stdout:
            observations.append(self._make_observation({
                "tool": "ldap_rootdse",
                "type": "ldap_configuration",
                "snippet": stdout[:2000],
            }))
            return tuple(observations)

        # Detect SMB enumeration output
        if "Sharename" in stdout and "ADMIN$" in stdout:
            observations.append(self._make_observation({
                "tool": "smb_enumeration",
                "type": "smb_shares",
                "shares": stdout[:1000],
            }))
            return tuple(observations)

        # Detect bounded Kerberos/AS-REP user validation output
        if (
            "VALID USERNAME" in stdout
            or "kerbrute" in stdout.lower()
            or "doesn't have UF_DONT_REQUIRE_PREAUTH set" in stdout
            or "$krb5asrep$" in stdout
        ):
            observations.append(self._make_observation({
                "tool": "kerberos_user_validation",
                "type": "user_enumeration",
                "valid_users": stdout[:2000],
            }))
            return tuple(observations)

        # Detect BloodHound collection output
        if "BloodHound" in stdout or "SharpHound" in stdout:
            observations.append(self._make_observation({
                "tool": "bloodhound_collection",
                "type": "domain_relationship_mapping",
                "snippet": stdout[:2000],
            }))
            return tuple(observations)

        # Detect Certipy output
        if "certipy" in stdout.lower() and "vulnerable" in stdout.lower():
            observations.append(self._make_observation({
                "tool": "certipy_find",
                "type": "adcs_discovery",
                "vulnerable_templates": stdout[:2000],
            }))
            return tuple(observations)

        # Detect password spray output
        if "LOGIN FAILED" in stdout or "spray" in stdout.lower():
            observations.append(self._make_observation({
                "tool": "password_spray",
                "type": "credential_spray",
                "results": stdout[:2000],
            }))
            return tuple(observations)

        # Detect credential dump output
        if "impacket-secretsdump" in stdout.lower() or "SAM" in stdout:
            observations.append(self._make_observation({
                "tool": "credential_dump",
                "type": "credential_access",
                "snippet": stdout[:2000],
            }))
            return tuple(observations)

        # Fallback: generic observation
        if len(stdout.strip()) > 20:
            observations.append(self._make_observation({
                "type": "raw_output",
                "snippet": stdout[:500],
            }))

        return tuple(observations)

    def _make_observation(self, data: dict[str, object]) -> Observation:
        from ariadne.core.engagement import TargetSpec

        return Observation(
            observation_id=uuid4(),
            target=TargetSpec(host="0.0.0.0"),
            source="active_directory",
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
                summary="AD operation timed out; partial results may be available",
            )
        if result.exit_code != 0:
            return ExecutionClassification(
                kind="failure",
                confidence=0.5,
                summary=f"AD operation exited with code {result.exit_code}",
            )
        if len(observations) > 0:
            return ExecutionClassification(
                kind="success",
                confidence=0.7,
                summary=f"AD operation returned {len(observations)} observations",
            )
        return ExecutionClassification(
            kind="unknown",
            confidence=0.5,
            summary="AD operation completed with no structured output",
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
