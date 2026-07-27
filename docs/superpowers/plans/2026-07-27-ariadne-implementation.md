# Ariadne Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Ariadne as a native Hades plugin that conducts policy-bounded, evidence-driven penetration tests against explicitly authorized lab and CTF targets and produces both a technical walkthrough and a professional report.

**Architecture:** Ariadne separates a Hades-specific adapter from a deterministic Python core. The core owns immutable engagement snapshots, policy intersection, state transitions, playbooks, typed tool adapters, evidence, and reporting; all target-facing execution occurs in allowlisted Docker containers based on official Kali and ZAP images.

**Tech Stack:** Python 3.11-3.13; Hades 0.17 plugin API; Pydantic 2.13.4; PyYAML 6.0.3; JSON Schema 2020-12; Jinja2 3.1.6; asyncio subprocesses; Docker Compose v2; `kalilinux/kali-rolling`; OWASP ZAP stable image; pytest 9.0.2; pytest-asyncio 1.3.0; Hypothesis; Ruff 0.15.10; `ty` 0.0.21.

## Global Constraints

- Repository, plugin, and Python package name: `ariadne`.
- Registered skill name: `ariadne:lab-pentest`.
- Interactive command: `/ariadne`.
- Initial host compatibility target: Hades 0.17.0 and its `PluginContext` API.
- Supported Python: `>=3.11,<3.14`, matching Hades.
- Runtime imports are limited to the Python standard library and dependencies already pinned by Hades; new Python packages must not be installed implicitly by plugin loading.
- The initial target is one user-confirmed IP address or FQDN; objectives are one or more explicit typed objectives.
- Every run requires interactive Hades/Hermes Q/A, a versioned legal disclaimer, and direct user confirmation.
- Environment profiles are selected only by the user.
- Effective policy is `base ∩ environment ∩ engagement ∩ action plan`; lower layers may never widen higher layers.
- `autonomy: full` never bypasses contract confirmation, scope amendments, host installation approval, uncurated PoC approval, or base invariants.
- Hades `--yolo` has no effect on Ariadne guardrails.
- Newly discovered assets are `observed_only` until a direct scope amendment creates a new immutable snapshot.
- HTB policy forbids denial of service, resource exhaustion, subnet scanning, and actions against other platform targets.
- Docker is the only execution environment; there is no VM fallback.
- The primary image is official `kalilinux/kali-rolling` with `kali-linux-headless`; ZAP runs in its official separate image.
- No persistence, C2, automatic propagation, or uncontrolled resource-stress behavior is implemented in v1.
- No shell interpolation is permitted: every executable action is an argument vector.
- Every subprocess has a timeout, maximum output size, and process-tree termination path.
- HexStrike is not a dependency, compatibility target, or roadmap item.
- The dossier is local, append-only, hash-verified, permission-restricted, and excluded from Git.
- Reporting is offline-first; SysReptor network push is explicit and previewed.
- The ordinary CI suite may only address loopback and its isolated Docker test network.
- Use TDD, keep tasks independently reviewable, and commit after each task.

---

## Source of Truth and Execution Order

The approved design is stored in this repository at:

`docs/superpowers/specs/2026-07-27-ariadne-design.md`

Treat it as the source of truth. Any implementation-driven design change must
update that document and receive review before the affected task continues.

Tasks are dependency-ordered. Do not start a later task while an earlier task
has failing tests. Milestone gates are:

1. Tasks 1-7: deterministic core and local dossier.
2. Tasks 8-10: Hades integration and non-bypassable in-session controls.
3. Tasks 11-16: Docker runtime and direct tool adapters.
4. Tasks 17-19: post-exploitation, AD/pivoting, and playbook catalog.
5. Tasks 20-22: evidence, reports, and SysReptor.
6. Tasks 23-24: adversarial integration testing, documentation, and release.

## Planned File Map

```text
ariadne/
  plugin.yaml                         Hades plugin manifest
  __init__.py                         minimal register(ctx) entry point
  pyproject.toml                      packaging and development tools
  uv.lock                             reproducible development environment
  src/ariadne/
    composition.py                    constructs services and registered handlers
    core/
      enums.py                        stable string enums
      engagement.py                   draft, objective, target, snapshot models
      planning.py                     action plans and approval records
      observations.py                 observations, assets, and hypotheses
      findings.py                     finding and remediation models
      canonical.py                    canonical JSON and SHA-256 helpers
      policy.py                       policy models, intersection, authorization
      state_machine.py                legal engagement transitions
      workflow.py                     playbook schema and catalog
      planner.py                      bounded plan construction and validation
      errors.py                       typed domain exceptions
    store/
      paths.py                        profile-scoped paths and permissions
      jsonl.py                        append-only JSONL writer/reader
      run_store.py                    snapshots, events, artifacts, active bindings
      integrity.py                    digest manifest generation and verification
    hades_adapter/
      registration.py                 PluginContext registrations
      schemas.py                      Hades tool JSON schemas
      handlers.py                     registered tool handlers
      commands.py                     `/ariadne` parser and direct approvals
      guard_hook.py                   pre_tool_call hard blocking
      session.py                      Hades session-to-engagement binding
    runtime/
      platform.py                     OS/architecture detection
      preflight.py                    Docker, route, VPN, disk, and memory checks
      install.py                      curated host install proposals/execution
      docker.py                       Docker Compose lifecycle
      network_policy.py               target resolution and allowlist generation
      process.py                      bounded subprocess runner
    adapters/
      base.py                         adapter protocol and typed execution results
      nmap.py                         Nmap builder and XML parser
      httpx.py                        httpx builder and JSONL parser
      zap.py                          ZAP Automation Framework plans
      nuclei.py                       curated Nuclei workflow execution
      research.py                     local/vendor/CVE/Exploit-DB research
      metasploit.py                   search/info/check/module execution
      postex.py                       PEASS, pspy, PrivescCheck, Seatbelt
      active_directory.py             NetExec, Impacket, BloodHound, Certipy
      pivot.py                        Ligolo-ng/Chisel lifecycle
      screenshot.py                   headless Chromium evidence
    evidence/
      records.py                      artifact metadata and provenance
      collector.py                    immutable file and transcript ingestion
      findings.py                     candidate-to-validated finding service
      redaction.py                    deterministic secret redaction
    reporting/
      validation.py                   pre-export quality gates
      walkthrough.py                  technical CTF renderer
      professional.py                 professional renderer
      pdf.py                          Chromium PDF export
      sysreptor.py                    offline bundle, preview, explicit push
  policies/
    policy.schema.json
    base.yaml
    private-lab.yaml
    htb.yaml
  workflows/
    workflow.schema.json
    base.yaml
    web.yaml
    linux.yaml
    windows.yaml
    active-directory.yaml
    pivoting.yaml
  containers/
    compose.yaml
    image-lock.yaml
    tool-manifest.yaml
    kali/Dockerfile
    netguard/entrypoint.sh
  skills/lab-pentest/
    SKILL.md
    references/contract.md
    references/workflow.md
    references/reporting.md
  report_templates/
    walkthrough/
    professional/
    sysreptor/
  tests/
    unit/
    contract/
    policy/
    integration/
    e2e/
    fixtures/
  docs/
    superpowers/specs/
    superpowers/plans/
    architecture.md
    operator-guide.md
    policy-reference.md
    adapter-development.md
  README.md
  SECURITY.md
  LICENSE
```

## Task 1: Bootstrap the Native Hades Plugin Repository

**Files:**
- Create: `plugin.yaml`
- Create: `__init__.py`
- Create: `pyproject.toml`
- Create: `.gitignore`
- Create: `src/ariadne/__init__.py`
- Create: `src/ariadne/composition.py`
- Create: `src/ariadne/hades_adapter/__init__.py`
- Create: `src/ariadne/hades_adapter/registration.py`
- Create: `skills/lab-pentest/SKILL.md`
- Create: `tests/unit/test_packaging.py`
- Existing: `docs/superpowers/specs/2026-07-27-ariadne-design.md`

**Interfaces:**
- Consumes: Hades `PluginContext.register_tool`, `register_command`, `register_hook`, and `register_skill`.
- Produces: `register(ctx: object) -> None` and `build_services(profile_name: str) -> ServiceContainer`.

- [ ] **Step 1: Add development metadata and a failing packaging contract test**

Create `pyproject.toml` first with `requires-python = ">=3.11,<3.14"`, the
Hades-compatible runtime pins listed in this plan's Tech Stack, and the pinned
development tools. Then add:

```python
from pathlib import Path
import yaml


def test_plugin_manifest_and_skill_are_hades_loadable() -> None:
    root = Path(__file__).parents[2]
    manifest = yaml.safe_load((root / "plugin.yaml").read_text())
    assert manifest["name"] == "ariadne"
    assert manifest["kind"] == "standalone"
    assert manifest["manifest_version"] == 1
    assert (root / "__init__.py").is_file()
    assert (root / "skills/lab-pentest/SKILL.md").is_file()
```

- [ ] **Step 2: Run the test and verify the missing scaffold**

Run: `uv lock && uv run pytest tests/unit/test_packaging.py -v`
Expected: FAIL because `plugin.yaml` and the skill do not exist.

- [ ] **Step 3: Create the manifest, entry point, package metadata, and minimal skill**

`plugin.yaml`:

```yaml
manifest_version: 1
name: ariadne
version: 0.1.0
kind: standalone
description: Policy-bounded lab and CTF pentesting for Hades
author: Gabriele
provides_tools:
  - ariadne_prepare_engagement
  - ariadne_bind_engagement
  - ariadne_status
  - ariadne_propose_plan
  - ariadne_execute_plan
  - ariadne_render_report
provides_hooks:
  - pre_tool_call
```

Root `__init__.py`:

```python
from pathlib import Path
import sys

_SRC = Path(__file__).parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ariadne.composition import register

__all__ = ["register"]
```

Start `composition.py` with this stable bootstrap interface; later tasks add
services without changing its caller:

```python
@dataclass(frozen=True)
class ServiceContainer:
    profile_name: str


def build_services(profile_name: str) -> ServiceContainer:
    return ServiceContainer(profile_name=profile_name)


def register(ctx: object) -> None:
    from ariadne.hades_adapter.registration import register_plugin
    register_plugin(ctx, build_services(getattr(ctx, "profile_name", "default")))
```

The initial `register_plugin` registers only the skill so the scaffold is
loadable before Task 8:

```python
def register_plugin(ctx: object, services: ServiceContainer) -> None:
    skill_path = Path(__file__).parents[3] / "skills" / "lab-pentest" / "SKILL.md"
    ctx.register_skill(
        name="lab-pentest",
        path=skill_path,
        description="Controlled authorized lab and CTF pentesting",
    )
```

Do not add an install hook to `plugin.yaml`; directory plugins are imported
directly by Hades.

- [ ] **Step 4: Run packaging and quality checks**

Run:

```bash
uv lock
uv run pytest tests/unit/test_packaging.py -v
uv run ruff check .
uv run ty check src
```

Expected: lock generation succeeds and all checks pass.

- [ ] **Step 5: Commit the independently loadable skeleton**

```bash
git add plugin.yaml __init__.py pyproject.toml uv.lock .gitignore src tests skills
git commit -m "chore: bootstrap Ariadne Hades plugin"
```

## Task 2: Define Stable Domain Models and Canonical Digests

**Files:**
- Create: `src/ariadne/core/enums.py`
- Create: `src/ariadne/core/engagement.py`
- Create: `src/ariadne/core/planning.py`
- Create: `src/ariadne/core/observations.py`
- Create: `src/ariadne/core/findings.py`
- Create: `src/ariadne/core/canonical.py`
- Create: `src/ariadne/core/errors.py`
- Test: `tests/unit/test_domain_models.py`

**Interfaces:**
- Consumes: Pydantic 2.13.4.
- Produces: `EngagementDraft`, `EngagementSnapshot`, `ActionPlan`,
  `Observation`, `Asset`, `Hypothesis`, `Finding`, and
  `canonical_digest(model: BaseModel) -> str`.

- [ ] **Step 1: Write failing tests for normalized targets, objectives, and deterministic digests**

```python
from ariadne.core.canonical import canonical_digest
from ariadne.core.engagement import EngagementDraft, Objective, TargetSpec
from ariadne.core.enums import AutonomyMode, EnvironmentProfile


def test_draft_normalizes_fqdn_and_digest_is_stable() -> None:
    draft = EngagementDraft(
        authorization_attested=True,
        disclaimer_version="2026-07-27",
        profile=EnvironmentProfile.HTB,
        autonomy=AutonomyMode.CONTROLLED,
        target=TargetSpec(host="BOX.HTB."),
        objectives=[Objective(kind="user_flag", description="Obtain user flag")],
    )
    assert draft.target.host == "box.htb"
    assert canonical_digest(draft) == canonical_digest(
        EngagementDraft.model_validate(draft.model_dump())
    )
```

- [ ] **Step 2: Verify the model imports fail**

Run: `uv run pytest tests/unit/test_domain_models.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Implement enums and strict models**

Use `ConfigDict(extra="forbid", frozen=True)`. Define these exact enum values:

```python
class AutonomyMode(StrEnum):
    CONTROLLED = "controlled"
    FULL = "full"


class EnvironmentProfile(StrEnum):
    PRIVATE_LAB = "private-lab"
    HTB = "htb"


class AssetStatus(StrEnum):
    IN_SCOPE = "in_scope"
    OBSERVED_ONLY = "observed_only"


class FindingStatus(StrEnum):
    CANDIDATE = "candidate"
    VALIDATED = "validated"
    EXPLOITED = "exploited"
    FALSE_POSITIVE = "false_positive"
    INFORMATIONAL = "informational"
    POLICY_BLOCKED = "not_tested_due_to_policy"
```

`TargetSpec` accepts only a valid IP literal or normalized IDNA FQDN, rejects
URLs, CIDRs, wildcards, and embedded ports. `Objective.kind` is one of
`user_flag`, `root_flag`, `domain_admin`, `proof`, or `custom`. `custom`
requires a non-empty description.

`canonical_digest` serializes with sorted keys, UTF-8, compact separators, UTC
timestamps, and SHA-256.

- [ ] **Step 4: Exercise validation and type checks**

Run:

```bash
uv run pytest tests/unit/test_domain_models.py -v
uv run ruff check src/ariadne/core tests/unit/test_domain_models.py
uv run ty check src/ariadne/core
```

Expected: all checks pass.

- [ ] **Step 5: Commit the domain contract**

```bash
git add src/ariadne/core tests/unit/test_domain_models.py
git commit -m "feat: define Ariadne domain models"
```

## Task 3: Implement Immutable Engagement Snapshots

**Files:**
- Modify: `src/ariadne/core/engagement.py`
- Modify: `src/ariadne/core/canonical.py`
- Create: `tests/unit/test_engagement_snapshot.py`

**Interfaces:**
- Consumes: `EngagementDraft`, `canonical_digest`.
- Produces:
  `lock_engagement(draft: EngagementDraft, confirmation: Confirmation) -> EngagementSnapshot`
  and
  `amend_scope(snapshot: EngagementSnapshot, targets: tuple[TargetSpec, ...], confirmation: Confirmation) -> EngagementSnapshot`.

- [ ] **Step 1: Write failing immutability and amendment tests**

```python
def test_scope_amendment_creates_new_linked_snapshot(confirmed_draft, confirmation):
    first = lock_engagement(confirmed_draft, confirmation)
    second = amend_scope(
        first,
        targets=first.targets + (TargetSpec(host="10.10.10.20"),),
        confirmation=confirmation,
    )
    assert second.revision == first.revision + 1
    assert second.previous_snapshot_hash == first.snapshot_hash
    assert second.snapshot_hash != first.snapshot_hash
```

Also assert that direct attribute mutation raises and that a confirmation whose
challenge, disclaimer version, or expiry does not match is rejected.

- [ ] **Step 2: Confirm tests fail without the locking functions**

Run: `uv run pytest tests/unit/test_engagement_snapshot.py -v`
Expected: FAIL because the snapshot functions are undefined.

- [ ] **Step 3: Implement confirmation and snapshot creation**

Define:

```python
class Confirmation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    challenge_id: str
    challenge_digest: str
    confirmed_at: datetime
    expires_at: datetime
    actor: Literal["user"]


class EngagementSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    engagement_id: UUID
    revision: int
    previous_snapshot_hash: str | None
    snapshot_hash: str
    confirmed_at: datetime
    authorization_attested: bool
    disclaimer_version: str
    profile: EnvironmentProfile
    autonomy: AutonomyMode
    targets: tuple[TargetSpec, ...]
    objectives: tuple[Objective, ...]
    constraints: EngagementConstraints
```

Calculate the digest from every field except `snapshot_hash`; validate the
challenge against the canonical draft digest and reject confirmations older
than five minutes.

- [ ] **Step 4: Run snapshot and domain tests**

Run: `uv run pytest tests/unit/test_engagement_snapshot.py tests/unit/test_domain_models.py -v`
Expected: PASS.

- [ ] **Step 5: Commit immutable snapshots**

```bash
git add src/ariadne/core tests/unit/test_engagement_snapshot.py
git commit -m "feat: lock immutable engagement snapshots"
```

## Task 4: Implement Monotonic Policy Intersection

**Files:**
- Create: `policies/policy.schema.json`
- Create: `policies/base.yaml`
- Create: `policies/private-lab.yaml`
- Create: `policies/htb.yaml`
- Create: `src/ariadne/core/policy.py`
- Create: `tests/policy/test_policy_intersection.py`
- Create: `tests/policy/test_htb_denials.py`

**Interfaces:**
- Consumes: `EnvironmentProfile`, `EngagementSnapshot`, `ActionPlan`.
- Produces:
  `load_policy(path: Path) -> PolicyDocument`,
  `intersect_policies(*documents: PolicyDocument) -> EffectivePolicy`, and
  `authorize(policy: EffectivePolicy, request: ActionRequest) -> PolicyDecision`.

- [ ] **Step 1: Write failing property and HTB denial tests**

```python
from hypothesis import given
from hypothesis import strategies as st


@given(st.integers(1, 1000), st.integers(1, 1000))
def test_intersection_never_raises_rate(left: int, right: int) -> None:
    effective = intersect_policies(
        policy_with_rate(left),
        policy_with_rate(right),
    )
    assert effective.rule("scan.tcp").max_rate <= min(left, right)


def test_htb_blocks_resource_stress_and_cidr_targets(htb_policy) -> None:
    assert not authorize(htb_policy, request("resource.stress")).allowed
    assert not authorize(
        htb_policy, request("scan.tcp", target="10.10.10.0/24")
    ).allowed
```

- [ ] **Step 2: Run policy tests and observe missing engine failures**

Run: `uv run pytest tests/policy -v`
Expected: FAIL because policy types and fixtures do not exist.

- [ ] **Step 3: Implement schema, profiles, and fail-closed algebra**

Define `CapabilityRule` with:

```python
class CapabilityRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    allowed: bool = False
    always_manual: bool = False
    max_rate: int | None = None
    max_concurrency: int | None = None
    max_attempts: int | None = None
    max_duration_seconds: int | None = None
    max_output_bytes: int | None = None
    allowed_tools: frozenset[str] = frozenset()


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str
    version: int
    capabilities: Mapping[str, CapabilityRule]


class EffectivePolicy(PolicyDocument):
    source_digests: tuple[str, ...]


class ActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    capability: str
    target: str
    tool: str
    requested_rate: int
    requested_concurrency: int
    requested_attempts: int
    requested_duration_seconds: int
    requested_output_bytes: int


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    allowed: bool
    requires_manual_approval: bool
    reason_code: str
    effective_rule: CapabilityRule | None
```

Intersection uses boolean AND, the minimum of every non-null numeric bound,
tool-set intersection, and `always_manual` boolean OR. `null` means that layer
does not add a numeric restriction; the base policy still supplies a finite
bound for every executable capability. A missing capability is denied.
Validation errors raise `PolicyConfigurationError`.

The base profile must deny persistence, C2, propagation, automatic host
installation, automatic uncurated PoC, and unrestricted stress. The HTB profile
must set `resource.stress.allowed: false` and restrict targets to explicit
hosts.

- [ ] **Step 4: Run deterministic and property-based checks**

Run:

```bash
uv run pytest tests/policy -v
uv run ruff check src/ariadne/core/policy.py tests/policy
uv run ty check src/ariadne/core/policy.py
```

Expected: all tests pass, including 100 generated monotonicity examples.

- [ ] **Step 5: Commit policy enforcement**

```bash
git add policies src/ariadne/core/policy.py tests/policy
git commit -m "feat: enforce monotonic engagement policies"
```

## Task 5: Implement the Engagement State Machine

**Files:**
- Create: `src/ariadne/core/state_machine.py`
- Modify: `src/ariadne/core/enums.py`
- Create: `tests/unit/test_state_machine.py`

**Interfaces:**
- Consumes: current `EngagementState`, `TransitionRequest`, evidence IDs, and
  `PolicyDecision`.
- Produces:
  `transition(current: EngagementState, request: TransitionRequest) -> TransitionResult`.

- [ ] **Step 1: Write failing legal, illegal, and evidence-gated transition tests**

```python
def test_execution_requires_approved_plan_and_minimum_evidence() -> None:
    request = TransitionRequest(
        next_state=EngagementState.EXECUTION,
        plan_id="plan-1",
        approval_id=None,
        evidence_ids=(),
    )
    with pytest.raises(TransitionDenied):
        transition(EngagementState.ACTION_PLANNING, request)


def test_new_asset_enters_scope_amendment_state() -> None:
    result = transition(
        EngagementState.ENUMERATION,
        TransitionRequest(
            next_state=EngagementState.SCOPE_AMENDMENT_REQUIRED,
            evidence_ids=("asset-observation-1",),
        ),
    )
    assert result.next_state is EngagementState.SCOPE_AMENDMENT_REQUIRED
```

- [ ] **Step 2: Verify the transition table is absent**

Run: `uv run pytest tests/unit/test_state_machine.py -v`
Expected: FAIL on missing imports.

- [ ] **Step 3: Implement explicit transition rules**

Add every primary and side state from the design as `EngagementState`. Store
rules in an immutable mapping:

```python
class TransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    next_state: EngagementState
    plan_id: str | None = None
    approval_id: str | None = None
    evidence_ids: tuple[str, ...] = ()
    reason: str = ""


class TransitionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    previous_state: EngagementState
    next_state: EngagementState
    event_type: str


@dataclass(frozen=True)
class TransitionRule:
    sources: frozenset[EngagementState]
    destination: EngagementState
    required_fields: frozenset[str] = frozenset()
    minimum_evidence: int = 0


TRANSITION_RULES: tuple[TransitionRule, ...] = (
    TransitionRule(
        sources=frozenset({EngagementState.ACTION_PLANNING}),
        destination=EngagementState.AWAITING_APPROVAL,
        required_fields=frozenset({"plan_id"}),
    ),
    TransitionRule(
        sources=frozenset({
            EngagementState.AWAITING_APPROVAL,
            EngagementState.AUTO_APPROVED,
        }),
        destination=EngagementState.EXECUTION,
        required_fields=frozenset({"plan_id", "approval_id"}),
    ),
)
```

Complete the mapping for all design states. Unknown transitions raise
`TransitionDenied` and emit no state change.

- [ ] **Step 4: Run the complete state-machine suite**

Run: `uv run pytest tests/unit/test_state_machine.py -v`
Expected: PASS with every enum state appearing as a source or destination.

- [ ] **Step 5: Commit state control**

```bash
git add src/ariadne/core tests/unit/test_state_machine.py
git commit -m "feat: add evidence-gated engagement state machine"
```

## Task 6: Load Versioned Playbooks and Build Bounded Plans

**Files:**
- Create: `workflows/workflow.schema.json`
- Create: `src/ariadne/core/workflow.py`
- Create: `src/ariadne/core/planner.py`
- Create: `tests/unit/test_workflow_catalog.py`
- Create: `tests/unit/test_planner.py`
- Create: `tests/fixtures/workflows/minimal.yaml`

**Interfaces:**
- Consumes: `Observation`, `Hypothesis`, `EffectivePolicy`, and
  `EngagementSnapshot`.
- Produces:
  `WorkflowCatalog.load(directory: Path) -> WorkflowCatalog`,
  `WorkflowCatalog.eligible(context: WorkflowContext) -> tuple[Playbook, ...]`,
  and
  `Planner.build(playbook_id: str, context: PlanningContext) -> ActionPlan`.

- [ ] **Step 1: Write failing playbook-validation and stale-snapshot tests**

```python
def test_catalog_rejects_shell_strings(tmp_path: Path) -> None:
    write_workflow(tmp_path, actions=[{"adapter": "nmap", "shell": "nmap {target}"}])
    with pytest.raises(WorkflowConfigurationError):
        WorkflowCatalog.load(tmp_path)


def test_plan_carries_snapshot_and_expiry(catalog, planning_context) -> None:
    plan = Planner(catalog).build("network.tcp-discovery.v1", planning_context)
    assert plan.snapshot_hash == planning_context.snapshot.snapshot_hash
    assert plan.expires_at > plan.created_at
    assert all(action.argv is None for action in plan.actions)
```

The final assertion ensures playbooks name adapter operations; only the adapter
may generate an argument vector.

- [ ] **Step 2: Run the catalog and planner tests**

Run: `uv run pytest tests/unit/test_workflow_catalog.py tests/unit/test_planner.py -v`
Expected: FAIL because the catalog and planner are not implemented.

- [ ] **Step 3: Implement playbook models and plan construction**

Define these stable interfaces:

```python
class WorkflowContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    snapshot: EngagementSnapshot
    state: EngagementState
    observations: tuple[Observation, ...]
    assets: tuple[Asset, ...]
    effective_policy: EffectivePolicy


class PlanningContext(WorkflowContext):
    hypothesis: Hypothesis
    now: datetime


class PlaybookAction(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    adapter: str
    operation: str
    inputs: dict[str, JsonValue]


class Playbook(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    version: int
    stage: str
    triggers: tuple[Trigger, ...]
    required_evidence_types: frozenset[str]
    capabilities: frozenset[str]
    actions: tuple[PlaybookAction, ...]
    limits: PlaybookLimits
    stop_conditions: tuple[str, ...]
    success_emits: tuple[str, ...]
    next_playbooks: tuple[str, ...]
    report_sections: tuple[str, ...]
```

The planner intersects playbook limits with the effective policy, calculates
expected request count/duration/output, sets a 15-minute expiry, and rejects
unregistered adapters, unmet evidence, an `observed_only` target, or a denied
capability.

- [ ] **Step 4: Run schema, planner, and policy tests**

Run:

```bash
uv run pytest tests/unit/test_workflow_catalog.py tests/unit/test_planner.py tests/policy -v
uv run ruff check src/ariadne/core tests/unit
```

Expected: PASS.

- [ ] **Step 5: Commit deterministic planning**

```bash
git add workflows/workflow.schema.json src/ariadne/core tests/unit tests/fixtures/workflows
git commit -m "feat: build bounded plans from validated playbooks"
```

## Task 7: Build the Append-Only Run Store and Integrity Manifest

**Files:**
- Create: `src/ariadne/store/paths.py`
- Create: `src/ariadne/store/jsonl.py`
- Create: `src/ariadne/store/run_store.py`
- Create: `src/ariadne/store/integrity.py`
- Create: `tests/unit/test_run_store.py`
- Create: `tests/unit/test_integrity.py`

**Interfaces:**
- Consumes: immutable domain models and artifact byte streams.
- Produces:
  `RunStore.create(snapshot: EngagementSnapshot) -> RunHandle`,
  `RunStore.append_event(handle: RunHandle, event: Event) -> None`,
  `RunStore.add_artifact(handle: RunHandle, source: BinaryIO, metadata: ArtifactInput) -> StoredArtifact`,
  and
  `verify_run(path: Path) -> IntegrityResult`.

- [ ] **Step 1: Write failing permission, append, and tamper tests**

```python
def test_store_uses_restrictive_permissions(store, snapshot) -> None:
    handle = store.create(snapshot)
    assert stat.S_IMODE(handle.path.stat().st_mode) == 0o700
    assert stat.S_IMODE((handle.path / "engagement.lock.yaml").stat().st_mode) == 0o600


def test_integrity_detects_artifact_tampering(store, snapshot) -> None:
    handle = store.create(snapshot)
    artifact = store.add_bytes(handle, b"original", evidence("terminal"))
    artifact.path.write_bytes(b"changed")
    assert not verify_run(handle.path).valid
```

- [ ] **Step 2: Run store tests and verify failure**

Run: `uv run pytest tests/unit/test_run_store.py tests/unit/test_integrity.py -v`
Expected: FAIL on missing store modules.

- [ ] **Step 3: Implement profile-scoped paths and atomic appends**

Use:

```text
${HERMES_HOME:-~/.hermes}/ariadne/
  active-sessions.json
  challenges/
  runs/<engagement-id>/
```

Write files through a temporary file in the same directory, `flush`,
`os.fsync`, and `os.replace`. JSONL events include `sequence`,
`previous_event_hash`, and `event_hash`. Reject a sequence gap or hash-chain
mismatch. Evidence filenames are generated from UUIDs and safe extensions, not
user input.

`RunStore.add_artifact` must stream to disk while hashing, enforce the maximum
byte count before commit, set mode `0600`, and never follow symlinks.

Define the pre-report storage boundary without depending on Task 20:

```python
class ArtifactInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    media_type: str
    evidence_type: str
    source_name: str
    maximum_bytes: int


class StoredArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    artifact_id: UUID
    relative_path: Path
    size_bytes: int
    sha256: str
```

- [ ] **Step 4: Run store tests including interruption cases**

Run: `uv run pytest tests/unit/test_run_store.py tests/unit/test_integrity.py -v`
Expected: PASS, including recovery from an uncommitted temporary file.

- [ ] **Step 5: Commit the dossier store**

```bash
git add src/ariadne/store tests/unit/test_run_store.py tests/unit/test_integrity.py
git commit -m "feat: add hash-chained engagement store"
```

## Task 8: Register Ariadne with the Real Hades Plugin API

**Files:**
- Modify: `src/ariadne/composition.py`
- Modify: `src/ariadne/hades_adapter/registration.py`
- Create: `src/ariadne/hades_adapter/schemas.py`
- Create: `src/ariadne/hades_adapter/handlers.py`
- Modify: `skills/lab-pentest/SKILL.md`
- Create: `skills/lab-pentest/references/contract.md`
- Create: `skills/lab-pentest/references/workflow.md`
- Create: `tests/contract/test_hades_registration.py`

**Interfaces:**
- Consumes: Hades
  `ctx.register_tool(name, toolset, schema, handler, is_async, description, emoji)`,
  `ctx.register_skill(name, path, description)`,
  `ctx.register_command(name, handler, description, args_hint)`, and
  `ctx.register_hook(name, callback)`.
- Produces: registered skill `ariadne:lab-pentest`, six typed tools,
  `/ariadne`, and `pre_tool_call`.

- [ ] **Step 1: Write a failing fake-PluginContext contract test**

```python
def test_register_exposes_namespaced_skill_tools_command_and_hook(tmp_path):
    ctx = RecordingPluginContext(profile_name="test")
    register(ctx)
    assert ctx.skills == [("lab-pentest", "skills/lab-pentest/SKILL.md")]
    assert set(ctx.tools) == {
        "ariadne_prepare_engagement",
        "ariadne_bind_engagement",
        "ariadne_status",
        "ariadne_propose_plan",
        "ariadne_execute_plan",
        "ariadne_render_report",
    }
    assert "ariadne" in ctx.commands
    assert "pre_tool_call" in ctx.hooks
```

- [ ] **Step 2: Run the registration contract**

Run: `uv run pytest tests/contract/test_hades_registration.py -v`
Expected: FAIL because registration is still minimal.

- [ ] **Step 3: Implement registration against Hades 0.17 signatures**

Use `ctx.register_skill(name="lab-pentest", path=<SKILL.md path>)`; Hades adds
the `ariadne:` namespace automatically. Register all handlers with
`toolset="ariadne"`, `is_async=True`, `override=False`.

The skill must:

- display the authorization disclaimer before collecting operational details;
- ask one concise contract question at a time;
- call `ariadne_prepare_engagement` only after all answers are explicit;
- direct the user to `/ariadne confirm <challenge>`;
- call only Ariadne tools for target-facing actions;
- stop when a handler reports scope amendment, policy denial, or ambiguity;
- never tell Hades that `--yolo` changes Ariadne policy.

- [ ] **Step 4: Run contract and packaging tests**

Run:

```bash
uv run pytest tests/contract/test_hades_registration.py tests/unit/test_packaging.py -v
uv run ruff check src/ariadne/hades_adapter skills
```

Expected: PASS.

- [ ] **Step 5: Commit native Hades registration**

```bash
git add src/ariadne/composition.py src/ariadne/hades_adapter skills tests/contract
git commit -m "feat: register Ariadne tools and skill with Hades"
```

## Task 9: Implement Interactive Contract Challenges and Direct Approvals

**Files:**
- Create: `src/ariadne/hades_adapter/commands.py`
- Create: `src/ariadne/hades_adapter/session.py`
- Modify: `src/ariadne/hades_adapter/handlers.py`
- Modify: `src/ariadne/composition.py`
- Create: `tests/contract/test_ariadne_command.py`
- Create: `tests/contract/test_engagement_handlers.py`

**Interfaces:**
- Consumes: `RunStore`, snapshot locking, planner, and approval records.
- Produces:
  `AriadneCommand.handle(raw_args: str) -> str`,
  `prepare_engagement(args: dict, **context: object) -> dict`,
  and
  `bind_engagement(args: dict, session_id: str, **context: object) -> dict`.

- [ ] **Step 1: Write failing tests proving models cannot self-confirm**

```python
def test_prepare_returns_challenge_but_does_not_lock(command_service, valid_answers):
    result = command_service.prepare(valid_answers)
    assert result.status == "awaiting_user_confirmation"
    assert not command_service.store.has_snapshot(result.engagement_id)


def test_direct_confirm_locks_then_bind_requires_same_challenge(command, session_id):
    challenge = command.prepare(valid_answers()).challenge_id
    response = command.handle(f"confirm {challenge}")
    assert "confirmed" in response.lower()
    binding = command.bind(challenge, session_id=session_id)
    assert binding.snapshot_hash
```

Also test expired challenge, second use, wrong disclaimer version, stale plan,
scope amendment, install approval, and uncurated-PoC approval.

- [ ] **Step 2: Run command tests and verify direct-confirmation failures**

Run: `uv run pytest tests/contract/test_ariadne_command.py tests/contract/test_engagement_handlers.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement challenge ledger and command grammar**

Supported grammar:

```text
/ariadne new
/ariadne confirm <challenge-id>
/ariadne status
/ariadne plan
/ariadne approve <plan-id>
/ariadne reject <plan-id>
/ariadne amend-scope
/ariadne pause
/ariadne resume
/ariadne abort
/ariadne evidence
/ariadne report
/ariadne doctor
```

Parse with `shlex.split`, reject extra tokens, and render deterministic text.
Challenges are random 128-bit URL-safe values, stored with a canonical payload
digest, type (`contract`, `scope`, `host_install`, `uncurated_poc`), five-minute
expiry, and one-use flag. Approval records set `actor="user"` and are appended
to the event chain.

Session binding occurs only after a direct confirmation and is stored by Hades
`session_id`; the confirmation challenge cannot be supplied to a normal
target-facing tool as an approval substitute.

- [ ] **Step 4: Run all engagement and Hades contract tests**

Run:

```bash
uv run pytest tests/contract tests/unit/test_engagement_snapshot.py -v
uv run ruff check src/ariadne/hades_adapter tests/contract
```

Expected: PASS.

- [ ] **Step 5: Commit interactive approvals**

```bash
git add src/ariadne/hades_adapter src/ariadne/composition.py tests/contract
git commit -m "feat: require direct Ariadne contract approvals"
```

## Task 10: Enforce In-Session Guardrails with `pre_tool_call`

**Files:**
- Create: `src/ariadne/hades_adapter/guard_hook.py`
- Modify: `src/ariadne/hades_adapter/session.py`
- Modify: `src/ariadne/hades_adapter/registration.py`
- Create: `tests/policy/test_guard_hook.py`

**Interfaces:**
- Consumes: Hades hook keyword arguments `tool_name`, `args`, `session_id`,
  `task_id`, `tool_call_id`, `turn_id`, and `api_request_id`.
- Produces:
  `GuardHook.__call__(**payload: object) -> dict[str, str] | None`.

- [ ] **Step 1: Write failing bypass tests**

```python
@pytest.mark.parametrize(
    ("tool_name", "args"),
    [
        ("terminal", {"command": "nmap 10.10.10.10"}),
        ("python", {"code": "subprocess.run(['curl','http://10.10.10.10'])"}),
        ("write_file", {"path": ".../engagement.lock.yaml", "content": "changed"}),
        ("terminal", {"command": "docker exec ariadne-kali nmap target"}),
    ],
)
def test_active_engagement_blocks_generic_execution(guard, tool_name, args):
    result = guard(tool_name=tool_name, args=args, session_id="active")
    assert result is not None
    assert result["action"] == "block"
    assert result["message"]
```

Add positive tests for Ariadne tools, inactive sessions, `/ariadne` status, and
unrelated non-execution tools.

- [ ] **Step 2: Run the guard suite**

Run: `uv run pytest tests/policy/test_guard_hook.py -v`
Expected: FAIL because no hook exists.

- [ ] **Step 3: Implement capability-based hard blocking**

Maintain explicit sets:

```python
ARIADNE_TOOLS = frozenset({
    "ariadne_prepare_engagement",
    "ariadne_bind_engagement",
    "ariadne_status",
    "ariadne_propose_plan",
    "ariadne_execute_plan",
    "ariadne_render_report",
})

GENERIC_EXECUTION_TOOLS = frozenset({
    "terminal",
    "shell",
    "python",
    "computer",
    "write_file",
    "apply_patch",
})
```

For an active Ariadne-bound session, block every generic execution or file
mutation tool rather than attempting to recognize every possible encoding of a
target command. Read-only conversational and retrieval tools remain available.
Block any non-Ariadne tool unknown to the compatibility table if it advertises
execution or mutation metadata. The hook itself does not inspect Hades's
approval mode and therefore remains active under `--yolo`.

- [ ] **Step 4: Run policy, command, and registration tests**

Run: `uv run pytest tests/policy tests/contract -v`
Expected: PASS, including encoded and indirect bypass fixtures.

- [ ] **Step 5: Commit the Hades boundary**

```bash
git add src/ariadne/hades_adapter tests/policy/test_guard_hook.py
git commit -m "feat: block in-session Ariadne guardrail bypasses"
```

## Task 11: Detect the Host and Produce Confirmable Docker Install Proposals

**Files:**
- Create: `src/ariadne/runtime/platform.py`
- Create: `src/ariadne/runtime/preflight.py`
- Create: `src/ariadne/runtime/install.py`
- Create: `tests/unit/test_platform_detection.py`
- Create: `tests/unit/test_docker_install.py`
- Create: `tests/fixtures/preflight/`

**Interfaces:**
- Consumes: `platform.system()`, `platform.machine()`, executable lookup, and
  bounded process probes.
- Produces:
  `detect_host() -> HostPlatform`,
  `DockerPreflight.run() -> PreflightResult`,
  `DockerInstaller.propose(host: HostPlatform) -> InstallProposal`, and
  `DockerInstaller.execute(proposal: InstallProposal, confirmation: Confirmation) -> InstallResult`.

- [ ] **Step 1: Write failing platform and no-implicit-install tests**

```python
def test_apple_silicon_is_normalized() -> None:
    host = detect_host(system="Darwin", machine="arm64")
    assert host.os is HostOS.MACOS
    assert host.arch is Architecture.ARM64
    assert host.docker_platform == "linux/arm64"


def test_install_requires_matching_direct_confirmation(installer, mac_host):
    proposal = installer.propose(mac_host)
    with pytest.raises(ConfirmationRequired):
        installer.execute(proposal, confirmation=None)
```

Cover Linux `x86_64`/`aarch64`, Windows AMD64/ARM64, unknown architecture,
missing package manager, stopped Docker daemon, low disk, and failed probe.

- [ ] **Step 2: Run runtime discovery tests**

Run: `uv run pytest tests/unit/test_platform_detection.py tests/unit/test_docker_install.py -v`
Expected: FAIL because runtime modules are absent.

- [ ] **Step 3: Implement safe proposals and execution**

`InstallProposal` contains exact argument vectors, documentation URL, privilege
requirement, approximate effects, reboot/relogin note, and canonical digest.
Curated proposals are:

```python
MACOS_BREW = (("brew", "install", "--cask", "docker"),)
WINDOWS_WINGET = ((
    "winget", "install", "--id", "Docker.DockerDesktop", "--exact",
    "--accept-source-agreements", "--accept-package-agreements",
),)
```

For Linux, first query the configured package manager without changing it.
Only propose `apt-get install docker-ce docker-ce-cli containerd.io
docker-buildx-plugin docker-compose-plugin` or the equivalent DNF packages when
those packages already have candidates from a configured Docker repository.
For Arch, propose the distribution `docker` and `docker-compose` packages.
Never pipe remote scripts into a shell and never auto-add a repository. If no
curated package is available, return the official Docker documentation URL and
stop for manual setup.

Before execution, recompute and compare the proposal digest to the directly
confirmed challenge. Run each argv independently and stop on the first failure.

- [ ] **Step 4: Run runtime tests with a fake process probe**

Run:

```bash
uv run pytest tests/unit/test_platform_detection.py tests/unit/test_docker_install.py -v
uv run ruff check src/ariadne/runtime tests/unit
```

Expected: PASS without invoking the real package manager.

- [ ] **Step 5: Commit host bootstrap planning**

```bash
git add src/ariadne/runtime tests/unit tests/fixtures/preflight
git commit -m "feat: add confirmable Docker host bootstrap"
```

## Task 12: Build the Pinned Kali, ZAP, and Netguard Container Stack

**Files:**
- Create: `containers/kali/Dockerfile`
- Create: `containers/netguard/entrypoint.sh`
- Create: `containers/compose.yaml`
- Create: `containers/image-lock.yaml`
- Create: `containers/tool-manifest.yaml`
- Create: `src/ariadne/runtime/docker.py`
- Create: `src/ariadne/runtime/network_policy.py`
- Create: `tests/contract/test_container_manifests.py`
- Create: `tests/integration/test_netguard.py`

**Interfaces:**
- Consumes: confirmed target resolutions and Docker preflight.
- Produces:
  `DockerRuntime.prepare(snapshot: EngagementSnapshot) -> RuntimeHandle`,
  `DockerRuntime.exec(service: str, argv: tuple[str, ...], limits: ProcessLimits) -> ProcessResult`,
  and
  `DockerRuntime.destroy(handle: RuntimeHandle) -> None`.

- [ ] **Step 1: Write failing manifest and egress tests**

```python
def test_compose_shares_netguard_namespace() -> None:
    compose = yaml.safe_load(Path("containers/compose.yaml").read_text())
    assert compose["services"]["kali"]["network_mode"] == "service:netguard"
    assert compose["services"]["zap"]["network_mode"] == "service:netguard"
    assert compose["services"]["netguard"]["cap_add"] == ["NET_ADMIN"]
    assert "NET_ADMIN" not in compose["services"]["kali"].get("cap_add", [])


@pytest.mark.integration
def test_netguard_allows_target_and_blocks_neighbor(runtime, target_fixture):
    assert runtime.tcp_connect(target_fixture.allowed_host, 8080)
    assert not runtime.tcp_connect(target_fixture.blocked_neighbor, 8080)
```

- [ ] **Step 2: Verify the container stack is absent**

Run: `uv run pytest tests/contract/test_container_manifests.py -v`
Expected: FAIL because the Compose file does not exist.

- [ ] **Step 3: Implement pinned images and shared network namespace**

Use build arguments `KALI_BASE_REF` and `ZAP_IMAGE_REF` populated only from
`image-lock.yaml`. The lock records image, digest, platform, retrieval time,
and upstream documentation URL. `Dockerfile` installs
`kali-linux-headless` plus the exact packages in `tool-manifest.yaml`, clears
APT lists, creates an unprivileged `ariadne` user, and contains no PoC download.

`netguard` owns `NET_ADMIN`; Kali and ZAP share its network namespace. Its
entrypoint:

1. flushes its dedicated nftables table;
2. allows established traffic, loopback, Docker DNS, and only resolved
   confirmed target addresses/ports;
3. applies explicit rate ceilings;
4. logs denied destinations without payloads;
5. drops all remaining egress.

Mount run directories read/write only where evidence is expected. Mount
engagement snapshots read-only. Do not mount the Docker socket into any
container.

- [ ] **Step 4: Build and run isolated container tests**

Run:

```bash
docker compose -f containers/compose.yaml config
uv run pytest tests/contract/test_container_manifests.py -v
uv run pytest tests/integration/test_netguard.py -v -m integration
```

Expected: Compose validates; allowed fixture connects; blocked neighbor and
public Internet destinations fail.

- [ ] **Step 5: Commit the execution environment**

```bash
git add containers src/ariadne/runtime tests/contract tests/integration/test_netguard.py
git commit -m "feat: add allowlisted Kali and ZAP runtime"
```

## Task 13: Implement the Bounded Process Runner and Adapter SDK

**Files:**
- Create: `src/ariadne/runtime/process.py`
- Create: `src/ariadne/adapters/base.py`
- Create: `tests/unit/test_process_runner.py`
- Create: `tests/contract/test_adapter_contract.py`

**Interfaces:**
- Consumes: Docker runtime or host diagnostic execution.
- Produces:
  `ProcessRunner.run(spec: ProcessSpec) -> ProcessResult` and
  `ToolAdapter` protocol methods `probe`, `plan`, `execute`, `parse`,
  `classify`, `collect`, and `cleanup`.

- [ ] **Step 1: Write failing timeout, output-bound, and argv tests**

```python
@pytest.mark.asyncio
async def test_runner_kills_process_group_on_timeout(runner):
    result = await runner.run(ProcessSpec(
        argv=("python", "-c", "import time; time.sleep(60)"),
        timeout_seconds=1,
        max_output_bytes=1024,
    ))
    assert result.status is ProcessStatus.TIMED_OUT
    assert result.process_tree_terminated


def test_process_spec_rejects_shell_command() -> None:
    with pytest.raises(ValidationError):
        ProcessSpec(argv=("sh", "-c", "nmap target"))
```

- [ ] **Step 2: Run runner and adapter-contract tests**

Run: `uv run pytest tests/unit/test_process_runner.py tests/contract/test_adapter_contract.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement process and adapter contracts**

```python
class ProcessSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    argv: tuple[str, ...]
    cwd: Path | None = None
    environment: Mapping[str, str] = Field(default_factory=dict)
    timeout_seconds: int = Field(ge=1, le=3600)
    max_output_bytes: int = Field(ge=1024, le=100_000_000)
    stdin: bytes | None = None


class ToolAdapter(Protocol):
    name: ClassVar[str]
    async def probe(self, runtime: Runtime) -> ToolProbe: ...
    def plan(self, action: PlannedAction, context: AdapterContext) -> ProcessSpec: ...
    async def execute(self, spec: ProcessSpec, runtime: Runtime) -> ProcessResult: ...
    def parse(self, result: ProcessResult) -> tuple[Observation, ...]: ...
    def classify(self, result: ProcessResult, observations: tuple[Observation, ...]) -> ExecutionClassification: ...
    async def collect(self, result: ProcessResult, collector: EvidenceCollector) -> tuple[str, ...]: ...
    async def cleanup(self, context: AdapterContext) -> CleanupResult: ...
```

Reject executable names outside the adapter's declared allowlist, embedded NUL,
`sh -c`, `bash -c`, PowerShell encoded commands, and environment keys not
declared by the adapter. Drain stdout/stderr concurrently, truncate only after
writing the bounded evidence record, and terminate the complete process group.

- [ ] **Step 4: Run process, type, and lint checks**

Run:

```bash
uv run pytest tests/unit/test_process_runner.py tests/contract/test_adapter_contract.py -v
uv run ruff check src/ariadne/runtime/process.py src/ariadne/adapters
uv run ty check src/ariadne/runtime/process.py src/ariadne/adapters
```

Expected: PASS.

- [ ] **Step 5: Commit the adapter foundation**

```bash
git add src/ariadne/runtime/process.py src/ariadne/adapters tests/unit/test_process_runner.py tests/contract/test_adapter_contract.py
git commit -m "feat: add bounded tool adapter runtime"
```

## Task 14: Add Nmap and httpx Discovery Adapters

**Files:**
- Create: `src/ariadne/adapters/nmap.py`
- Create: `src/ariadne/adapters/httpx.py`
- Create: `tests/contract/test_nmap_adapter.py`
- Create: `tests/contract/test_httpx_adapter.py`
- Create: `tests/fixtures/nmap/`
- Create: `tests/fixtures/httpx/`

**Interfaces:**
- Consumes: `PlannedAction(operation, inputs)`, `AdapterContext`, and bounded
  process results.
- Produces typed `network.port`, `service.fingerprint`, `http.endpoint`, and
  `web.technology_fingerprint` observations.

- [ ] **Step 1: Write failing command-builder and parser tests**

```python
def test_nmap_plan_uses_xml_stdout_and_explicit_target(context):
    spec = NmapAdapter().plan(
        action("tcp_discovery", ports=(22, 80, 443)),
        context(target="10.10.10.10"),
    )
    assert spec.argv == (
        "nmap", "-n", "-Pn", "-sS", "--max-rate", "100",
        "-p", "22,80,443", "-oX", "-", "--", "10.10.10.10",
    )


def test_httpx_parser_emits_endpoint(load_fixture):
    observations = HttpxAdapter().parse(load_fixture("httpx/https.jsonl"))
    assert observations[0].type == "http.endpoint"
    assert observations[0].data["url"] == "https://10.10.10.10/"
```

Include malformed XML, a DTD/entity fixture, incomplete JSONL, IPv6, unknown
service, timeout, and output limit.

- [ ] **Step 2: Run adapter tests**

Run: `uv run pytest tests/contract/test_nmap_adapter.py tests/contract/test_httpx_adapter.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement safe builders and parsers**

Nmap operations are `tcp_discovery`, `service_fingerprint`, and
`udp_targeted`. SYN scan requires the runtime's declared `NET_RAW` capability;
otherwise use `-sT`. The parser rejects any XML containing `<!DOCTYPE` or
`<!ENTITY` before using `xml.etree.ElementTree`.

httpx receives targets through a bounded stdin file, outputs JSONL, disables
automatic probing of unrelated hostnames, and records redirects as new
observations. A redirect to an unconfirmed host is marked `observed_only` and
is not followed.

- [ ] **Step 4: Run adapter and policy suites**

Run:

```bash
uv run pytest tests/contract/test_nmap_adapter.py tests/contract/test_httpx_adapter.py tests/policy -v
uv run ruff check src/ariadne/adapters tests/contract
```

Expected: PASS.

- [ ] **Step 5: Commit baseline discovery**

```bash
git add src/ariadne/adapters tests/contract tests/fixtures/nmap tests/fixtures/httpx
git commit -m "feat: add typed Nmap and httpx discovery"
```

## Task 15: Add ZAP, Nuclei, Content Discovery, and Screenshot Adapters

**Files:**
- Create: `src/ariadne/adapters/zap.py`
- Create: `src/ariadne/adapters/nuclei.py`
- Create: `src/ariadne/adapters/screenshot.py`
- Create: `tests/contract/test_zap_adapter.py`
- Create: `tests/contract/test_nuclei_adapter.py`
- Create: `tests/contract/test_screenshot_adapter.py`
- Create: `tests/fixtures/zap/`
- Create: `tests/fixtures/nuclei/`

**Interfaces:**
- Consumes: confirmed HTTP endpoints, web policy limits, and curated template
  catalog.
- Produces `web.endpoint`, `web.parameter`, `web.alert_candidate`,
  `web.template_match_candidate`, HTTP transcript, and screenshot evidence.

- [ ] **Step 1: Write failing active-scan and scope-boundary tests**

```python
def test_zap_plan_contains_only_confirmed_context(zap, web_context):
    plan = zap.automation_plan(web_context)
    assert plan["env"]["contexts"][0]["urls"] == ["https://10.10.10.10"]
    assert plan["env"]["contexts"][0]["includePaths"] == [
        r"https://10\.10\.10\.10/.*"
    ]


def test_nuclei_rejects_unlocked_template_directory(adapter, context):
    with pytest.raises(AdapterPolicyError):
        adapter.plan(action("scan", template_dir="/tmp/download"), context)
```

- [ ] **Step 2: Run web adapter tests**

Run: `uv run pytest tests/contract/test_zap_adapter.py tests/contract/test_nuclei_adapter.py tests/contract/test_screenshot_adapter.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement deterministic web plans**

ZAP uses an Automation Framework YAML file generated from the action plan,
context regex, request rate, maximum duration, authentication settings, passive
scan, spider/AJAX spider, and optional active scan. Treat ZAP alerts as
candidates.

Nuclei accepts only template IDs and workflow IDs present in the pinned
`tool-manifest.yaml`; record the template repository commit. Feroxbuster,
ffuf, and Katana are represented as operations in the same module or as small
neighbor adapters, each with rate, depth, wordlist digest, and redirect
boundaries.

The screenshot adapter invokes pinned Chromium headless with a fresh temporary
profile, confirmed URL, fixed viewport, maximum load time, and output path
inside the run evidence mount. It records URL, timestamp, browser version, and
SHA-256.

- [ ] **Step 4: Run contract tests and validate generated ZAP YAML**

Run:

```bash
uv run pytest tests/contract/test_zap_adapter.py tests/contract/test_nuclei_adapter.py tests/contract/test_screenshot_adapter.py -v
docker compose -f containers/compose.yaml config
```

Expected: PASS; generated plans contain no out-of-scope URL.

- [ ] **Step 5: Commit web testing adapters**

```bash
git add src/ariadne/adapters tests/contract tests/fixtures/zap tests/fixtures/nuclei
git commit -m "feat: add policy-bounded web adapters"
```

## Task 16: Implement CVE, Exploit-DB, Metasploit, and PoC Provenance

**Files:**
- Create: `src/ariadne/adapters/research.py`
- Create: `src/ariadne/adapters/metasploit.py`
- Create: `src/ariadne/core/research.py`
- Create: `tests/contract/test_research_pipeline.py`
- Create: `tests/contract/test_metasploit_adapter.py`
- Create: `tests/policy/test_uncurated_poc.py`
- Create: `tests/fixtures/research/`

**Interfaces:**
- Consumes: exact service fingerprint and network-research policy.
- Produces:
  `ResearchPipeline.investigate(fingerprint: ServiceFingerprint) -> ResearchDossier`,
  `MetasploitAdapter` observations, and
  `PocProvenance`.

- [ ] **Step 1: Write failing ordering, privacy, and approval tests**

```python
@pytest.mark.asyncio
async def test_research_order_and_query_minimization(pipeline, fingerprint):
    dossier = await pipeline.investigate(fingerprint)
    assert dossier.sources_attempted == (
        "local-searchsploit", "vendor", "nvd", "cisa-kev",
        "metasploit", "public-poc-index",
    )
    assert fingerprint.target_host not in pipeline.network_queries


def test_uncurated_poc_cannot_form_executable_action_without_confirmation():
    with pytest.raises(ConfirmationRequired):
        authorize_poc(uncurated_poc(), confirmation=None)
```

- [ ] **Step 2: Run research and PoC tests**

Run: `uv run pytest tests/contract/test_research_pipeline.py tests/contract/test_metasploit_adapter.py tests/policy/test_uncurated_poc.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement source adapters and provenance**

Normalize online queries to product, version, protocol, and candidate CVE only.
Never include target address, domain, credential, captured content, or evidence.
Record source URL, retrieval time, author/owner, license, release/tag/commit,
file digest, curation status, and review decision.

Metasploit operations are separate: `search`, `info`, `check`, and
`run_module`. `run_module` cannot be planned from a scanner candidate alone;
it requires an exact module record, compatible fingerprint, eligible
capability, expected effect, cleanup, and bounded plan. Generate a resource file
inside the run directory with one command per line from validated tokens and
invoke `msfconsole -q -r <resource-file>`. Reject semicolons/newlines inside
tokens, resource files outside the run directory, and console commands outside
the exact operation template.

Uncurated PoC bytes are quarantined under the run, mode `0600`, never imported
into the Hades process, and executed only in the Kali container after direct
challenge confirmation.

- [ ] **Step 4: Run research, policy, and adapter tests**

Run:

```bash
uv run pytest tests/contract/test_research_pipeline.py tests/contract/test_metasploit_adapter.py tests/policy/test_uncurated_poc.py -v
uv run ruff check src/ariadne/core/research.py src/ariadne/adapters
```

Expected: PASS, with an explicit `source_limitations` record when offline.

- [ ] **Step 5: Commit evidence-driven exploit research**

```bash
git add src/ariadne/core/research.py src/ariadne/adapters tests/contract tests/policy/test_uncurated_poc.py tests/fixtures/research
git commit -m "feat: add provenance-aware vulnerability research"
```

## Task 17: Add Linux and Windows Post-Exploitation Adapters

**Files:**
- Create: `src/ariadne/adapters/postex.py`
- Create: `tests/contract/test_linux_postex.py`
- Create: `tests/contract/test_windows_postex.py`
- Create: `tests/policy/test_payload_upload.py`
- Create: `tests/fixtures/postex/`
- Modify: `containers/tool-manifest.yaml`

**Interfaces:**
- Consumes: a validated foothold, explicit post-exploitation capabilities, and
  curated tool artifacts.
- Produces `host.identity`, `host.privilege`, `privesc.candidate`,
  `credential.material_candidate`, and cleanup records.

- [ ] **Step 1: Write failing targeted-mode and upload-policy tests**

```python
def test_linpeas_default_plan_is_not_aggressive(adapter, linux_context):
    spec = adapter.plan(action("linpeas"), linux_context)
    assert "-a" not in spec.argv
    assert spec.timeout_seconds <= 900


def test_windows_tool_upload_requires_capability(adapter, windows_context):
    windows_context.policy = deny("exploit.payload_upload")
    with pytest.raises(AdapterPolicyError):
        adapter.plan(action("winpeas"), windows_context)
```

Add tests for pspy duration, sudo/SUID/capability checks, PrivescCheck,
Seatbelt, unknown binary hash, credential redaction, and cleanup after a
partially failed upload.

- [ ] **Step 2: Run post-exploitation contract tests**

Run: `uv run pytest tests/contract/test_linux_postex.py tests/contract/test_windows_postex.py tests/policy/test_payload_upload.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement curated post-exploitation operations**

Linux operations:

```text
identity
sudo_rules
suid_files
file_capabilities
scheduled_jobs
services
linpeas_standard
pspy_bounded
```

Windows operations:

```text
identity
token_privileges
services
scheduled_tasks
registry
winpeas_standard
privesccheck
seatbelt_selected
```

Curated binary metadata includes upstream release URL, version, SHA-256,
license, supported architecture, and local container path. Target upload uses
a randomized path under the target's temporary directory, records the remote
digest where possible, and always emits a cleanup action. Findings remain
candidates until a manual check or bounded exploitation validates impact.

- [ ] **Step 4: Run post-exploitation and cleanup suites**

Run:

```bash
uv run pytest tests/contract/test_linux_postex.py tests/contract/test_windows_postex.py tests/policy/test_payload_upload.py -v
uv run ruff check src/ariadne/adapters/postex.py
```

Expected: PASS.

- [ ] **Step 5: Commit bounded post-exploitation**

```bash
git add src/ariadne/adapters/postex.py containers/tool-manifest.yaml tests/contract tests/policy/test_payload_upload.py tests/fixtures/postex
git commit -m "feat: add curated post-exploitation adapters"
```

## Task 18: Add Active Directory and Pivot Lifecycle Adapters

**Files:**
- Create: `src/ariadne/adapters/active_directory.py`
- Create: `src/ariadne/adapters/pivot.py`
- Create: `tests/contract/test_active_directory_adapter.py`
- Create: `tests/contract/test_pivot_adapter.py`
- Create: `tests/policy/test_ad_high_impact.py`
- Create: `tests/policy/test_scope_amendment.py`
- Create: `tests/fixtures/active_directory/`
- Create: `tests/fixtures/pivot/`

**Interfaces:**
- Consumes: domain evidence, credential references, AD capabilities, foothold,
  and confirmed scope.
- Produces typed domain/identity/relationship observations, tunnel lifecycle
  records, and `observed_only` assets.

- [ ] **Step 1: Write failing AD capability and pivot-scope tests**

```python
def test_certipy_find_is_separate_from_abuse(adapter, ad_context):
    find = adapter.plan(action("certipy_find"), ad_context)
    assert "find" in find.argv
    with pytest.raises(AdapterPolicyError):
        adapter.plan(action("certipy_relay"), ad_context)


def test_pivot_discovery_never_expands_scope(adapter, pivot_context):
    observations = adapter.parse(load_fixture("pivot/discovered-host.json"))
    assert observations[0].asset_status is AssetStatus.OBSERVED_ONLY
    with pytest.raises(ScopeAmendmentRequired):
        adapter.plan(action("scan_discovered_host"), pivot_context)
```

Cover NetExec authentication limits, Kerbrute lockout budget, Impacket
operations, BloodHound collection scope, Certipy discovery, credential dumping,
Responder/relay denial, tunnel timeout, process death, and cleanup.

- [ ] **Step 2: Run AD and pivot tests**

Run: `uv run pytest tests/contract/test_active_directory_adapter.py tests/contract/test_pivot_adapter.py tests/policy/test_ad_high_impact.py tests/policy/test_scope_amendment.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement explicit operation catalogs**

AD discovery operations:

```text
domain_discovery
ldap_rootdse
smb_enumeration
kerberos_user_validation
bloodhound_collection
certipy_find
```

High-impact operations each receive their own capability:

```text
ad.password_spray
ad.credential_dump
ad.ntlm_poisoning
ad.ntlm_relay
ad.ticket_manipulation
ad.object_modification
ad.adcs_abuse
```

Do not place them under a generic `ad.attack` switch. Password attempts must
respect the minimum of contract budget, detected domain lockout threshold
minus safety margin, and playbook limit.

Pivot operations are `start_tunnel`, `add_route`, `remove_route`, and
`stop_tunnel`. Store PID/session ID, local route, remote endpoint, expiry, and
cleanup result. Ligolo-ng is primary; Chisel and SSH are explicit fallbacks.
No route is added for an unconfirmed network.

- [ ] **Step 4: Run contract, policy, and state-machine tests**

Run:

```bash
uv run pytest tests/contract/test_active_directory_adapter.py tests/contract/test_pivot_adapter.py tests/policy tests/unit/test_state_machine.py -v
uv run ruff check src/ariadne/adapters/active_directory.py src/ariadne/adapters/pivot.py
```

Expected: PASS.

- [ ] **Step 5: Commit AD and pivot lifecycle**

```bash
git add src/ariadne/adapters tests/contract tests/policy tests/fixtures/active_directory tests/fixtures/pivot
git commit -m "feat: add explicit AD and pivot capabilities"
```

## Task 19: Author the Versioned Workflow Catalog

**Files:**
- Create: `workflows/base.yaml`
- Create: `workflows/web.yaml`
- Create: `workflows/linux.yaml`
- Create: `workflows/windows.yaml`
- Create: `workflows/active-directory.yaml`
- Create: `workflows/pivoting.yaml`
- Create: `tests/contract/test_builtin_workflows.py`
- Create: `tests/fixtures/scenarios/`

**Interfaces:**
- Consumes: every registered adapter operation and the workflow schema.
- Produces a complete graph from preflight through objective validation,
  cleanup, and reporting.

- [ ] **Step 1: Write failing graph-completeness tests**

```python
def test_every_action_names_a_registered_adapter_operation(catalog, registry):
    for playbook in catalog.playbooks:
        for action in playbook.actions:
            assert registry.supports(action.adapter, action.operation)


def test_every_nonterminal_playbook_has_reachable_next_state(catalog):
    unreachable = catalog.unreachable_from("engagement.preflight.v1")
    assert unreachable == set()
```

Also assert every invasive playbook has cleanup, limits, evidence requirements,
stop conditions, and report mapping; every AD high-impact operation requires
its exact capability; no playbook targets an `observed_only` asset.

- [ ] **Step 2: Run built-in workflow validation**

Run: `uv run pytest tests/contract/test_builtin_workflows.py -v`
Expected: FAIL because built-in workflows are absent.

- [ ] **Step 3: Write the complete built-in graph**

Required base sequence:

```text
engagement.preflight.v1
network.tcp-discovery.v1
network.service-fingerprint.v1
service.protocol-routing.v1
research.service-vulnerability.v1
validation.bounded-check.v1
foothold.confirmation.v1
postex.host-enumeration.v1
privesc.hypothesis-ranking.v1
objective.validation.v1
cleanup.verify.v1
report.render.v1
```

Add protocol branches for DNS, HTTP/S, SSH, FTP, SMTP, SMB/RPC, LDAP,
Kerberos, WinRM, RDP, SNMP, databases, and unknown services. Unknown services
terminate in passive research/manual-plan state, not arbitrary execution.

Web branches cover fingerprint, crawl, content discovery, passive ZAP, selected
Nuclei, evidence-driven specialist testing, optional active ZAP, validation,
and report mapping. Linux, Windows, AD, and pivot workflows use the operations
defined in Tasks 17-18.

- [ ] **Step 4: Validate schema, reachability, and representative scenarios**

Run:

```bash
uv run pytest tests/contract/test_builtin_workflows.py tests/unit/test_workflow_catalog.py tests/unit/test_planner.py -v
uv run python -m ariadne.core.workflow validate workflows
```

Expected: PASS with no dangling playbook, adapter, capability, or report
section.

- [ ] **Step 5: Commit deterministic workflows**

```bash
git add workflows tests/contract/test_builtin_workflows.py tests/fixtures/scenarios
git commit -m "feat: add Ariadne pentest workflow graph"
```

## Task 20: Implement Evidence Collection and Finding Validation

**Files:**
- Create: `src/ariadne/evidence/records.py`
- Create: `src/ariadne/evidence/collector.py`
- Create: `src/ariadne/evidence/findings.py`
- Create: `src/ariadne/evidence/redaction.py`
- Create: `src/ariadne/evidence/cvss.py`
- Create: `tests/unit/test_evidence_collector.py`
- Create: `tests/unit/test_finding_service.py`
- Create: `tests/unit/test_redaction.py`
- Create: `tests/unit/test_cvss.py`

**Interfaces:**
- Consumes: process results, native tool outputs, screenshots, observations, and
  action metadata.
- Produces:
  `EvidenceCollector.collect(...) -> StoredEvidence`,
  `FindingService.candidate(...) -> Finding`,
  and
  `FindingService.validate(finding_id: str, evidence_ids: tuple[str, ...]) -> Finding`.

- [ ] **Step 1: Write failing provenance, validation, and redaction tests**

```python
def test_evidence_records_full_provenance(collector, process_result):
    item = collector.collect_process(process_result, evidence_context())
    assert item.sha256
    assert item.tool_version == "nmap 7.95"
    assert item.snapshot_hash
    assert item.plan_id
    assert item.command_redacted[-1] == "10.10.10.10"


def test_scanner_alert_cannot_be_marked_validated_without_proof(service):
    candidate = service.candidate(scanner_alert())
    with pytest.raises(FindingValidationError):
        service.validate(candidate.id, evidence_ids=())
```

Add tests for URL credential redaction, Authorization headers, cookies, API
keys, passwords, NTLM hashes, private keys, flags, transformed-image lineage,
and redaction false positives.

- [ ] **Step 2: Run evidence tests**

Run: `uv run pytest tests/unit/test_evidence_collector.py tests/unit/test_finding_service.py tests/unit/test_redaction.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement immutable evidence and finding gates**

`EvidenceRecord` stores stable ID, snapshot hash, UTC timestamp, asset/service/
URL/identity, playbook, adapter, tool/version, plan ID, redacted argv, exit and
parser status, SHA-256, confidence, provenance, and parent artifact ID.

The collector preserves original bytes and creates a new related artifact for
crop, annotation, or redaction. It never overwrites originals.

Finding validation requires evidence types declared by the producing playbook.
Only `validated` and `exploited` enter the vulnerability summary. CVE is
optional. CVSS vector and numeric score must be recalculated and agree; use a
small internal CVSS 3.1 calculator with published vector tests rather than a
new runtime dependency.

- [ ] **Step 4: Run evidence, store, and finding tests**

Run:

```bash
uv run pytest tests/unit/test_evidence_collector.py tests/unit/test_finding_service.py tests/unit/test_redaction.py tests/unit/test_cvss.py tests/unit/test_run_store.py tests/unit/test_integrity.py -v
uv run ruff check src/ariadne/evidence
```

Expected: PASS.

- [ ] **Step 5: Commit the evidence dossier**

```bash
git add src/ariadne/evidence tests/unit
git commit -m "feat: validate findings from immutable evidence"
```

## Task 21: Render the Technical and Professional Reports

**Files:**
- Create: `src/ariadne/reporting/validation.py`
- Create: `src/ariadne/reporting/walkthrough.py`
- Create: `src/ariadne/reporting/professional.py`
- Create: `src/ariadne/reporting/pdf.py`
- Create: `report_templates/walkthrough/index.md.j2`
- Create: `report_templates/professional/index.html.j2`
- Create: `report_templates/professional/styles.css`
- Create: `tests/unit/test_report_validation.py`
- Create: `tests/golden/test_report_golden.py`
- Create: `tests/golden/walkthrough/`
- Create: `tests/golden/professional/`

**Interfaces:**
- Consumes: a verified run dossier.
- Produces:
  `ReportValidator.validate(run: RunHandle, options: ReportOptions) -> ValidationResult`,
  `WalkthroughRenderer.render(...) -> RenderedReport`,
  `ProfessionalRenderer.render(...) -> RenderedReport`, and
  `PdfExporter.export(html: Path, destination: Path) -> Path`.

- [ ] **Step 1: Write failing quality-gate and golden-output tests**

```python
@pytest.mark.parametrize(
    "broken_fixture",
    [
        "missing-snapshot",
        "finding-without-evidence",
        "missing-image",
        "bad-hash",
        "out-of-scope-asset",
        "objective-without-proof",
        "secret-leak",
        "missing-remediation",
    ],
)
def test_report_validation_fails_closed(load_run, broken_fixture):
    assert not ReportValidator().validate(load_run(broken_fixture), default_options()).valid


def test_professional_report_contains_required_sections(valid_run):
    html = ProfessionalRenderer().render(valid_run, default_options()).text
    for heading in REQUIRED_PROFESSIONAL_SECTIONS:
        assert heading in html
```

- [ ] **Step 2: Run report tests**

Run: `uv run pytest tests/unit/test_report_validation.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement both renderers from one dossier**

Walkthrough sections: scope, environment, discovery, enumeration, hypotheses,
discarded alternatives, initial access, post-exploitation, privilege
escalation, AD/pivoting, objectives/flags, cleanup, lessons, and reproducible
commands.

Professional sections: classification/version, contacts/disclaimer, executive
summary, objectives/scope/limitations, methodology, risk summary, finding
table, compromise narrative, technical findings, immediate/short/long
remediation, compromised hosts/users, objective evidence, cleanup, and scoring
appendices.

Use Jinja autoescape for HTML. Copy referenced evidence by digest to an export
directory; do not embed local absolute paths. Flag/secret inclusion defaults to
false and requires a report option backed by direct user confirmation.

PDF export runs pinned Chromium in the Kali/report container with
`--headless --disable-gpu --no-pdf-header-footer --print-to-pdf=<path>`;
validate `%PDF-` signature, nonzero page count, and digest.

- [ ] **Step 4: Run golden tests and render a sample PDF**

Run:

```bash
uv run pytest tests/unit/test_report_validation.py tests/golden -v
uv run python -m ariadne.reporting.professional tests/fixtures/runs/valid --output /tmp/ariadne-report
```

Expected: Markdown, standalone HTML, and PDF are generated; golden normalized
HTML matches.

- [ ] **Step 5: Commit offline reporting**

```bash
git add src/ariadne/reporting report_templates tests/unit/test_report_validation.py tests/golden
git commit -m "feat: render Ariadne walkthrough and professional report"
```

## Task 22: Add SysReptor Offline, Preview, and Explicit Push Modes

**Files:**
- Create: `src/ariadne/reporting/sysreptor.py`
- Create: `report_templates/sysreptor/mapping.yaml`
- Create: `tests/contract/test_sysreptor_bundle.py`
- Create: `tests/contract/test_sysreptor_push.py`
- Create: `tests/fixtures/sysreptor/`

**Interfaces:**
- Consumes: validated report model, destination URL, project reference, and
  credential supplied at execution time.
- Produces:
  `SysReptorExporter.offline(report: ReportModel) -> Bundle`,
  `SysReptorExporter.preview(bundle: Bundle) -> Preview`, and
  `SysReptorExporter.push(bundle: Bundle, approval: Confirmation) -> PushResult`.

- [ ] **Step 1: Write failing bundle and no-background-push tests**

```python
def test_offline_bundle_contains_findings_and_relative_assets(exporter, report):
    bundle = exporter.offline(report)
    assert bundle.manifest.finding_count == len(report.findings)
    assert all(not path.is_absolute() for path in bundle.manifest.assets)


@pytest.mark.asyncio
async def test_push_requires_destination_preview_and_confirmation(exporter, bundle):
    with pytest.raises(ConfirmationRequired):
        await exporter.push(bundle, approval=None)
```

Also assert API tokens never appear in events, evidence, bundle, or rendered
report and that a server-side validation failure leaves the local dossier
unchanged.

- [ ] **Step 2: Run SysReptor tests**

Run: `uv run pytest tests/contract/test_sysreptor_bundle.py tests/contract/test_sysreptor_push.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement three explicit modes**

The offline ZIP contains a versioned manifest, project metadata, report
sections, finding JSON, relative evidence assets, and SHA-256 checksums.
Preview validates the mapping and returns destination, project, object counts,
and data categories without sending them.

Push accepts the API token only through the process environment or an injected
secret provider, compares bundle digest and preview digest with a direct
confirmation challenge, uses bounded HTTP timeouts, and records only response
IDs/status. No retry may create a second project without an idempotency key.

- [ ] **Step 4: Run contract tests with a local fake SysReptor server**

Run:

```bash
uv run pytest tests/contract/test_sysreptor_bundle.py tests/contract/test_sysreptor_push.py -v
uv run ruff check src/ariadne/reporting/sysreptor.py
```

Expected: PASS; network calls target only the local fixture server.

- [ ] **Step 5: Commit SysReptor integration**

```bash
git add src/ariadne/reporting/sysreptor.py report_templates/sysreptor tests/contract tests/fixtures/sysreptor
git commit -m "feat: add explicit SysReptor export modes"
```

## Task 23: Build Adversarial Integration and End-to-End Gates

**Files:**
- Create: `tests/integration/compose.yaml`
- Create: `tests/integration/fixtures/`
- Create: `tests/e2e/test_authorized_single_target.py`
- Create: `tests/e2e/test_scope_amendment.py`
- Create: `tests/e2e/test_htb_guardrails.py`
- Create: `tests/e2e/test_failure_recovery.py`
- Create: `.github/workflows/ci.yaml`

**Interfaces:**
- Consumes: the complete plugin through its public Hades and Docker boundaries.
- Produces a release gate proving contract, policy, execution, evidence,
  cleanup, and reporting as one system.

- [ ] **Step 1: Write failing end-to-end acceptance tests**

```python
@pytest.mark.e2e
async def test_authorized_target_reaches_reports(hades_fixture, lab_fixture):
    engagement = await hades_fixture.confirm_contract(
        profile="private-lab",
        target=lab_fixture.host,
        objective="proof",
    )
    await hades_fixture.run_until_complete(engagement)
    assert engagement.snapshot_path.is_file()
    assert engagement.walkthrough_path.is_file()
    assert engagement.professional_pdf_path.is_file()
    assert engagement.sysreptor_bundle_path.is_file()
    assert engagement.integrity.valid


@pytest.mark.e2e
async def test_htb_dos_never_reaches_runner(hades_fixture, htb_engagement):
    result = await hades_fixture.request_capability(htb_engagement, "resource.stress")
    assert result.blocked
    assert hades_fixture.runner_calls == []
```

- [ ] **Step 2: Run E2E tests before fixture infrastructure**

Run: `uv run pytest tests/e2e -v -m e2e`
Expected: FAIL because isolated lab fixtures are absent.

- [ ] **Step 3: Implement isolated fixtures and CI**

The integration Compose network provides deterministic DNS, HTTP/HTTPS,
redirect, SSH-banner, SMB/LDAP fixture outputs, authentication limits, one
allowed host, and one discoverable blocked neighbor. It publishes no service
outside loopback. Tests stub high-impact exploitation but exercise real policy,
plan, process, evidence, and cleanup paths.

CI jobs:

```text
lint-type
unit
policy-negative
adapter-contract
integration-linux-amd64
report-golden
```

The CI firewall rejects Internet and external RFC1918 egress during integration
tests. A test fails if any process attempts an undeclared destination.

- [ ] **Step 4: Run the complete release gate**

Run:

```bash
uv run ruff check .
uv run ty check src
uv run pytest tests/unit tests/policy tests/contract -v
uv run pytest tests/integration -v -m integration
uv run pytest tests/e2e -v -m e2e
git diff --check
```

Expected: all commands pass and no external network packet is observed.

- [ ] **Step 5: Commit the adversarial test harness**

```bash
git add tests/integration tests/e2e .github/workflows/ci.yaml
git commit -m "test: gate Ariadne with adversarial end-to-end tests"
```

## Task 24: Document, Package, and Verify the v1 Release

**Files:**
- Create: `README.md`
- Create: `SECURITY.md`
- Create: `LICENSE`
- Create: `docs/architecture.md`
- Create: `docs/operator-guide.md`
- Create: `docs/policy-reference.md`
- Create: `docs/adapter-development.md`
- Modify: `plugin.yaml`
- Modify: `pyproject.toml`
- Create: `tests/contract/test_release_artifact.py`

**Interfaces:**
- Consumes: all v1 functionality and release-gate results.
- Produces an installable Git repository for
  `hades plugins install <owner>/ariadne`.

- [ ] **Step 1: Write a failing release-artifact test**

```python
def test_release_contains_operator_and_security_contracts():
    required = [
        "README.md",
        "SECURITY.md",
        "LICENSE",
        "docs/architecture.md",
        "docs/operator-guide.md",
        "docs/policy-reference.md",
        "docs/adapter-development.md",
    ]
    assert all(Path(path).is_file() for path in required)


def test_release_archive_excludes_runs_secrets_and_caches(release_archive):
    names = set(release_archive.names)
    assert not any(name.startswith("runs/") for name in names)
    assert not any(".env" in name or "__pycache__" in name for name in names)
```

- [ ] **Step 2: Run the release test**

Run: `uv run pytest tests/contract/test_release_artifact.py -v`
Expected: FAIL because operator documentation is incomplete.

- [ ] **Step 3: Write exact operator and security documentation**

README must cover installation, explicit authorized-use disclaimer, `/ariadne`
Q/A, Docker prerequisites, a no-target dry run, report locations, and removal.

`SECURITY.md` must define the enforceable Hades boundary, the separate-terminal
limitation, supported Hades/Python versions, uncurated-PoC policy, disclosure
process, and supply-chain update procedure.

Operator guide must include private-lab and HTB examples, controlled/full
autonomy behavior, scope amendment, pause/abort, cleanup, offline reporting,
and SysReptor preview/push. Policy reference lists every capability and its
default/profile limits. Adapter guide documents the exact protocol from Task
13 and fixture requirements.

- [ ] **Step 4: Perform final verification and local Hades smoke install**

Run:

```bash
uv run ruff check .
uv run ty check src
uv run pytest -v
hades plugins install file:///Users/gabriele/Dev/ariadne
hades plugins list
git status --short
```

Expected: all tests pass; Hades lists enabled plugin `ariadne`, skill
`ariadne:lab-pentest` resolves, `/ariadne doctor` reports no target action, and
the worktree is clean.

- [ ] **Step 5: Tag the reviewed release**

```bash
git add README.md SECURITY.md LICENSE docs plugin.yaml pyproject.toml tests/contract/test_release_artifact.py
git commit -m "docs: prepare Ariadne v1 operator release"
git tag -a v0.1.0 -m "Ariadne v0.1.0"
```

## Final Acceptance Checklist

- [ ] The user selected the environment profile; the agent never inferred it.
- [ ] The legal disclaimer and authorization attestation are stored in the snapshot.
- [ ] One or more explicit objectives are required.
- [ ] Direct confirmation is required for contract, scope, host install, and uncurated PoC.
- [ ] Full autonomy and Hades `--yolo` cannot bypass hard invariants.
- [ ] HTB resource-stress and cross-target attempts are blocked before a runner.
- [ ] New assets are `observed_only` until a new linked snapshot is confirmed.
- [ ] Every executable action comes from a versioned playbook and typed adapter.
- [ ] Every subprocess is bounded and uses argv without shell interpolation.
- [ ] Kali and ZAP use official pinned images adapted to the current architecture.
- [ ] Docker installation is attempted only from a confirmed curated proposal.
- [ ] CVE research covers local Exploit-DB, authoritative sources, Metasploit, and public PoC provenance without leaking target identifiers.
- [ ] Linux, Windows, AD, and pivoting branches enforce distinct capabilities.
- [ ] No persistence or C2 path exists.
- [ ] Every validated/exploited finding has linked immutable evidence.
- [ ] Walkthrough, professional HTML/PDF, and SysReptor bundle derive from the same dossier.
- [ ] SysReptor push is previewed, directly approved, bounded, and secret-safe.
- [ ] Unit, property, negative-policy, contract, integration, and E2E gates pass.
- [ ] HexStrike is absent from runtime dependencies and roadmap.

## Primary Implementation References

### Hades and skill integration

- Hades 0.17 local plugin API:
  `~/.hermes/hermes-agent/hermes_cli/plugins.py`
- Hades plugin installer:
  `~/.hermes/hermes-agent/hermes_cli/plugins_cmd.py`
- [Agent Skills specification](https://github.com/agentskills/agentskills)

### Methodology and platform rules

- [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/)
- [Hack The Box platform rules](https://help.hackthebox.com/en/articles/12325897-hack-the-box-platform-rules)

### Containers and web testing

- [Official Kali Docker images](https://www.kali.org/docs/containers/official-kalilinux-docker-images/)
- [Kali metapackages](https://www.kali.org/docs/general-use/metapackages/)
- [Docker host networking](https://docs.docker.com/engine/network/drivers/host/)
- [OWASP ZAP Docker images](https://www.zaproxy.org/docs/docker/about/)
- [OWASP ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/)
- [Nuclei workflows](https://docs.projectdiscovery.io/templates/workflows/overview)
- [Nuclei running documentation](https://docs.projectdiscovery.io/opensource/nuclei/running)

### Vulnerability and exploit research

- [NIST National Vulnerability Database](https://nvd.nist.gov/)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Exploit-DB SearchSploit manual](https://www.exploit-db.com/documentation/Offsec-SearchSploit.pdf)
- [Metasploit appropriate module use](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-a-metasploit-module-appropriately.html)

### Windows, Active Directory, and post-exploitation

- [Impacket](https://github.com/fortra/impacket)
- [NetExec](https://github.com/Pennyw0rth/NetExec)
- [SharpHound Community Edition](https://bloodhound.specterops.io/collect-data/ce-collection/sharphound)
- [Certipy](https://github.com/ly4k/Certipy)
- [PEASS-ng](https://github.com/peass-ng/PEASS-ng)
- [pspy](https://github.com/DominicBreuker/pspy)
- [PrivescCheck](https://github.com/itm4n/PrivescCheck)
- [Seatbelt](https://github.com/GhostPack/Seatbelt)
- [GTFOBins](https://gtfobins.github.io/)
- [LOLBAS](https://lolbas-project.github.io/)
- [Ligolo-ng](https://github.com/nicocha30/ligolo-ng)
- [Chisel](https://github.com/jpillora/chisel)

### Reporting

- [SysReptor CLI](https://docs.sysreptor.com/cli/getting-started)
- [SysReptor findings and templates](https://docs.sysreptor.com/cli/projects-and-templates/finding)
- [Syslifters HackTheBox reporting templates](https://github.com/Syslifters/HackTheBox-Reporting)
- HTB sample report:
  `/Users/gabriele/Downloads/sample-penetration-testing-report-template.pdf`
