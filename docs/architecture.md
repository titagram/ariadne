# Ariadne Architecture

## Overview

Ariadne separates a Hades-specific adapter layer from a deterministic Python
core. This separation ensures that the core logic (engagement state machines,
policy intersection, evidence validation, and reporting) remains testable and
independent of the Hades runtime.

```
┌──────────────────────────────────────────────────┐
│                  Hades / Hermes                   │
│  ┌──────────────────────────────────────────────┐│
│  │            Ariadne Plugin                     ││
│  │  ┌─────────────────────┐  ┌────────────────┐ ││
│  │  │   Hades Adapter     │  │  Deterministic  │ ││
│  │  │  (plugin.yaml,      │──│  Core           │ ││
│  │  │   registration.py,  │  │  (core/, store/,│ ││
│  │  │   handlers.py,      │  │   evidence/,    │ ││
│  │  │   guard_hook.py,    │  │   reporting/)   │ ││
│  │  │   commands.py)      │  │                │ ││
│  │  └─────────────────────┘  └────────┬───────┘ ││
│  │                                     │         ││
│  │  ┌──────────────────────────────────▼────────┐││
│  │  │  Knowledge + Runtime                      │││
│  │  │  (canonical Markdown, local process,      │││
│  │  │   conditional Kali, evidence dossier)     │││
│  │  └──────────────────┬───────────────────────┘││
│  └─────────────────────┼────────────────────────┘│
└────────────────────────┼─────────────────────────┘
                         │
              ┌──────────▼──────────┐
              │ Local curated tools │
              │ or lazy Kali/OWASP  │
              │ containers when the │
              │ playbook requires it│
              └─────────────────────┘
```

## Core Domain (src/ariadne/core/)

The core has **no dependency** on Hades, Docker, ZAP, or SysReptor. It is
pure Python with Pydantic models.

### Key packages

| Package      | Responsibility                                            |
|--------------|-----------------------------------------------------------|
| `enums.py`   | Stable string enums (`AutonomyMode`, `EnvironmentProfile`, `FindingStatus`, `AssetStatus`) |
| `engagement.py` | `EngagementDraft`, `EngagementSnapshot`, `TargetSpec`, `Confirmation` — immutable state |
| `planning.py` | `ActionPlan`, approval records, bounded plan construction |
| `observations.py` | `Observation`, `Asset`, `Hypothesis` — runtime findings |
| `findings.py` | Finding and remediation models |
| `canonical.py` | Deterministic SHA-256 digests with sorted-key JSON serialization |
| `policy.py`   | `PolicyDocument`, `CapabilityRule`, monotonic intersection, `authorize()` |
| `state_machine.py` | Legal engagement state transitions |
| `workflow.py`  | Playbook schema and catalog |
| `planner.py`   | Bounded plan construction and validation |
| `errors.py`    | Typed domain exceptions (`PolicyConfigurationError`, `AdapaterError`, etc.) |

Playbooks are capability-first. The planner selects an eligible workflow from
evidence and policy; tool resolution happens afterward. A playbook may
therefore use a tool that was not known when the playbook was authored, as long
as Ariadne can document it, bind it to an allowed capability, and execute it
through the same typed boundary.

### Policy intersection

Effective permission is computed as a monotonic intersection:

```
base policy ∩ environment profile ∩ engagement snapshot ∩ action plan
```

A lower layer may restrict a capability but may never expand a higher layer.
The `authorize()` function in `policy.py` is fail-closed: unknown capability,
ambiguous policy, stale approval, or malformed input stops execution.
Partial environment overlays are materialized from the complete base capability
map, then intersected with base and engagement rate/concurrency/duration
restrictions. The three semantic source digests are frozen into the snapshot
self-hash and revalidated at proposal and execution time.

### State machine

The primary lifecycle:

```
IDLE → ENGAGEMENT_DRAFT → AWAITING_CONFIRMATION → SNAPSHOT_LOCKED
→ ENVIRONMENT_PREFLIGHT → DISCOVERY → ENUMERATION → HYPOTHESIS
→ ACTION_PLANNING → AWAITING_APPROVAL | AUTO_APPROVED
→ EXECUTION → VALIDATION → FOOTHOLD → POST_EXPLOITATION
→ PRIVILEGE_ESCALATION → OBJECTIVE_VALIDATION → CLEANUP → REPORTING → COMPLETE
```

Side states: SCOPE_AMENDMENT, POC_APPROVAL, HOST_INSTALL_APPROVAL, PAUSED,
BLOCKED, FAILED, ABORTED.

## Store Layer (src/ariadne/store/)

| Module       | Responsibility                                    |
|--------------|---------------------------------------------------|
| `paths.py`   | Profile-scoped paths and permission management    |
| `jsonl.py`   | Append-only JSONL writer/reader for event logs    |
| `run_store.py` | Snapshots, events, artifacts, active bindings   |
| `integrity.py` | Digest manifest generation and verification     |

All engagement events are append-only and hash-verified. Contract revisions are
immutable, linked snapshots; an accepted amendment moves the active pointer to
the new revision without rewriting history. Generated reports are atomically
written and included in the integrity manifest. The dossier lives at
`~/.hermes/profiles/<name>/ariadne/` and is excluded from Git.

## Hades Adapter (src/ariadne/hades_adapter/)

| Module           | Responsibility                                          |
|------------------|---------------------------------------------------------|
| `registration.py` | `PluginContext` registrations for tools, hooks, skills |
| `schemas.py`     | JSON Schema definitions for registered tools            |
| `handlers.py`    | Registered tool handler implementations                 |
| `commands.py`    | `/ariadne` command parser and direct approval handlers  |
| `guard_hook.py`  | `pre_tool_call` hard blocking hook                      |
| `session.py`     | Hades session-to-engagement binding                     |

The Hades adapter owns the trusted interaction boundary. Initial activation
uses one summary confirmation. Routine curated plans in both autonomy modes are
durably auto-approved and atomically claimed. Amendments and manual-only
actions use separate trusted Hades consent surfaces.

## Knowledge Layer (knowledge/, src/ariadne/knowledge/)

The Markdown files under `knowledge/` are simultaneously canonical nodes and
wiki pages. Node kinds separate methodology/strategy, services, techniques,
tools, and sources/provenance. Frontmatter uses stable `id`, `next`,
`requires`, `policy`, and `provenance` links.

`KnowledgeIndex` validates those links and may generate a deterministic
navigation index. It is not a graph database or retrieval pipeline. Hades owns
indexing, search, memory, and project awareness.

`ToolCardVerifier` probes the installed executable's version, `--help`, and
`man` output before any official-documentation fallback. A concise tool card is
promoted to `runtime_verified` only after successful execution. Documentation
discovery never authorizes uncurated code. At execution time the card id is
derived from the authorized `ProcessSpec.argv[0]`, not from an adapter
allowlist. For an unknown executable, curated playbook `tool_card` metadata
supplies the official HTTPS documentation source and concise summary used by
`inspect_or_discover`. The real action is authorized first; unknown-tool probes
are then limited to fixed `--version` and `--help` forms. Missing metadata,
non-public URLs, or unsafe probe arguments produce a typed
`tool_documentation` boundary. Failed actions are never promoted.

## Runtime Layer (src/ariadne/runtime/)

| Module           | Responsibility                                            |
|------------------|-----------------------------------------------------------|
| `platform.py`    | OS/architecture detection                                 |
| `preflight.py`   | Host, route, VPN, disk, and optional Docker checks        |
| `install.py`     | Curated host install proposals and execution              |
| `docker.py`      | Docker Compose lifecycle (pull, up, down, logs)           |
| `network_policy.py` | Target resolution, allowlist generation, DNS mapping   |
| `process.py`     | Bounded subprocess runner (timeout, output cap, SIGTERM tree) |
| `selection.py`   | Deterministic local/Kali/blocked runtime decision         |

Runtime selection is local-first. Kali is selected only for a specialist
toolchain, isolation, VPN/routing, or compatibility. Missing ordinary local
utilities do not silently start a container; the workflow reports a typed
boundary. Docker installation always remains a specific user decision.

## Tool Adapters (src/ariadne/adapters/)

Each adapter follows the `ToolAdapter` protocol (see
[Adapter Development](adapter-development.md)):

| Module              | Tool                          |
|---------------------|-------------------------------|
| `nmap.py`           | Nmap scanner                  |
| `httpx.py`          | httpx HTTP probing            |
| `zap.py`            | OWASP ZAP Automation Framework |
| `nuclei.py`         | Nuclei workflow execution     |
| `research.py`       | Local/vendor/CVE/Exploit-DB research |
| `metasploit.py`     | Metasploit search/info/check  |
| `postex.py`         | PEASS, pspy, PrivescCheck     |
| `active_directory.py` | NetExec, Impacket, BloodHound |
| `pivot.py`          | Ligolo-ng/Chisel lifecycle    |
| `screenshot.py`     | Headless Chromium evidence     |

## Evidence Layer (src/ariadne/evidence/)

| Module        | Responsibility                         |
|---------------|----------------------------------------|
| `records.py`  | Artifact metadata and provenance        |
| `collector.py` | Immutable file and transcript ingestion |
| `findings.py`  | Candidate-to-validated finding service |
| `redaction.py` | Deterministic secret redaction         |
| `cvss.py`      | CVSS scoring helpers                   |

## Reporting Layer (src/ariadne/reporting/)

| Module          | Responsibility                                   |
|-----------------|--------------------------------------------------|
| `validation.py` | Pre-export quality gates (evidence check, completeness) |
| `walkthrough.py` | Markdown technical CTF walkthrough renderer     |
| `professional.py` | HTML professional report renderer              |
| `dossier.py`    | Evidence-only report model assembled from persisted state |
| `pdf.py`        | Chromium PDF export of the professional report  |
| `sysreptor.py`  | Offline bundle, preview, and explicit push       |

The dossier builder never invents findings or artifacts. Only validated
finding events and files present in the run store may appear in reports.

## Scope Candidates

A loopback address or service of the current target remains in scope. A
distinct host or container is classified as `scope_candidate`. Ariadne persists
the local discovery transcript, explains the relation, and stops before
sending traffic. Acceptance creates a linked contract revision; rejection
records the branch as blocked so the planner can continue without repeatedly
asking.
