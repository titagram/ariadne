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
│  │  │          Runtime Layer                    │││
│  │  │  (docker.py, process.py, install.py,      │││
│  │  │   network_policy.py, preflight.py)        │││
│  │  └──────────────────┬───────────────────────┘││
│  └─────────────────────┼────────────────────────┘│
└────────────────────────┼─────────────────────────┘
                         │
              ┌──────────▼──────────┐
              │   Docker Engine     │
              │  ┌──────┐ ┌──────┐  │
              │  │Kali  │ │ ZAP  │  │
              │  │Container│Container│
              │  └──────┘ └──────┘  │
              │  ┌──────────────┐   │
              │  │  Netguard    │   │
              │  │  (allowlist  │   │
              │  │   sidecar)   │   │
              │  └──────────────┘   │
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

### Policy intersection

Effective permission is computed as a monotonic intersection:

```
base policy ∩ environment profile ∩ engagement snapshot ∩ action plan
```

A lower layer may restrict a capability but may never expand a higher layer.
The `authorize()` function in `policy.py` is fail-closed: unknown capability,
ambiguous policy, stale approval, or malformed input stops execution.

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

All engagement state is append-only and hash-verified. The dossier lives at
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

## Runtime Layer (src/ariadne/runtime/)

| Module           | Responsibility                                            |
|------------------|-----------------------------------------------------------|
| `platform.py`    | OS/architecture detection                                 |
| `preflight.py`   | Docker, route, VPN, disk, and memory checks               |
| `install.py`     | Curated host install proposals and execution              |
| `docker.py`      | Docker Compose lifecycle (pull, up, down, logs)           |
| `network_policy.py` | Target resolution, allowlist generation, DNS mapping   |
| `process.py`     | Bounded subprocess runner (timeout, output cap, SIGTERM tree) |

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
| `pdf.py`        | Chromium PDF export of the professional report  |
| `sysreptor.py`  | Offline bundle, preview, and explicit push       |
