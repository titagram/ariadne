# Ariadne

**Policy-bounded lab and CTF penetration testing for Hades**

Ariadne is a native Hades plugin that conducts controlled, evidence-driven
penetration tests against explicitly authorized lab and CTF targets. It
separates a Hades-specific adapter from a deterministic Python core that owns
immutable engagement snapshots, policy intersection, state transitions,
playbooks, typed tool adapters, evidence, and reporting.

> ⚠️ **Authorized-use disclaimer.** Ariadne, Metasploit, exploit modules, and
> the other integrated tools may only be used against systems you own or are
> explicitly authorized to test. Unauthorized use may violate applicable laws.
> You must acknowledge this disclaimer during the initial `/ariadne` Q/A
> before any target-facing action occurs.

---

## Installation

### Prerequisites

- **Hades** 0.17.0 or later (Hermes agent)
- **Python** 3.11–3.13
- **Docker**, only for a future Kali execution integration when isolation or a
  specialist toolchain is required
- **Git** to clone the repository

### Install as a Hades plugin

```bash
git clone https://github.com/<owner>/ariadne
hades plugins install /path/to/ariadne
hades plugins list
```

Verify the plugin loaded and the skill is available:

```bash
hades plugins list               # ariadne should appear as enabled
```

In-Hermes the skill `ariadne:lab-pentest` will be available for session use.

### Install from a local directory

```bash
hades plugins install file:///Users/gabriele/Dev/ariadne
```

---

## Conditional Kali runtime

Ariadne's runtime selector prefers ordinary curated host tools and selects the
official `kalilinux/kali-rolling` image only for specialist tooling, isolation,
VPN/routing, or compatibility. The selector is implemented, but lifecycle and
network execution for the Kali container are not yet wired into the Hades
plugin; current bounded execution remains local.

There is no VM fallback. If Docker is required but missing, Ariadne stops at a
host-install boundary. It may offer package-manager installation where
supported, but performs it only after specific user approval.

---

## Quick start — no-target dry run

Use the project's representative fake-runtime test to verify the plugin
without contacting a target:

```bash
.venv/bin/pytest -q tests/contract/test_autonomous_run.py
```

There is currently no exposed `/ariadne doctor` command.

---

## Usage

In a Hermes session, supply an authorized target and objective. Ariadne asks
only for missing profile, target, objectives, intensity, and exclusions, then
shows one summary with the legal disclaimer. Hades performs one trusted
confirmation and atomically binds the accepted snapshot.

After confirmation, `ariadne_run` proceeds autonomously in both `controlled`
and `full` through objective completion, cleanup, and offline reporting.
Interaction occurs only at a true boundary: targeted scope amendment,
policy/guardrail conflict, an `always_manual` capability, host installation,
uncurated code, or a missing material decision.

Guardrails, immutable session/snapshot binding, plan expiry, and scope isolation
apply identically in both autonomy modes.

See the [Operator Guide](docs/operator-guide.md) for detailed walkthroughs.

## Knowledge base

The `knowledge/` directory is the canonical knowledge base and wiki source.
Markdown frontmatter links methodology, services, techniques, tools, and
official sources through stable `id`, `next`, `requires`, `policy`, and
`provenance` fields. Hades provides indexing, search, memory, and project
awareness; Ariadne does not add a graph database, vector database, crawler, or
separate RAG pipeline.

Tool documentation is recovered just in time from the installed version's
`--help`/`man` output, then from official documentation if needed. Concise tool
cards record version, source, and date and become `runtime_verified` only after
successful bounded execution. The execution path derives the tool identity
from the authorized `ProcessSpec`; a curated playbook can declare a
`tool_card` with its official HTTPS source and concise summary when that tool
is not yet in the canonical knowledge base. The declaration also pins the
documentation source date; discovery is fail-closed when the declaration is
missing or unsafe. The real action `ProcessSpec` is policy-authorized before
the fixed `--version`/`--help` probes run. Failed executions leave the new card
in `discovered` state. This does not authorize uncurated installation or
execution.

## Report locations

After a completed engagement, reports are written to the profile-scoped dossier:

```
~/.hermes/profiles/<profile>/ariadne/runs/<engagement-id>/
├── walkthrough.md          # Technical CTF walkthrough
└── professional.html       # Professional HTML report
```

PDF export and SysReptor bundle/push helpers exist as library components, but
they are not exposed by the current Hades plugin workflow.

## Removal

To remove the plugin:

```bash
hades plugins uninstall ariadne
```

To also remove all engagement data:

```bash
rm -rf ~/.hermes/profiles/<profile>/ariadne/
```

## License

[MIT](LICENSE)
