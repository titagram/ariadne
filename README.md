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
- **Docker**, only when Kali isolation or a specialist toolchain is selected
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
VPN/routing, missing curated tools, or compatibility. The Hades execution path
starts the architecture-specific pinned Kali Compose service lazily. Research
is routed per subprocess: ordinary available tools such as `curl` remain local,
while missing SearchSploit or Metasploit executables use Kali.

The derived `ariadne-kali` image starts from the minimal official base and
installs only the packages declared in `containers/tool-manifest.yaml`. It does
not install `kali-linux-headless`, desktop frontends, or unrelated Kali tool
families. The manifest is the reviewable boundary for adding a curated tool;
uncurated code still requires explicit approval.

Web discovery is provider-aware. Ariadne prefers a bounded Katana crawl,
uses ZAP only for its passive or active analysis capabilities, and retains a
single-page, same-host `curl` extractor as the local fallback. If a specialist
provider is unavailable, only that branch is exhausted; Ariadne continues with
the next eligible provider instead of blocking the whole engagement.

There is no VM fallback. If Docker is required but missing, Ariadne stops at a
typed `kali_runtime` boundary and never installs Docker implicitly.

The engagement ledger and Kali root filesystem are read-only. Only
`workspace/` (including the tool home) and `artifacts/` are writable and
persistent; `/tmp` is an ephemeral bounded tmpfs. Before every Nuclei run,
Ariadne verifies the container checkout commit, the mounted local index
revision/digest, and that each selected template is unchanged from its pinned
Git blob.

---

## Quick start — no-target dry run

Use the project's representative fake-runtime test to verify the plugin
without contacting a target:

```bash
.venv/bin/pytest -q tests/contract/test_autonomous_run.py
```

There is currently no exposed `/ariadne doctor` command.

## Vulnerability research and validation

Research consumes a persisted service product/version/CPE fingerprint and
queries SearchSploit, curated vendor advisories, NVD, CISA KEV, and Metasploit
independently. A CVE remains a candidate unless authoritative version-range,
CPE, or explicit affected-version evidence establishes applicability.
Metasploit modules are correlated by CVE search and module metadata; search,
`check`, and module use are separate stages. Module use additionally requires
persisted proof that the exact module's `check` reported the exact target
vulnerable.

Nuclei never runs its default catalog. Ariadne selects a bounded set from the
official ProjectDiscovery catalog pinned in
`src/ariadne/catalog/nuclei/catalog.lock.yaml`, using validated CVEs and
observed technologies.

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
