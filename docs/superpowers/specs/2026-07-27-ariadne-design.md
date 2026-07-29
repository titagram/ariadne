# Ariadne: Hades-Native Agentic Lab Pentesting

**Status:** Approved design  
**Date:** 2026-07-27  
**Initial host:** Hades/Hermes  
**Initial use case:** Authorized lab and CTF environments  
**Repository/plugin name:** `ariadne`  
**Skill name:** `ariadne:lab-pentest`  
**Interactive command:** `/ariadne`

## 1. Purpose

Ariadne is a Hades-native plugin and embedded skill for conducting controlled,
evidence-driven penetration tests against authorized lab and CTF targets.

Its purpose is not to give a language model an unrestricted shell and ask it to
"hack the box." Instead, Ariadne constrains the model to a versioned workflow
graph, typed tool adapters, immutable engagement policies, bounded action plans,
and evidence-backed state transitions.

The first release targets one explicit entry IP address or FQDN. The internal
asset model nevertheless supports Active Directory, pivoting, and multi-host
attack paths. Hosts discovered beyond the confirmed scope remain
`observed_only` until the user explicitly amends the engagement contract.
The project owner has approved HTTP redirect traversal for discovery: httpx
may follow redirect chains, but every host discovered through a redirect still
remains `observed_only`. This exception is limited to retrieving the redirect;
it does not authorize additional playbooks or active actions against that host.

The project supersedes the architectural role originally considered for
HexStrike. HexStrike is not a dependency, compatibility target, or planned
adapter. It may only be reconsidered if a future, concrete capability is
demonstrably cheaper and safer to integrate than to implement through Ariadne's
typed adapters.

## 2. Design Principles

1. **Authorization before capability.** No target action occurs before the user
   completes the Q/A, attests authorization, and accepts the current disclaimer.
2. **Fail closed.** Unknown state, ambiguous policy, stale approval, malformed
   output, or unexpected scope stops execution.
3. **Guardrails are not an autonomy setting.** The current runtime retains plan
   approval in both modes. The next continuous-mode boundary will remove only
   routine curated/in-policy prompts and will never bypass hard invariants.
4. **The model proposes; the engine permits.** The LLM ranks hypotheses and
   selects eligible playbooks. The deterministic core authorizes transitions.
5. **Evidence before claims.** Scanner alerts are candidates. Findings become
   validated only after the required evidence is collected.
6. **Scope is immutable per snapshot.** Any scope change creates a new snapshot
   and invalidates outstanding plans.
7. **One dossier, multiple views.** The technical walkthrough and professional
   report are generated from the same structured evidence.
8. **Offline first.** The engagement can complete without a remote reporting
   service. SysReptor is a first-class explicit export/push destination.
9. **Small, typed integrations.** Direct adapters are preferred to monolithic
   orchestration frameworks.
10. **No persistence or C2 in v1.** A reproducible proof, objective, or flag is
    sufficient. Ariadne does not establish long-lived command-and-control.
11. **Explicit legal acknowledgement.** The interactive contract displays a
    clear authorized-use disclaimer and requires direct acknowledgement. The
    disclaimer is repeated before high-impact exploitation categories.

## 3. Scope and Non-Goals

### 3.1 In scope for v1

- Interactive Hades/Hermes Q/A resembling a penetration-testing contract.
- Generic IP address or FQDN as the initial target.
- User-selected environment profiles such as private lab and HTB.
- Controlled autonomy and full autonomy defined inside the contract.
- Docker-only execution using the official Kali rolling image.
- OWASP ZAP as a separate official container.
- Network, web, Linux, Windows, Active Directory, and pivoting playbooks.
- Mandatory service-to-CVE/exploit research workflow.
- Direct tool adapters with structured parsing.
- Local immutable engagement records and evidence.
- A technical CTF walkthrough and a professional report.
- Offline SysReptor bundle generation and explicit SysReptor push.

### 3.2 Explicit non-goals

- General-purpose real-world red-team operations.
- Automatic selection of the environment policy.
- Automatic scope expansion.
- Persistence, covert long-term access, or general C2 infrastructure.
- Denial-of-service testing in the HTB profile.
- Virtual-machine provisioning or fallback.
- Headless/CI engagement setup in v1.
- Automatic execution of uncurated public proof-of-concept code.
- Automatic host software installation without user confirmation.
- A daemon, database server, or local HTTP control plane.
- HexStrike compatibility.

## 4. Architecture

### 4.1 Repository layout

```text
ariadne/
  plugin.yaml
  __init__.py
  pyproject.toml
  hades_adapter/
    registration.py
    tools.py
    tool_schemas.py
    hooks.py
    commands.py
  core/
    engagement/
    policy/
    workflow/
    planning/
    evidence/
    reporting/
    models/
  infrastructure/
    docker/
    runners/
    tool_adapters/
    research/
    screenshots/
    sysreptor/
  skills/
    lab-pentest/
      SKILL.md
      references/
  policies/
    base.yaml
    htb.yaml
    private-lab.yaml
    policy.schema.json
  workflows/
    base.yaml
    web.yaml
    linux.yaml
    windows.yaml
    active-directory.yaml
    pivoting.yaml
  containers/
    kali/
      Dockerfile
    compose.yaml
    tool-manifest.yaml
    image-lock.yaml
  report_templates/
    walkthrough/
    professional/
    sysreptor/
  tests/
    unit/
    contract/
    integration/
    policy/
    fixtures/
  README.md
  SECURITY.md
  LICENSE
```

The root `__init__.py` is a minimal composition root. Only `hades_adapter`
imports Hades internals. The core has no dependency on Hades, Docker, ZAP, or
SysReptor.

Workflows and policies are schema-validated, versioned data. Tool outputs are
typed models. The embedded skill conducts the Q/A and calls registered Ariadne
tools; it does not construct or execute raw shell commands.

### 4.2 Hades integration

The plugin uses Hades's native `plugin.yaml` and `register(ctx)` contract. It
registers:

- the namespaced skill `ariadne:lab-pentest`;
- the interactive `/ariadne` command;
- typed Ariadne tools;
- pre-tool-call enforcement hooks;
- engagement lifecycle services;
- report renderers and exporters.

The planned user-facing commands are:

```text
/ariadne new
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

The initial contract is locked and bound atomically when the completed Q/A is
submitted from the trusted Hades session. Scope amendments, guardrail
exceptions, host installation, uncurated PoCs, and SysReptor push remain
separate, explicit user decisions. A model-supplied session identifier is never
accepted as a substitute for trusted Hades context.

## 5. Engagement Contract

### 5.1 Interactive Q/A

Each execution begins with Q/A covering:

- authorization attestation;
- environment profile, explicitly chosen by the user;
- one or more explicit objectives;
- initial target IP/FQDN;
- permitted time window;
- allowed and forbidden techniques;
- ports, request rates, concurrency, and authentication limits;
- autonomy mode;
- credentials and hints supplied by the user;
- pivoting and multi-host constraints;
- evidence and screenshot preferences;
- output and report preferences;
- optional SysReptor destination.

The system never chooses the environment profile on behalf of the user.

After validation, Ariadne displays a concise contract summary and asks the user
to accept the current, server-controlled disclaimer. That acceptance is the
single initial authorization act: `ariadne_prepare_engagement` writes the
immutable `engagement.lock.yaml`, appends lock and binding events, and binds the
snapshot to the trusted Hades session as one logical operation. There is no
initial confirmation token or TTL.

The summary includes an authorized-use disclaimer stating that Ariadne,
Metasploit, exploit modules, and the other integrated tools may only be used
against systems the user owns or is explicitly authorized to test. Direct
the atomic lock records the acknowledgement, disclaimer version, and timestamp.

### 5.2 Autonomy

Autonomy is a contract field, not a global Hades flag:

```yaml
autonomy: controlled
```

or:

```yaml
autonomy: full
```

Controlled autonomy requires direct approval of bounded action plans. The
current implementation also requires plan approval in `full`; it does not yet
auto-execute. The immediately following milestone is continuous mode: after the
brief Q/A it autonomously executes curated, in-policy plans through completion
and generates the offline local report.

Continuous mode pauses for scope/new-target decisions, policy or guardrail
conflicts, host installation, uncurated code, missing credentials or choices,
high-impact actions not already authorized in the contract, and SysReptor
network push.

The following always require a direct user decision:

- initial Q/A authorization and disclaimer acceptance;
- scope amendment;
- host container-runtime installation;
- acquisition or execution of uncurated PoC code.
- SysReptor network push.

Hades's existing `--yolo` option has no effect on Ariadne policy or immutable
approval requirements.

## 6. State Machine and Bounded Plans

The primary state machine is:

```text
IDLE
  -> ENGAGEMENT_DRAFT
  -> AWAITING_CONFIRMATION
  -> SNAPSHOT_LOCKED
  -> ENVIRONMENT_PREFLIGHT
  -> DISCOVERY
  -> ENUMERATION
  -> HYPOTHESIS
  -> ACTION_PLANNING
  -> AWAITING_APPROVAL | AUTO_APPROVED
  -> EXECUTION
  -> VALIDATION
  -> FOOTHOLD
  -> POST_EXPLOITATION
  -> PRIVILEGE_ESCALATION
  -> OBJECTIVE_VALIDATION
  -> CLEANUP
  -> REPORTING
  -> COMPLETE
```

Side states cover:

- scope amendment;
- uncurated PoC approval;
- host installation approval;
- paused;
- blocked;
- failed;
- aborted.

Each transition declares minimum evidence, applicable policy capabilities,
eligible playbooks, events, stop conditions, and allowed next states.

A bounded action plan includes:

- plan ID;
- snapshot hash;
- target and hypothesis;
- ordered actions and tools;
- expected requests, rate, duration, and effect;
- expected evidence;
- stop conditions;
- cleanup;
- expiration.

Plans are approved with:

```text
/ariadne approve <plan-id>
```

Any new scope snapshot invalidates plans associated with the previous snapshot.

## 7. Policy Model and Enforcement

Effective permission is an intersection:

```text
base policy
  ∩ environment profile
  ∩ immutable engagement snapshot
  ∩ bounded action plan
```

A lower layer may restrict a capability but may never expand a higher layer.

### 7.1 Typed capabilities

The capability model includes:

- passive discovery;
- TCP/UDP scanning;
- service enumeration;
- web crawl, passive scan, active scan, and fuzzing;
- default-credential checks, spraying, and brute force;
- Metasploit, curated exploit, uncurated exploit, and payload upload;
- post-exploitation enumeration and credential access;
- privilege escalation;
- pivoting;
- bounded resource-stress testing;
- evidence collection;
- cleanup.

Each capability can constrain targets, ports, rates, concurrency, attempts,
duration, output size, callback behavior, tools, approvals, and stop
conditions.

### 7.2 Base invariants

The base policy always requires:

- explicit authorization attestation;
- acknowledgement of the versioned legal disclaimer;
- no automatic scope expansion;
- no persistence or C2;
- no automatic propagation;
- no host installation without confirmation;
- no uncurated PoC without confirmation;
- no upload of evidence to Hades memory;
- immutable snapshot and append-only events;
- bounded and killable processes.

The HTB profile additionally prohibits denial of service, resource exhaustion,
subnet scanning, and actions against other platform targets.

The private-lab profile may raise limits and permit explicitly bounded stress
testing. It cannot remove v1 base invariants.

### 7.3 Enforcement layers

1. Tool handlers revalidate the current snapshot, plan, and capability.
2. Hades `pre_tool_call` hooks block terminal/code/file bypass attempts during
   an active engagement.
3. Engagement state is written only through the plugin's store.
4. Container networking applies the confirmed target allowlist.
5. Runners enforce timeouts, output bounds, and process-group termination.
6. Reporting applies secret detection and redaction.

The hook blocks direct commands against scoped or observed targets, manual use
of offensive tools, unauthorized access to Ariadne containers, state-file
modification, and actions against `observed_only` assets. Ambiguous
classification fails closed.

A plugin cannot control a separate terminal opened by the computer owner.
Ariadne's enforceable promise is that it provides no internal path around its
guardrails and blocks bypasses within its Hades engagement boundary.

## 8. Networking and Containers

The execution environment uses the official multi-architecture
`kalilinux/kali-rolling` image and installs `kali-linux-headless` plus
manifested extras. Docker selects the matching architecture; Ariadne verifies
platform availability and records the resolved image digest.

OWASP ZAP runs in its separate official container using the Automation
Framework. The ZAP API is available only on the internal Docker network.

The preflight checks:

- host OS and architecture;
- Docker presence, health, disk, and memory;
- DNS and routes to the target;
- VPN reachability;
- Docker Desktop limitations;
- required ports and callback feasibility.

If Docker is absent, Ariadne presents the official installation path, required
privileges, commands, and consequences. Installation begins only after direct
confirmation. Supported attempts are Docker Desktop through Homebrew Cask on
macOS, Docker Desktop through `winget` on Windows, and official Docker packages
for supported Linux distributions. There is no VM fallback.

After Docker is available, Ariadne displays the official images, platforms,
digests, approximate download size, and build steps it intends to use. Pull and
build begin only after this preflight summary is accepted. A failed runtime
installation, architecture mismatch, or unavailable image stops setup rather
than switching to another execution environment.

The ordinary Kali process uses a non-root user. Capabilities such as
`CAP_NET_RAW` are granted only when needed. `CAP_NET_ADMIN` is reserved for
routing, tunnel, or firewall playbooks. Kali and ZAP images are pinned by
digest in an explicit lockfile.

## 9. Workflow and Playbooks

The workflow graph is:

```text
contract
  -> preflight
  -> discovery
  -> service fingerprinting
  -> protocol-specific enumeration
  -> ranked hypotheses
  -> mandatory CVE/exploit research
  -> bounded validation or exploitation
  -> foothold
  -> post-exploitation
  -> privilege escalation
  -> AD or pivot branches where applicable
  -> objective validation
  -> cleanup
  -> reporting
```

A playbook declares:

- stable ID and version;
- stage and triggers;
- required evidence and capabilities;
- typed inputs;
- primary and fallback adapters;
- estimated cost, noise, and impact;
- policy limits;
- output parser;
- success, failure, and retry conditions;
- stop conditions;
- cleanup;
- emitted observations;
- eligible next states;
- evidence and report mappings.

The LLM may correlate evidence, rank hypotheses, choose from eligible
playbooks, explain its reasoning to the user, and propose a new non-executable
playbook. It may not improvise an executable command. If no playbook matches,
Ariadne continues passively, enters `research_only`, or requests a manual plan.

## 10. Golden Toolset

The tool manifest distinguishes base tools, pinned build-time extras, separate
service containers, optional high-impact tools, and non-executable references.
Runtime presence and version are probed rather than assumed from the Kali
metapackage.

### 10.1 Network and web

- Nmap as the primary network scanner.
- `dig`, `dnsrecon`, and `tcpdump` for DNS and packet evidence.
- Masscan or Naabu only under an appropriately aggressive policy.
- httpx, WhatWeb, and curl for HTTP fingerprinting.
- Katana, Feroxbuster, and ffuf for bounded discovery.
- OWASP ZAP Automation Framework for repeatable active web testing.
- Nuclei with selected curated workflows.
- sqlmap, dalfox, and testssl.sh only after relevant evidence.

### 10.2 Network services, Windows, and AD

- smbclient, rpcclient, enum4linux-ng, and ldapsearch.
- NetExec, Impacket, and Evil-WinRM for typed remote operations.
- BloodHound collectors, Kerbrute, and Certipy for dedicated AD branches.
- Separate playbooks for Kerberos, ACLs, delegation, and AD CS.
- Responder, relay, credential dumping, ticket manipulation, and object
  modification require explicit high-impact capabilities.

### 10.3 Research and exploitation

For every viable service hypothesis, Ariadne follows:

1. exact product/version fingerprint;
2. vendor advisory and authoritative CVE sources;
3. Exploit-DB/SearchSploit;
4. Metasploit `search`, `info`, and `check` where available;
5. public PoC provenance and review.

A scanner match never directly authorizes exploitation. Metasploit, curated
exploits, and pwntools are execution options only after an eligible plan.
Uncurated code always requires direct approval.

SearchSploit and local indexes are queried before network research. Online
queries contain only the normalized product, version, protocol, and candidate
CVE: Ariadne does not submit the target IP/FQDN, credentials, screenshots,
captured content, or dossier data to public search services. If online research
is unavailable, the workflow records the source limitation rather than
silently treating local results as exhaustive.

### 10.4 Post-exploitation

- Linux: LinPEAS, pspy, and explicit checks for sudo, SUID, capabilities, jobs,
  services, and permissions; GTFOBins as a reference.
- Windows: WinPEAS, PrivescCheck, Seatbelt, and explicit system checks; LOLBAS
  as a reference.
- Credentials: Hashcat and John for policy-bounded offline work.
- Pivoting: Ligolo-ng, Chisel, SSH, and ProxyChains.

New assets found through a tunnel remain `observed_only` until a confirmed
scope amendment creates a new snapshot.

### 10.5 Adapter contract

Every executable integration implements:

```text
probe()     presence and version
plan()      playbook to argv and limits
execute()   process execution without shell interpolation
parse()     typed observations
classify()  success, failure, or ambiguity
collect()   evidence and provenance
cleanup()   declared temporary effects
```

Commands are argument arrays, not shell strings. Timeout, maximum output, and
process-group termination are mandatory.

## 11. Evidence Dossier

Each run writes:

```text
runs/<engagement-id>/
  engagement.lock.yaml
  manifest.json
  events.jsonl
  observations.jsonl
  hypotheses.jsonl
  actions.jsonl
  findings/
  evidence/
    screenshots/
    terminal/
    http/
    files/
    pcaps/
  reports/
    walkthrough/
    professional/
    sysreptor/
  checksums.sha256
```

No database or resident service is required. Directories use restrictive local
permissions and are excluded from source control. Encryption is not required
for the initial lab/CTF release.

Every evidence artifact records:

- stable ID, engagement ID, and snapshot hash;
- UTC timestamp;
- target asset, service, URL, or identity;
- playbook, adapter, and tool version;
- action plan;
- reproducible redacted command;
- exit status and parser status;
- SHA-256 digest;
- related observations, objectives, and findings;
- confidence and provenance;
- transformations such as crop, annotation, or redaction.

Original binary evidence is immutable. A transformation creates a related new
artifact.

Finding states are:

- candidate;
- validated;
- exploited;
- false positive;
- informational;
- not tested due to policy.

Only validated or exploited findings enter the automatic vulnerability
summary.

## 12. Reporting

### 12.1 Finding model

A finding contains:

- stable ID, title, status, severity, and confidence;
- affected assets;
- description, root cause, and impact;
- attack path and reproduction steps;
- immediate, short-term, and long-term remediation;
- optional CVE and CWE identifiers;
- CVSS version, vector, and score where applicable;
- references and evidence IDs.

CVE is optional because misconfigurations, weak credentials, excessive ACLs,
and AD attack paths may be valid findings without a CVE.

### 12.2 Technical walkthrough

The CTF-oriented renderer follows:

1. objective and scope;
2. environment and connectivity;
3. discovery and enumeration;
4. hypotheses and discarded alternatives;
5. initial access;
6. post-exploitation;
7. privilege escalation;
8. AD or pivoting;
9. objectives and flags;
10. cleanup;
11. lessons and reproducible commands.

Secrets and flags are redacted by default and included only through an explicit
export choice.

### 12.3 Professional report

The professional renderer follows the supplied HTB sample:

- cover, classification, and version control;
- contacts and disclaimer;
- executive summary;
- scope, objectives, assumptions, and limitations;
- methodology;
- risk and finding summaries;
- compromise narrative;
- full technical findings;
- remediation roadmap;
- compromised hosts and users;
- objective evidence;
- cleanup;
- scoring and methodology appendices.

It produces Markdown, standalone HTML, PDF, and a SysReptor bundle.

### 12.4 SysReptor

SysReptor is a first-class explicit destination with three modes:

- `offline`: produce an importable bundle;
- `preview`: validate mapping without upload;
- `push`: explicitly create or update a project.

There is no automatic or background upload. Before a push, Ariadne displays
the destination, project, and data classes to be sent. API credentials are
never written to the dossier or reports.

The mapping is engagement to project, Ariadne finding to SysReptor finding,
asset to affected component, evidence to image/attachment, and narrative
sections to project sections.

### 12.5 Report quality gates

Export fails if:

- the authorization snapshot is missing;
- a confirmed finding lacks evidence;
- a referenced artifact is missing;
- dossier hashes or links do not validate;
- CVSS score and vector disagree;
- a reported asset is outside the confirmed scope;
- an objective is claimed without proof;
- forbidden secrets remain;
- executive summary or remediation is missing;
- an invasive action lacks its plan and approval event.

## 13. Testing Strategy

### 13.1 Unit and property tests

Unit tests cover the state machine, policy intersection, snapshot immutability,
plan expiration, asset classification, redaction, finding scoring, evidence
links, and schema validation.

Property-based tests verify policy monotonicity: a lower policy layer cannot
make an action more permissive.

### 13.2 Adapter contract tests

Each adapter is tested against fixtures for valid, partial, unknown-version,
malformed, timed-out, killed, oversized, ambiguous, and unreachable results.
Tests assert typed results rather than console formatting.

### 13.3 Negative policy tests

Mandatory negative cases include:

- denial of service under the HTB profile;
- scanning a discovered but unapproved host;
- executing a stale plan;
- unapproved uncurated PoC;
- unapproved host installation;
- authentication attempts above configured limits;
- pivoting to an unauthorized subnet;
- terminal-based adapter bypass;
- event-file tampering;
- accidental evidence upload to Hades memory.

The test passes only when the request is blocked before reaching a runner.

### 13.4 Integration and end-to-end tests

An isolated Docker network hosts deterministic TCP, HTTP, authentication, DNS,
and scope-expansion fixtures. Optional suites may use OWASP Juice Shop.

The ordinary CI suite never connects to Internet targets or external RFC1918
networks.

The minimum end-to-end acceptance scenario proves:

1. contract creation and direct confirmation;
2. immutable snapshot;
3. Docker preflight;
4. isolated discovery;
5. bounded plan and approval;
6. evidence collection;
7. validated finding;
8. both report renderers;
9. valid SysReptor bundle;
10. cleanup and digest verification.

## 14. v1 Release Criteria

The first release is complete when:

- it installs as a native Hades plugin;
- Q/A, confirmation, and immutable snapshots work;
- `base`, `private-lab`, and `htb` policies are enforced;
- a generic IP/FQDN entry target is supported;
- network, web, Linux, Windows, AD, and pivoting playbooks exist;
- execution stops on new assets pending amendment;
- Kali and ZAP are orchestrated through Docker;
- both reports and a valid SysReptor bundle are produced;
- all mandatory guardrail-negative tests pass;
- HexStrike is not required;
- limitations and the threat boundary are documented.

## 15. Initial Delivery Sequence

Implementation planning should preserve this dependency order:

1. project scaffold, schemas, and architectural boundaries;
2. core state machine, policy algebra, planning, and dossier;
3. Hades registration, Q/A, direct confirmations, and hooks;
4. Docker/Kali/ZAP preflight and lifecycle;
5. direct network and web adapters;
6. research and exploitation adapters;
7. Linux and Windows post-exploitation;
8. Active Directory and pivoting;
9. report renderers and SysReptor;
10. security hardening, integration suites, documentation, and release.

## 16. Primary References

- Hades local plugin implementation
  (`~/.hermes/hermes-agent/hermes_cli/plugins.py`, inspected 2026-07-27)
- [Official Kali Linux Docker images](https://www.kali.org/docs/containers/official-kalilinux-docker-images/)
- [Kali `kali-linux-headless` metapackage](https://www.kali.org/tools/kali-meta/)
- [Docker host network driver](https://docs.docker.com/engine/network/drivers/host/)
- [OWASP ZAP Docker images](https://www.zaproxy.org/docs/docker/about/)
- [OWASP ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/)
- [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final)
- [NIST National Vulnerability Database](https://nvd.nist.gov/)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [ProjectDiscovery Nuclei workflows](https://docs.projectdiscovery.io/templates/workflows/overview)
- [Exploit-DB SearchSploit manual](https://www.exploit-db.com/documentation/Offsec-SearchSploit.pdf)
- [Metasploit appropriate module use](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-a-metasploit-module-appropriately.html)
- [Impacket](https://github.com/fortra/impacket)
- [SharpHound Community Edition](https://bloodhound.specterops.io/collect-data/ce-collection/sharphound)
- [Certipy](https://github.com/ly4k/Certipy)
- [PEASS-ng](https://github.com/peass-ng/PEASS-ng)
- [pspy](https://github.com/DominicBreuker/pspy)
- [PrivescCheck](https://github.com/itm4n/PrivescCheck)
- [Seatbelt](https://github.com/GhostPack/Seatbelt)
- [Ligolo-ng](https://github.com/nicocha30/ligolo-ng)
- [SysReptor CLI](https://docs.sysreptor.com/cli/getting-started)
- [SysReptor findings and templates](https://docs.sysreptor.com/cli/projects-and-templates/finding)
- [Syslifters HackTheBox reporting templates](https://github.com/Syslifters/HackTheBox-Reporting)
- [Hack The Box platform rules](https://help.hackthebox.com/en/articles/12325897-hack-the-box-platform-rules)
- [Agent Skills specification](https://github.com/agentskills/agentskills)
