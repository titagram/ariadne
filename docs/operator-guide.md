# Ariadne Operator Guide

## 1. Start an Engagement

In a Hades/Hermes session, provide an authorized target and objective in
natural language or enter:

```text
/ariadne new
```

Ariadne reuses fields already present in the prompt or Hades project context
and asks only for missing values:

1. environment profile, such as `private-lab` or `htb`;
2. target IP address or FQDN;
3. one or more explicit objectives;
4. bounded intensity: `low`, `normal`, or `high`;
5. optional exclusions.

It then displays one contract summary containing the authorization attestation
and current legal disclaimer. One trusted Hades acceptance atomically writes
revision 1 and binds it to the current session. There are no confirmation
tokens or repeated flags.

```text
Target: 10.10.10.10
Profile: private-lab
Objectives: user_flag, root_flag
Intensity: normal
Exclusions: denial of service
→ one summary
→ one Hades confirmation
→ active engagement
```

## 2. Autonomous Operation

After activation, Ariadne calls the deterministic `ariadne_run` loop. Routine
curated, in-policy actions proceed automatically in both `controlled` and
`full`. The modes can select different policy ceilings, but neither changes
the non-overridable guardrails.

The loop persists each plan, atomically claims execution, captures the real
transcript, classifies evidence, and advances until:

- every objective and cleanup condition is satisfied and reports are written;
- a distinct target needs a scope amendment;
- uncurated code is required;
- policy or an `always_manual` capability needs a decision;
- a material credential or choice is missing;
- report evidence fails a quality gate.

Hades's `--yolo` flag has no effect on Ariadne guardrails.

## 3. Amend an Active Contract

An engagement is amendable even though every version is immutable:

```text
/ariadne amend-scope
→ agent calls ariadne_amend_engagement with the proposed delta and reason
→ one targeted Hades confirmation
→ immutable revision 2 linked to revision 1
```

An amendment may add targets or revise objectives, intensity, and exclusions.
Plans bound to the earlier snapshot become stale.

### Lateral movement

Localhost and services of the current target do not require an amendment. A
distinct host or container becomes a `scope_candidate`. Ariadne first saves
only the evidence visible on the current machine, explains what was discovered
and why traffic might be useful, then requests one targeted amendment before
sending any packets.

If declined, the candidate branch is recorded as blocked. Ariadne continues
with other in-scope alternatives and does not repeatedly propose the same
candidate.

## 4. Tools and Kali

Playbooks request capabilities rather than fixed product names. Before using a
tool, Ariadne consults its canonical Markdown card. When the card is absent or
stale, it checks the installed version and local `--help`/`man` output first,
then official online documentation. The resulting card is concise and records
version, source, and date. Successful execution promotes it to
`runtime_verified`.

Local curated tools are preferred. Ariadne can select the official
`kalilinux/kali-rolling` image when a specialist toolchain, isolation,
VPN/routing, or compatibility makes it necessary, but container lifecycle is
not yet connected to the current Hades execution path. Docker is therefore not
started automatically today.

No VM fallback is used. Acquiring or running uncurated code also remains a
specific approval boundary.

## 5. Status

```text
/ariadne status
```

The current plugin exposes status through `ariadne_status`. It does not expose
interactive pause, resume, or abort commands; a real blocking boundary leaves
the immutable dossier intact for a later amendment or operator decision.

## 6. Offline Reporting

Successful completion automatically writes:

```text
~/.hermes/profiles/<name>/ariadne/runs/<engagement-id>/
├── snapshots/              # immutable contract revisions
├── artifacts/              # real evidence and command transcripts
├── events.jsonl            # hash-chained audit events
├── walkthrough.md          # technical CTF walkthrough
└── professional.html       # professional evidence-backed report
```

Reports contain only persisted evidence. Screenshots, URLs, CVEs, PoCs, and
exploit details appear only when they were actually collected and referenced.
Scanner alerts remain labelled as candidates and are excluded from validated
risk totals until a separate validation event is persisted. Nuclei execution
also requires a structured, evidence-linked validated template candidate for
the current target; a missing candidate stops at a typed boundary without
starting the subprocess.
Use `ariadne_render_report` to regenerate local outputs after the quality gate
passes. `include_flags` and `include_secrets` are explicit opt-in inputs; both
default to redaction.

## 7. SysReptor and PDF follow-up

Offline SysReptor bundle and PDF helper modules are present, but neither is
currently exposed through a Hades tool or generated automatically. The active
workflow produces the Markdown walkthrough and professional HTML dossier only.
Any future SysReptor push must remain a separate explicit operator action.

## 8. Verification

Project tests use a fake runtime for the representative end-to-end dry-run;
they do not perform a real pentest. There is currently no `/ariadne doctor`
command.
