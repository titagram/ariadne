# Ariadne Operator Guide

## Overview

This guide walks through a typical Ariadne engagement from start to finish,
covering both environment profiles, autonomy modes, scope amendment, and
reporting.

---

## 1. Starting an engagement

In a Hades Hermes session, either write a natural-language prompt containing
the authorized target and objective or enter:

```text
/ariadne new
```

Ariadne will begin interactive Q/A covering:

1. **Authorization attestation** — confirm you are authorized to test the target
2. **Environment profile** — choose `private-lab` or `htb`
3. **Target** — one IP address or FQDN
4. **Objectives** — one or more of: `user_flag`, `root_flag`, `domain_admin`, `proof`, `custom`
5. **Time window** — permitted testing duration
6. **Autonomy mode** — `controlled` or `full`
7. **Additional constraints** — ports, rates, credentials, auth limits
8. **Reporting preferences** — offline walkthrough, professional report, SysReptor

After Q/A, Ariadne displays a **contract summary** and the current legal
disclaimer. Explicit acceptance locks and activates the engagement immediately.

### Example: Private lab

```text
/ariadne new
  Profile: private-lab
  Target: 10.10.10.10
  Objectives: user_flag, root_flag
  Autonomy: controlled
  Time window: 8 hours
→ Contract summary displayed
→ Disclaimer accepted; engagement locked and bound
```

### Example: HTB

```text
/ariadne new
  Profile: htb
  Target: box.htb
  Objectives: user_flag, root_flag
  Autonomy: full
  Time window: 24 hours
→ Contract summary displayed
→ Disclaimer accepted; engagement locked and bound
```

---

## 2. Controlled vs Full autonomy

### Controlled autonomy (default)

Every bounded action plan requires explicit approval:

```text
/ariadne plan
→ Plan p1: scan TCP ports 1-10000 on 10.10.10.10
           expected duration: 5 min
           expected evidence: open ports, service banners
/ariadne approve p1
```

### Full autonomy

In `full`, curated, catalog-backed, in-policy plans without an `always_manual`
capability are durably auto-approved. The agent immediately calls execution,
repeats propose/execute through objective validation and cleanup, and
automatically renders the local offline report.

The continuous loop pauses only for:

- scope changes or newly discovered targets;
- policy or guardrail conflicts;
- host container-runtime installation;
- acquisition or execution of uncurated code;
- missing credentials or decisions;
- high-impact actions not already authorized by the contract;
- SysReptor network push.

The offline local report is generated automatically at completion. SysReptor
network push remains a separate direct decision.

> Hades's `--yolo` flag has **no effect** on Ariadne guardrails.

---

## 3. Scope amendment

If you want to add a target during an active engagement:

```text
/ariadne amend-scope
→ New target: 10.10.10.20
→ Contract summary displayed
→ Explicit scope-amendment approval requested
```

This creates a new immutable snapshot linked to the previous one. Any plans
associated with the previous snapshot are invalidated.

> Targets added this way are `in_scope`. Newly *discovered* hosts are always
> `observed_only` until a direct scope amendment.

---

## 4. Pause and abort

### Pause

```text
/ariadne pause
```

Pauses the current engagement. Running containers are kept alive; no new actions
are dispatched.

```text
/ariadne resume
```

Resumes from the paused state.

### Abort

```text
/ariadne abort
```

Stops the engagement and triggers cleanup: running containers are torn down,
temporary files are removed.

---

## 5. Cleanup

Cleanup happens automatically at the end of a successful engagement, after an
abort, or on failure. Manual cleanup:

```text
/ariadne cleanup
```

This removes:
- Running Docker containers from the engagement stack
- Temporary files created during execution
- Transient network configurations

The dossier (evidence, findings, events) is **not** removed by cleanup.

---

## 6. Offline reporting

In `full`, Ariadne generates the offline report automatically after objective
validation and cleanup. In `controlled`, or to regenerate a report explicitly:

```text
/ariadne report
```

This produces:
- **Technical walkthrough** (`walkthrough.md`) — markdown with shells, flags,
  and key commands
- **Professional report** (`professional.html`) — formatted HTML suitable for
  printing or PDF conversion
- **Professional PDF** (`professional.pdf`) — if Chromium is available in the host

Reports are written to the profile dossier:

```
~/.hermes/profiles/<name>/ariadne/runs/<engagement-id>/
```

---

## 7. SysReptor reporting

### Preview

Before pushing, preview the SysReptor bundle:

```text
/ariadne sysreptor preview
```

This generates an offline ZIP bundle with:
- Manifest (`manifest.json`) with SHA-256 hashes
- Findings as individual JSON files
- Evidence as referenced files
- Summary metadata

The preview is written to the report directory but is **not pushed** to
SysReptor.

### Push

To push to a SysReptor instance:

```text
/ariadne sysreptor push
```

This requires:
1. SysReptor CLI configured with API credentials
2. User confirmation (always required, even under full autonomy)

The push reports progress and confirms successful upload or error details.

> SysReptor credentials, API URL, and project template are configured in the
> SysReptor CLI configuration, not in Ariadne.

---

## 8. Monitoring

```text
/ariadne status
```

Shows current engagement state, active snapshot hash, elapsed time, and
progress toward objectives.

```text
/ariadne evidence
```

Lists collected evidence artifacts with their hashes.
