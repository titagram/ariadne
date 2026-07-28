# Ariadne Operator Guide

## Overview

This guide walks through a typical Ariadne engagement from start to finish,
covering both environment profiles, autonomy modes, scope amendment, and
reporting.

---

## 1. Starting an engagement

In a Hades Hermes session, enter:

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

After Q/A, Ariadne displays a **contract summary** and a confirmation code.

### Example: Private lab

```text
/ariadne new
  Profile: private-lab
  Target: 10.10.10.10
  Objectives: user_flag, root_flag
  Autonomy: controlled
  Time window: 8 hours
→ Contract summary displayed
→ Confirmation code: a7k3
/ariadne confirm a7k3
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
→ Confirmation code: b2x9
/ariadne confirm b2x9
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

Plans that satisfy all policy and playbook conditions run without routine
approval. The following always require a direct user decision regardless of
autonomy mode:

- Initial contract confirmation
- Scope amendment
- Host container-runtime installation
- Acquisition or execution of uncurated PoC code

> Hades's `--yolo` flag has **no effect** on Ariadne guardrails.

---

## 3. Scope amendment

If you want to add a target during an active engagement:

```text
/ariadne amend-scope
→ New target: 10.10.10.20
→ Contract summary displayed
→ Confirmation code: c3m5
/ariadne confirm c3m5
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

After the engagement is complete, generate the report:

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
