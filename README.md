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
- **Docker** (recommended: Docker Desktop for macOS/Windows, or `docker.io` on
  Linux) — see [Docker prerequisites](#docker-prerequisites) below
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

## Docker prerequisites

Ariadne executes all target-facing tools inside Docker containers based on the
official `kalilinux/kali-rolling` image and an OWASP ZAP stable image.

Before starting an engagement:

1. Install Docker Desktop (macOS/Windows) or `docker.io` (Linux).
2. Ensure the Docker daemon is running:
   ```bash
   docker info
   ```
3. The first `/ariadne new` will run a preflight check and present the images
   it intends to pull. Confirm to proceed.

> Ariadne does not use a VM fallback. If Docker is unavailable, the
> `/ariadne doctor` command will report the issue and guide through
> installation.

---

## Quick start — no-target dry run

You can verify the plugin is operational without engaging a real target by
running `/ariadne doctor` in a Hades session:

```text
/ariadne doctor
```

This checks:
- Plugin registration and skill availability
- Docker daemon presence (without pulling images)
- Hades version compatibility
- Filesystem permissions for the dossier

No target-side action is initiated.

---

## Usage

All user interaction happens through the `/ariadne` slash commands in a Hermes
session. The typical lifecycle:

1. **`/ariadne new`** — Interactive Q/A to define the engagement contract
   (target, objectives, profile, autonomy mode, time window, etc.)
2. **Accept the current disclaimer** — Atomically lock and bind the completed
   Q/A to the trusted Hades session
3. **`/ariadne status`** — View current engagement state and progress
4. **`/ariadne plan`** — Generate a bounded action plan
5. **`/ariadne approve <plan-id>`** — Approve a plan for execution
6. **`/ariadne evidence`** — Review collected evidence
7. **`/ariadne report`** — Generate the technical walkthrough and professional
   report
8. **`/ariadne abort`** — Stop the current engagement

See the [Operator Guide](docs/operator-guide.md) for detailed walkthroughs.

## Report locations

After a completed engagement, reports are written to the profile-scoped dossier:

```
~/.hermes/profiles/<profile>/ariadne/runs/<engagement-id>/
├── walkthrough.md          # Technical CTF walkthrough
├── professional.html       # Professional HTML report
├── professional.pdf        # Professional PDF report (if Chromium available)
└── sysreptor/              # SysReptor offline bundle (if generated)
```

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
