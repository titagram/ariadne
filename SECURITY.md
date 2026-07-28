# Security Policy

## Supported Versions

| Version | Supported          | Hades Version | Python         |
|---------|--------------------|---------------|----------------|
| 0.1.x   | :white_check_mark: | 0.17.x        | 3.11, 3.12, 3.13 |

## Enforceable Hades Boundary

Ariadne enforces its guardrails within the Hades plugin boundary:

- **Tool handlers** revalidate the current snapshot, plan, and capability before
  any target-facing action.
- **`pre_tool_call` hooks** block terminal, code, and file tool bypass attempts
  during an active engagement.
- **Engagement state** is written only through Ariadne's store — direct file
  system modification of dossier content breaks the chain of custody.
- **Container networking** applies the confirmed target allowlist using a
  dedicated `netguard` sidecar container.
- **Runners** enforce timeouts, output-size bounds, and process-group
  termination.
- **Reporting** applies secret detection and redaction before export.

### Separate-terminal limitation

Ariadne cannot control a separate terminal opened by the host user. The
plugin's promise is that it provides no internal path around its guardrails and
blocks all bypass attempts within its Hades engagement boundary. Users are
expected to operate through the Hermes session for the duration of an
engagement.

## Policy on Uncurated Proof-of-Concept Code

Uncurated (public, non-versioned) PoC code always requires direct user
confirmation before execution. It is never executed automatically under any
autonomy mode. This includes PoCs from public repositories, Pastebin,
Exploit-DB user submissions, and security-advisory links.

## Disclosure Process

If you discover a security vulnerability in Ariadne:

1. **Do not** open a public GitHub issue.
2. Send details to the project maintainer via a private channel (email or
   direct message).
3. Include a clear description, steps to reproduce, affected versions, and any
   proposed remedy.
4. Allow 14 days for an initial response before any public disclosure.

## Supply-Chain Update Procedure

1. Dependencies are pinned to exact versions in `pyproject.toml`.
2. Update by changing the pinned version, running `uv lock`, and committing
   both `pyproject.toml` and `uv.lock`.
3. Run the full test suite before merging:
   ```bash
   uv run pytest
   uv run ruff check .
   uv run ty check src
   ```
4. Tag the release after verification:
   ```bash
   git tag -a v<new-version> -m "Ariadne v<new-version>"
   ```
5. Notify plugin consumers to re-install or update.

The Kali base image (`kalilinux/kali-rolling`) and ZAP image are pinned by
digest in `containers/image-lock.yaml`. Update by pulling the latest tag,
verifying the digest, and committing the lockfile update.

## Reporting a Vulnerability

For urgent or sensitive reports, contact the maintainer directly. For
non-urgent issues, open a private GitHub security advisory or use the
repository's issue tracker with sensitive details redacted.
