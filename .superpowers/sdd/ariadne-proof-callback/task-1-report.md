# Task 1 report — proof semantics

Implemented the narrow proof-semantics rules without changing callback or Docker code:

- Metasploit runs without an observed session now emit `exploit_no_session`.
- A no-session Metasploit run is classified non-success, so it cannot be persisted as an
  executed exploit.
- Only an `exploit_succeeded` observation with `session_opened=true` can advance to foothold.
- Nuclei `info` output cannot emit `vulnerability_validated`.
- Screenshots cannot synthesize foothold evidence or objective proof.
- Replayed stale screenshot `foothold_established` records cannot advance state without
  an independently structured SSH or Metasploit session proof.
- SSH plan eligibility requires both an observed SSH service and a protected credential reference.
- Repeated terminal boundaries are recorded once as a `dead_end`, keyed by a canonical boundary/state/snapshot signature.

Added focused parser/progression tests, including positive observed-session evidence and negative no-session, info-only Nuclei, and browser-error screenshot cases.

Validation:

- `python -m pytest -q tests/unit/test_proof_semantics.py tests/contract/test_metasploit_adapter.py -k 'session or screenshot or nuclei'` — 4 passed.
- Ruff and `git diff --check` pass after redirecting the cache to `/private/tmp` because the sandbox disallows writes to the repository cache.

The guarded-runtime replay now passes from its seeded web evidence through the real
credential-referenced SSH session path.
