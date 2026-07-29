---
schema_version: 1
id: tool.nmap
kind: tool
title: Nmap
next: []
requires:
  - technique.tcp.port-scan
policy:
  - scan.tcp
provenance:
  - source.nmap.official
status: curated
version: runtime
source_date: "2026-07-29"
documentation_source: official
tool:
  executable: nmap
  version_args:
    - --version
  help_args:
    - --help
  official_source: source.nmap.official
---

Nmap provides the bounded TCP discovery capability. Runtime use is permitted
only after the local binary and concise local guidance are verified for the
current immutable card.
