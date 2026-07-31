---
schema_version: 1
id: tool.msfconsole
kind: tool
title: Metasploit Framework
next: []
requires: []
policy:
- exploit.metasploit
provenance:
- source.msfconsole.official
status: runtime_verified
version: 'Framework Version: 6.4.146-dev'
source_date: '2026-07-29'
documentation_source: local_help
tool:
  executable: msfconsole
  version_args:
  - --version
  help_args:
  - --help
  official_source: source.msfconsole.official
---

Exact module check selected from validated research evidence.
