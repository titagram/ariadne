---
schema_version: 1
id: tool.searchsploit
kind: tool
title: SearchSploit
next: []
requires: []
policy:
- research.vulnerability
provenance:
- source.searchsploit.official
status: runtime_verified
version: 20260709-0kali1
source_date: '2026-07-29'
documentation_source: local_help
tool:
  executable: searchsploit
  version_args:
  - --version
  help_args:
  - --help
  official_source: source.searchsploit.official
---

Local Exploit-DB index lookup tied to a validated service fingerprint.
