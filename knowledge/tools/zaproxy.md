---
schema_version: 1
id: tool.zaproxy
kind: tool
title: OWASP ZAP
next: []
requires: []
policy:
- web.passive_scan
provenance:
- source.zaproxy.official
status: discovered
version: runtime
source_date: '2026-07-30'
documentation_source: official
tool:
  executable: zaproxy
  version_args:
  - -version
  help_args:
  - -help
  official_source: source.zaproxy.official
---

Official OWASP proxy used for bounded passive analysis.
