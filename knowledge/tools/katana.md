---
schema_version: 1
id: tool.katana
kind: tool
title: ProjectDiscovery Katana
next: []
requires: []
policy:
- web.content_discovery
provenance:
- source.katana.official
status: discovered
version: runtime
source_date: '2026-07-30'
documentation_source: official
tool:
  executable: katana
  version_args:
  - --version
  help_args:
  - --help
  official_source: source.katana.official
---

Official target-scoped crawler used for bounded endpoint discovery.
