---
schema_version: 1
id: tool.chromium
kind: tool
title: Chromium
next: []
requires: []
policy:
- foothold.confirm
provenance:
- source.chromium.official
status: runtime_verified
version: Chromium 150.0.7871.181 built on Debian GNU/Linux forky/sid
source_date: '2026-07-29'
documentation_source: local_help
tool:
  executable: chromium
  version_args:
  - --version
  help_args:
  - --help
  official_source: source.chromium.official
---

Headless browser used for bounded evidence screenshots.
