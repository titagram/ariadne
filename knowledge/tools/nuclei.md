---
schema_version: 1
id: tool.nuclei
kind: tool
title: Nuclei
next: []
requires: []
policy:
- exploit.validation
provenance:
- source.nuclei.official
status: runtime_verified
version: "[\e[34mINF\e[0m] Nuclei Engine Version: v3.11.0\n[\e[34mINF\e[0m] Nuclei\
  \ Config Directory: /workspace/home/.config/nuclei\n[\e[34mINF\e[0m] Nuclei Cache\
  \ Directory: /workspace/home/.cache/nuclei\n[\e[34mINF\e[0m] PDCP Directory: /workspace/home/.pdcp"
source_date: '2026-07-29'
documentation_source: local_help
tool:
  executable: nuclei
  version_args:
  - --version
  help_args:
  - --help
  official_source: source.nuclei.official
---

Template-based scanner used only with target-bound validated candidates.
