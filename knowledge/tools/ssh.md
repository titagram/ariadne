---
schema_version: 1
id: tool.ssh
kind: tool
title: OpenSSH client
next: []
requires: []
policy:
  - foothold.ssh
  - postex.enum
  - postex.linux.enum
  - postex.linux.identity
  - privesc.enum
  - privesc.linux.sudo
  - privesc.linux.suid
  - privesc.linux.capabilities
  - privesc.linux.scheduled_tasks
  - privesc.linux.services
  - privesc.linux.linpeas
  - privesc.linux.pspy
provenance:
  - source.openssh.official
status: curated
version: runtime
source_date: "2026-07-30"
documentation_source: official
tool:
  executable: ssh
  version_args:
    - -V
  help_args:
    - -h
  official_source: source.openssh.official
---

OpenSSH is used only with an exact in-scope host, an observed SSH port, and an
opaque credential reference stored under the current engagement. Password
material is supplied through the bounded askpass bridge and never enters argv,
events, evidence transcripts, or reports.
