---
schema_version: 1
id: technique.tcp.port-scan
kind: technique
title: Bounded TCP port scan
next:
  - tool.nmap
requires:
  - service.http
policy:
  - scan.tcp
provenance:
  - source.nmap.official
---

Use a policy-bounded TCP scan only against the locked target. Rate, concurrency,
duration, and port range remain execution-contract inputs rather than prose.
