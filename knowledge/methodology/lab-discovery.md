---
schema_version: 1
id: methodology.lab.discovery
kind: methodology
title: Bounded lab discovery
next:
  - service.http
requires: []
policy: []
provenance:
  - source.nmap.official
---

Start with the least invasive bounded discovery needed to identify reachable
services on the locked target. Preserve evidence before selecting a narrower
enumeration technique.
