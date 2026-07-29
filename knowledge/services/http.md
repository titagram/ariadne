---
schema_version: 1
id: service.http
kind: service
title: HTTP service
next:
  - technique.tcp.port-scan
requires:
  - methodology.lab.discovery
policy: []
provenance:
  - source.nmap.official
---

An HTTP endpoint is a candidate service only after target-bound transport
evidence exists. Keep host, port, scheme, and observed response metadata.
