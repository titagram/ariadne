---
schema_version: 1
id: tool.nmap
kind: tool
title: Nmap
next: []
requires:
- technique.tcp.port-scan
policy:
- scan.tcp
provenance:
- source.nmap.official
status: runtime_verified
version: 'Nmap version 7.99 ( https://nmap.org )

  Platform: arm-apple-darwin25.3.0

  Compiled with: nmap-liblua-5.4.8 openssl-3.6.3 libssh2-1.11.1 libz-1.2.12 libpcre2-10.47
  nmap-libpcap-1.10.6 nmap-libdnet-1.18.0 ipv6

  Compiled without:

  Available nsock engines: kqueue poll select'
source_date: '2026-07-29'
documentation_source: local_help
tool:
  executable: nmap
  version_args:
  - --version
  help_args:
  - --help
  official_source: source.nmap.official
---

Nmap provides the bounded TCP discovery capability. Runtime use is permitted
only after the local binary and concise local guidance are verified for the
current immutable card.
