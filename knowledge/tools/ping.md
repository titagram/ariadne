---
schema_version: 1
id: tool.ping
kind: tool
title: iputils ping
next: []
requires: []
policy:
- preflight.check
provenance:
- source.ping.official
status: runtime_verified
version: "ping: unrecognized option `--version'\nusage: ping [-AaDdfnoQqRrv] [-c count]\
  \ [-G sweepmaxsize]\n            [-g sweepminsize] [-h sweepincrsize] [-i wait]\n\
  \            [-l preload] [-M mask | time] [-m ttl] [-p pattern]\n            [-S\
  \ src_addr] [-s packetsize] [-t timeout][-W waittime]\n            [-z tos] host\n\
  \       ping [-AaDdfLnoQqRrv] [-c count] [-I iface] [-i wait]\n            [-l preload]\
  \ [-M mask | time] [-m ttl] [-p pattern] [-S src_addr]\n            [-s packetsize]\
  \ [-T ttl] [-t timeout] [-W waittime]\n            [-z tos] mcast-group\nApple specific\
  \ options (to be specified before mcast-group or host like all options)\n      \
  \      -b boundif           # bind the socket to the interface\n            -k traffic_class\
  \     # set traffic class socket option\n            -K net_service_type  # set\
  \ traffic class socket options\n            --apple-connect      # call connect(2)\
  \ in the socket\n            --apple-time         # display current time\n     \
  \       --apple-print-id     # display echo ID\n            --apple-print-req  \
  \  # display echo request"
source_date: '2026-07-29'
documentation_source: local_help
tool:
  executable: ping
  version_args:
  - --version
  help_args:
  - --help
  official_source: source.ping.official
---

Bounded reachability probe used by environment preflight.
