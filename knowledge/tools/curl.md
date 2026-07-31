---
schema_version: 1
id: tool.curl
kind: tool
title: curl
next: []
requires: []
policy:
- web.content_discovery
provenance:
- source.curl.official
status: runtime_verified
version: 'curl 8.7.1 (x86_64-apple-darwin25.0) libcurl/8.7.1 (SecureTransport) LibreSSL/3.3.6
  zlib/1.2.12 nghttp2/1.68.1

  Release-Date: 2024-03-27

  Protocols: dict file ftp ftps gopher gophers http https imap imaps ipfs ipns ldap
  ldaps mqtt pop3 pop3s rtsp smb smbs smtp smtps telnet tftp

  Features: alt-svc AsynchDNS GSS-API HSTS HTTP2 HTTPS-proxy IPv6 Kerberos Largefile
  libz MultiSSL NTLM SPNEGO SSL threadsafe UnixSockets'
source_date: '2026-07-30'
documentation_source: local_help
tool:
  executable: curl
  version_args:
  - --version
  help_args:
  - --help
  official_source: source.curl.official
---

Official curl client used for a bounded same-host HTML fallback.
