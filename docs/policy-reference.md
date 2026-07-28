# Ariadne Policy Reference

## Overview

Effective permission is computed as a monotonic intersection:

```
base policy ∩ environment profile ∩ engagement snapshot ∩ action plan
```

The base policy declares universal invariants. The environment profile
(`private-lab` or `htb`) may restrict a capability but may **never** expand
one. The engagement snapshot adds per-run constraints. The action plan's
requested dimensions are validated against the intersected effective policy.

Each capability rule has the following fields:

| Field              | Type      | Description                                                          |
|--------------------|-----------|----------------------------------------------------------------------|
| `allowed`          | bool      | Whether the capability is permitted (default: `false` — fail-closed)|
| `always_manual`    | bool      | Whether the capability always requires direct user approval          |
| `max_rate`         | int\|null | Maximum requests/operations per second                               |
| `max_concurrency`  | int\|null | Maximum concurrent operations                                        |
| `max_attempts`     | int\|null | Maximum retry attempts                                               |
| `max_duration_seconds` | int\|null | Maximum wall-clock duration                                      |
| `max_output_bytes` | int\|null | Maximum output size                                                  |
| `allowed_tools`    | list[str] | Explicitly permitted tool names (empty = unrestricted within policy) |

`null` means that layer places no restriction; the intersection preserves the
more restrictive value from any layer.

---

## Capabilities

### Passive discovery

**Capability:** `passive.discovery`

Non-intrusive information gathering through DNS, WHOIS, and packet capture.

| Field | Base | HTB | Private Lab |
|-------|------|-----|-------------|
| allowed | true | (inherited) | (inherited) |
| max_rate | 10 | (inherited) | (inherited) |
| max_concurrency | 2 | (inherited) | (inherited) |
| max_duration | 86400s | (inherited) | (inherited) |
| max_output | 10 MB | (inherited) | (inherited) |
| allowed_tools | dig, dnsrecon, whois, tcpdump | (inherited) | (inherited) |

---

### TCP Scan

**Capability:** `scan.tcp`

Port scanning using TCP connect, SYN, or similar techniques.

| Field | Base | HTB | Private Lab |
|-------|------|-----|-------------|
| allowed | true | true | true |
| max_rate | 500 | 500 | 2000 |
| max_concurrency | 10 | 10 | 25 |
| max_duration | 3600s | (inherited) | 7200s |
| max_output | 50 MB | (inherited) | (inherited) |
| allowed_tools | nmap, masscan, naabu, unicornscan | (inherited) | (inherited) |

---

### UDP Scan

**Capability:** `scan.udp`

Port scanning using UDP probes.

| Field | Base | HTB | Private Lab |
|-------|------|-----|-------------|
| allowed | true | (inherited) | (inherited) |
| max_rate | 100 | (inherited) | (inherited) |
| max_concurrency | 5 | (inherited) | (inherited) |
| max_duration | 3600s | (inherited) | (inherited) |
| max_output | 20 MB | (inherited) | (inherited) |
| allowed_tools | nmap, unicornscan | (inherited) | (inherited) |

---

### Service Enumeration

**Capability:** `service.enum`

Banner grabbing, service fingerprinting, and protocol-specific enumeration.

| Field | Base | HTB | Private Lab |
|-------|------|-----|-------------|
| allowed | true | (inherited) | (inherited) |
| max_rate | 50 | (inherited) | (inherited) |
| max_concurrency | 5 | (inherited) | (inherited) |
| max_attempts | 3 | (inherited) | (inherited) |
| max_duration | 3600s | (inherited) | (inherited) |
| max_output | 50 MB | (inherited) | (inherited) |
| allowed_tools | smbclient, rpcclient, enum4linux-ng, ldapsearch, snmpwalk, onesixtyone | (inherited) | (inherited) |

---

### Web Crawl

**Capability:** `web.crawl`

Directory and endpoint discovery.

| Field | Base | HTB | Private Lab |
|-------|------|-----|-------------|
| allowed | true | (inherited) | (inherited) |
| max_rate | 20 | (inherited) | (inherited) |
| max_concurrency | 3 | (inherited) | (inherited) |
| max_duration | 7200s | (inherited) | (inherited) |
| max_output | 50 MB | (inherited) | (inherited) |
| allowed_tools | katana, feroxbuster, ffuf | (inherited) | (inherited) |

---

### Web Passive Scan

**Capability:** `web.passive_scan`

HTTP fingerprinting, header analysis, and passive technology detection.

| Field | Base | HTB | Private Lab |
|-------|------|-----|-------------|
| allowed | true | (inherited) | (inherited) |
| max_rate | 20 | (inherited) | (inherited) |
| max_concurrency | 3 | (inherited) | (inherited) |
| max_duration | 7200s | (inherited) | (inherited) |
| max_output | 50 MB | (inherited) | (inherited) |
| allowed_tools | curl, httpx, whatweb, nuclei | (inherited) | (inherited) |

---

### Web Active Scan

**Capability:** `web.active_scan`

Active vulnerability scanning via ZAP and curated Nuclei workflows.

| Field | Base | HTB | Private Lab |
|-------|------|-----|-------------|
| allowed | true | (inherited) | (inherited) |
| max_rate | 10 | (inherited) | (inherited) |
| max_concurrency | 2 | (inherited) | (inherited) |
| max_attempts | 3 | (inherited) | (inherited) |
| max_duration | 14400s | (inherited) | (inherited) |
| max_output | 100 MB | (inherited) | (inherited) |
| allowed_tools | zap, nuclei | (inherited) | (inherited) |

---

### Web Fuzzing

**Capability:** `web.fuzz`

Parameter fuzzing, content discovery, and input testing.

| Field | Base | HTB | Private Lab |
|-------|------|-----|-------------|
| allowed | true | true | true |
| max_rate | 50 | 20 | 200 |
| max_concurrency | 5 | 3 | 10 |
| max_duration | 3600s | 3600s | 7200s |
| max_output | 50 MB | (inherited) | (inherited) |
| allowed_tools | ffuf, feroxbuster | (inherited) | (inherited) |

---

### Default Credential Check

**Capability:** `auth.default_creds`

Testing default and well-known credentials.

| Field | Base | HTB | Private Lab |
|-------|------|-----|-------------|
| allowed | true | (inherited) | (inherited) |
| max_rate | 10 | (inherited) | (inherited) |
| max_concurrency | 3 | (inherited) | (inherited) |
| max_attempts | 5 | (inherited) | (inherited) |
| max_duration | 1800s | (inherited) | (inherited) |
| max_output | 10 MB | (inherited) | (inherited) |
| allowed_tools | hydra, medusa, crackmapexec | (inherited) | (inherited) |

---

### Password Spray

**Capability:** `auth.spray`

Low-and-slow password spraying against identified accounts.

| Field | Base | HTB | Private Lab |
|-------|------|-----|-------------|
| allowed | true | (inherited) | (inherited) |
| max_rate | 5 | (inherited) | (inherited) |
| max_concurrency | 2 | (inherited) | (inherited) |
| max_attempts | 10 | (inherited) | (inherited) |
| max_duration | 3600s | (inherited) | (inherited) |
| max_output | 10 MB | (inherited) | (inherited) |
| allowed_tools | hydra, kerbrute | (inherited) | (inherited) |

---

### Brute Force

**Capability:** `auth.brute_force`

Offline or online brute force of authentication secrets. **Always requires
manual approval.**

| Field | Base | HTB | Private Lab |
|-------|------|-----|-------------|
| allowed | true | true | true |
| always_manual | true | true | true |
| max_rate | 3 | 2 | 10 |
| max_concurrency | 1 | 1 | 3 |
| max_attempts | 100 | 20 | 500 |
| max_duration | 7200s | 3600s | 14400s |
| max_output | 10 MB | (inherited) | (inherited) |
| allowed_tools | hydra, john, hashcat | (inherited) | (inherited) |

---

### Metasploit Exploitation

**Capability:** `exploit.metasploit`

Metasploit module search, info, check, and execution.

| Field | Base | HTB | Private Lab |
|-------|------|-----|-------------|
| allowed | true | (inherited) | (inherited) |
| max_rate | 3 | (inherited) | (inherited) |
| max_concurrency | 1 | (inherited) | (inherited) |
| max_attempts | 3 | (inherited) | (inherited) |
| max_duration | 3600s | (inherited) | (inherited) |
| max_output | 50 MB | (inherited) | (inherited) |
| allowed_tools | msfconsole | (inherited) | (inherited) |

---

### Curated Exploit

**Capability:** `exploit.curated`

Execution of versioned, curated exploit modules.

| Field | Base | HTB | Private Lab |
|-------|------|-----|-------------|
| allowed | true | (inherited) | (inherited) |
| max_rate | 3 | (inherited) | (inherited) |
| max_concurrency | 1 | (inherited) | (inherited) |
| max_attempts | 3 | (inherited) | (inherited) |
| max_duration | 3600s | (inherited) | (inherited) |
| max_output | 50 MB | (inherited) | (inherited) |

---

### Resource Stress

**Capability:** `resource.stress`

Bounded resource-stress testing. **Always requires manual approval.**

| Field | Base | HTB | Private Lab |
|-------|------|-----|-------------|
| allowed | true | **false** | true |
| always_manual | true | N/A | true |
| max_rate | 1000 | N/A | 5000 |
| max_concurrency | 50 | N/A | 50 |
| max_duration | 300s | N/A | 600s |
| max_output | 100 MB | N/A | (inherited) |

> Explicitly denied under the HTB profile per platform rules.

---

### Resource Exhaustion

**Capability:** `resource.exhaustion`

Bounded resource-exhaustion testing. **Always requires manual approval.**

| Field | Base | HTB | Private Lab |
|-------|------|-----|-------------|
| allowed | true | **false** | true |
| always_manual | true | N/A | true |
| max_rate | 1000 | N/A | 5000 |
| max_concurrency | 50 | N/A | 50 |
| max_duration | 300s | N/A | 600s |
| max_output | 100 MB | N/A | (inherited) |

> Explicitly denied under the HTB profile per platform rules.

---

### Base Invariants (Always Denied)

These capabilities exist in every policy but are always `allowed: false`:

- **`persistence`** — No persistent access mechanisms
- **`c2`** — No command-and-control infrastructure
- **`propagation`** — No automatic self-propagation

These invariants cannot be overridden by any environment profile.

---

### Host Installation

**Capability:** `host.install`

Installation of host tools (Docker, etc.). **Always requires manual approval.**

| Field | Base |
|-------|------|
| allowed | true |
| always_manual | true |

---

### Uncurated PoC

**Capability:** `poc.uncurated`

Execution of public, uncurated proof-of-concept code. **Always requires manual
approval.**

| Field | Base |
|-------|------|
| allowed | true |
| always_manual | true |

---

### Evidence Collection

**Capability:** `evidence.collect`

Collection of screenshots, transcripts, and artifacts.

| Field | Base |
|-------|------|
| allowed | true |
| max_rate | 50 |
| max_concurrency | 5 |
| max_output | 500 MB |
| allowed_tools | screenshot, curl, tcpdump |

---

### Cleanup

**Capability:** `cleanup`

Cleanup of temporary files, containers, and network resources.

| Field | Base |
|-------|------|
| allowed | true |
| max_rate | 50 |
| max_concurrency | 5 |
| max_duration | 600s |
| max_output | 10 MB |
