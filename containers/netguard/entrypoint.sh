#!/bin/sh
# Ariadne netguard — nftables-based egress firewall for Kali and ZAP containers.
#
# Flushes its dedicated nftables table, applies allowlist rules, rate
# ceilings, and a default-drop policy. Accepted traffic includes:
#   - established / related connections
#   - loopback (lo)
#   - Docker DNS (127.0.0.11:53)
#   - explicitly confirmed target addresses and ports (injected via
#     ARIADNE_ALLOW_TARGETS env, format: "<ip>:<port> <ip>:<port> ...")
#
# All denied destinations are logged without payloads.
set -eu

NFT="/usr/sbin/nft"
TABLE="ariadne-netguard"

# Flush and recreate the table
$NFT flush table inet "$TABLE" 2>/dev/null || true
$NFT add table inet "$TABLE"

# Chains
$NFT add chain inet "$TABLE" input   { type filter hook input   priority 0\; policy drop\; }
$NFT add chain inet "$TABLE" forward { type filter hook forward priority 0\; policy drop\; }
$NFT add chain inet "$TABLE" output  { type filter hook output  priority 0\; policy drop\; }

# ── Allow established / related ──
$NFT add rule inet "$TABLE" input   ct state established,related accept
$NFT add rule inet "$TABLE" output  ct state established,related accept
$NFT add rule inet "$TABLE" forward ct state established,related accept

# ── Allow loopback ──
$NFT add rule inet "$TABLE" input  iif lo accept
$NFT add rule inet "$TABLE" output oif lo accept

# ── Allow Docker DNS (127.0.0.11:53, the embedded resolver) ──
$NFT add rule inet "$TABLE" output  ip daddr 127.0.0.11 udp dport 53 accept
$NFT add rule inet "$TABLE" output  ip daddr 127.0.0.11 tcp dport 53 accept

# ── Allow confirmed target addresses ──
# ARIADNE_ALLOW_TARGETS is a space-separated list of "ip:port" entries.
# Example: ARIADNE_ALLOW_TARGETS="10.10.10.10:443 10.10.10.10:80 10.10.10.20:8080"
if [ -n "${ARIADNE_ALLOW_TARGETS:-}" ]; then
    for entry in $ARIADNE_ALLOW_TARGETS; do
        case "$entry" in
            *:*)
                addr="${entry%:*}"
                port="${entry##*:}"
                # Rate-limit only explicitly confirmed TCP targets.  This
                # rule drops over-limit SYNs; it never permits a new target.
                $NFT add rule inet "$TABLE" output \
                    ip daddr "$addr" tcp dport "$port" tcp flags syn limit rate over 100/second drop
                # Allow TCP egress to the confirmed target/port.
                $NFT add rule inet "$TABLE" output \
                    ip daddr "$addr" tcp dport "$port" accept
                # Allow UDP as well (DNS queries to target, etc.)
                $NFT add rule inet "$TABLE" output \
                    ip daddr "$addr" udp dport "$port" accept
                ;;
        esac
    done
fi

# ── Log denied egress (no payloads) ──
$NFT add rule inet "$TABLE" output log prefix \"ARIADNE-DENY-OUT: \" group 0 drop

# ── Default drop (already set by chain policy, but explicit never hurts) ──
# Input, forward, and output chain policies are all "drop" from declaration above.

# Keep the shared network namespace alive for Kali/ZAP after rules are loaded.
exec tail -f /dev/null
