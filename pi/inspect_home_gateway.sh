#!/usr/bin/env bash
# READ-ONLY. Run on Raspberry Pi; no credentials, private keys, or rules change.
set -uo pipefail
printf '\nMini Rack home gateway — read-only inspection\n'
printf '\n=== IPv4 default routes ===\n'
ip -4 route show default || true
printf '\n=== WireGuard interface (public keys suppressed) ===\n'
sudo wg show wg0 latest-handshakes 2>/dev/null | awk '{print "peer handshake_timestamp=" $2}' || echo 'wg0 unavailable'
printf '\n=== IPv4 forwarding ===\n'
sysctl net.ipv4.ip_forward 2>/dev/null || true
printf '\n=== nftables forwarding/NAT chains (review yourself) ===\n'
sudo nft list ruleset 2>/dev/null | grep -E '^table |^\s*chain |hook (forward|postrouting)|masquerade' | head -90 || true
printf '\n=== Home IPv4 (egress) ===\n'
curl -4fsS --max-time 5 https://api.ipify.org 2>/dev/null || echo 'IPv4 test unavailable'
printf '\n\nDo not publish private WireGuard keys or your bridge HMAC key.\n'
