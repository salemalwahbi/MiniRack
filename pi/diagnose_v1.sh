#!/usr/bin/env bash
# READ ONLY snapshot. Do not print VPN keys or privileged configs.
set -uo pipefail
export LC_ALL=C
printf '%s\n' 'Mini Rack V1 — read-only Pi snapshot' '--- IPv4 forwarding ---'
sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 'unknown'
printf '%s\n' '--- Interfaces ---'
ip -br -4 addr show wg0 wlan0 2>/dev/null || true
printf '%s\n' '--- Default IPv4 route ---'
ip -4 route show default 2>/dev/null || true
printf '%s\n' '--- WireGuard public metadata (no keys) ---'
wg show wg0 latest-handshakes 2>/dev/null || true
wg show wg0 transfer 2>/dev/null || true
printf '%s\n' '--- Mini Rack nft rules ---'
if command -v nft >/dev/null; then
  nft -a list table ip minirack_v1_gateway 2>/dev/null || echo 'No persistent gateway table.'
  nft -a list table ip minirack_v1_trial 2>/dev/null || echo 'No temporary trial table.'
else echo 'nft unavailable'; fi
printf '%s\n' '--- Safe verdict ---' 'A handshake/link is NOT proof of AP client egress or guest isolation.'
