#!/usr/bin/env bash
# Mini Rack V1 end-to-end PRE-FLIGHT (read-only, NO system changes).
set -u
WG="${MINIRACK_WG_DEV:-wg0}"
WAN="${MINIRACK_WAN_DEV:-}"
ESP="${MINIRACK_ESP_WG_IPV4:-10.10.0.3}"
msg(){ printf '%s\n' "$*"; }
warn(){ msg "[CHECK] $*"; }
pass(){ msg "[OK] $*"; }
command -v ip >/dev/null || { msg 'ERROR: ip command missing'; exit 2; }
msg '=== MINI RACK V1 / PI READ-ONLY CHECK ==='
msg 'No configuration, firewall, forwarding or VPN state will change.'
if ip link show dev "$WG" >/dev/null 2>&1; then pass "WireGuard device $WG exists"; else warn "WireGuard device $WG absent"; fi
if ip -4 addr show dev "$WG" 2>/dev/null | grep -q 'inet '; then pass 'WG has an IPv4 address'; else warn 'WG IPv4 address missing'; fi
if command -v wg >/dev/null; then
  if sudo -n wg show "$WG" allowed-ips 2>/dev/null | grep -Fq "$ESP/32"; then
    pass "Pi WG contains expected ESP peer $ESP/32"
  else
    warn "Cannot verify peer $ESP/32 (sudo permission may be needed)."
  fi
else warn 'wg binary missing'; fi
if [ -z "$WAN" ]; then WAN="$(ip -4 route show default | awk 'NR==1 {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1);exit}}')"; fi
if [ -n "$WAN" ]; then pass "Pi default WAN interface currently $WAN"; else warn 'No IPv4 default route'; fi
if [ -r /proc/sys/net/ipv4/ip_forward ]; then
  FWD="$(cat /proc/sys/net/ipv4/ip_forward)"
  if [ "$FWD" = 1 ]; then pass 'IPv4 forwarding currently on'; else warn 'IPv4 forwarding currently off; tunnel Internet egress will not work'; fi
else warn 'Cannot read /proc/sys/net/ipv4/ip_forward'; fi
if command -v nft >/dev/null; then
  if sudo -n nft list table ip minirack_v1_gateway >/dev/null 2>&1; then
    pass 'Scoped Mini Rack nftables gateway table found'
  else
    warn 'Scoped Mini Rack nftables gateway table not present or cannot inspect'
  fi
else warn 'nft binary missing'; fi
msg 'Important: interface/forwarding checks are NOT proof that phone traffic exits via home.'
msg 'Check Pi wg counters AND a phone public IPv4 test during a controlled session.'
msg 'Do not publish these diagnostics if they contain private IPs or public hostnames.'
