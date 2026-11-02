#!/usr/bin/env bash
# Pi-side NAT adapter for OWNER-ONLY Mini Rack AP over WireGuard.
# NO AP guest firewall. IPv4 ONLY. NOT persistent. Dry-run by default.
set -euo pipefail
WG_DEV="${WG_DEV:-wg0}"
ESP_WG_IPV4="${ESP_WG_IPV4:-10.10.0.3}"
WAN_DEV="${WAN_DEV:-$(ip -4 route show default | awk 'NR==1 {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1);exit}}')}"
if [[ ! "$WG_DEV" =~ ^[[:alnum:]_.-]+$ || ! "$WAN_DEV" =~ ^[[:alnum:]_.-]+$ ||
      ! "$ESP_WG_IPV4" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo 'Invalid interface or IPv4 argument' >&2; exit 1
fi
if [[ $# -eq 0 || "${1:-}" == '--dry-run' ]]; then
  echo 'DRY RUN. No Pi settings are modified.'
  echo "WAN_DEV=$WAN_DEV  WG_DEV=$WG_DEV  ESP_WG_IPV4=$ESP_WG_IPV4"
  echo "Required: IPv4 forwarding enabled, WG peer AllowedIPs includes $ESP_WG_IPV4/32"
  echo "Required: existing firewall permits FORWARD from $WG_DEV to $WAN_DEV and established replies"
  echo "Proposed extra nft NAT table: ip minirack_v1; masquerade $ESP_WG_IPV4/32 -> $WAN_DEV"
  echo 'Existing filter chains may still DROP traffic; no automatic firewall bypass.'
  echo 'Run --apply only after reviewing existing Pi rules (VPN/strongSwan must keep working).'
  exit 0
fi
if [[ "${1:-}" == '--remove' ]]; then
  if (( EUID != 0 )); then echo 'Run with sudo' >&2;exit 1;fi
  nft list table ip minirack_v1 >/dev/null 2>&1 && nft delete table ip minirack_v1 || true
  echo 'Removed only the Mini Rack NAT table. IP forwarding left unchanged.'
  exit 0
fi
if [[ "${1:-}" != '--apply' || "${2:-}" != '--i-reviewed-my-firewall' ]]; then
  echo 'Use --dry-run, --apply --i-reviewed-my-firewall, or --remove' >&2
  exit 2
fi
if (( EUID != 0 )); then echo 'Run with sudo' >&2; exit 1;fi
command -v nft >/dev/null || { echo 'nft missing' >&2; exit 1; }
ip link show "$WAN_DEV" >/dev/null
ip link show "$WG_DEV" >/dev/null
if [[ "$(sysctl -n net.ipv4.ip_forward)" != 1 ]]; then
  echo 'net.ipv4.ip_forward=0. Enable and audit forwarding separately; no changes made.' >&2
  exit 1
fi
if nft list table ip minirack_v1 >/dev/null 2>&1; then
  echo 'Existing Mini Rack NAT table found. Remove it with --remove before re-applying.' >&2
  exit 1
fi
backup="/root/minirack-before-nat-$(date +%Y%m%d-%H%M%S).nft"
nft list ruleset > "$backup"
nft -f - <<RULES
add table ip minirack_v1
add chain ip minirack_v1 postrouting { type nat hook postrouting priority srcnat; policy accept; }
add rule ip minirack_v1 postrouting oifname "$WAN_DEV" ip saddr $ESP_WG_IPV4/32 masquerade
RULES
printf 'Added *only* NAT rule for %s via %s. Backup: %s\n' "$ESP_WG_IPV4" "$WAN_DEV" "$backup"
echo 'NOT sufficient alone: existing forward firewall policies and actual client routing must be tested.'
