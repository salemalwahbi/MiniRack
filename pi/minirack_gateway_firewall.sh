#!/usr/bin/env bash
# MINI RACK V1: scoped IPv4 forwarding + MASQUERADE for the ESP WireGuard peer.
# No guessed secrets, no edits to strongSwan, Tailscale, wg0, routes, or sysctl.
# Safe default: --plan (READ ONLY). A real --apply requires an explicit opt-in.
set -Eeuo pipefail
export LC_ALL=C
MODE="${1:---plan}"
WG_DEV="${MINIRACK_WG_DEV:-wg0}"
ESP_IP="${MINIRACK_ESP_WG_IPV4:-10.10.0.3}"
WAN_DEV="${MINIRACK_WAN_DEV:-}"
TABLE="minirack_v1_gateway"

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Missing dependency: $1"; }
if [[ ! "$WG_DEV" =~ ^[[:alnum:]_.-]{1,15}$ ||
      ! "$ESP_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ||
      ( -n "$WAN_DEV" && ! "$WAN_DEV" =~ ^[[:alnum:]_.-]{1,15}$ ) ]]; then
  fail 'Invalid interface/IP parameter'
fi
resolve_wan(){
  if [[ -z "$WAN_DEV" ]]; then
    WAN_DEV="$(ip -4 route show default | awk 'NR==1 {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')"
  fi
  [[ "$WAN_DEV" =~ ^[[:alnum:]_.-]{1,15}$ ]] || fail 'Cannot determine WAN device'
  [[ "$WAN_DEV" != "$WG_DEV" ]] || fail 'WAN and WireGuard device cannot be identical'
}
preflight(){
  for name in ip wg nft sysctl; do need "$name"; done
  resolve_wan
  ip link show dev "$WG_DEV" >/dev/null || fail "Missing $WG_DEV"
  ip link show dev "$WAN_DEV" >/dev/null || fail "Missing $WAN_DEV"
  local actual
  actual="$(ip -4 route show default | awk 'NR==1 {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')"
  [[ "$WAN_DEV" == "$actual" ]] || fail "WAN expected $WAN_DEV but default is $actual"
  ip -4 addr show dev "$WG_DEV" | grep -q 'inet 10\.10\.0\.1/' || fail 'WG local IP must be 10.10.0.1'
  wg show "$WG_DEV" allowed-ips | grep -Fq "$ESP_IP/32" || fail "WG peer $ESP_IP/32 missing"
}
readable_plan(){
  cat <<'PLAN'
Mini Rack V1 gateway — scoped firewall/NAT (IPv4 ONLY)
--plan: READ ONLY. --apply never touches WireGuard, strongSwan, Tailscale,
       systemd services, routes or IPv4 forwarding value.
Rules: ESP 10.10.0.3/32 arriving on wg0 may forward only via home's WAN;
       RFC1918, loopback, CGNAT, link-local, multicast are blocked;
       masquerade only 10.10.0.3/32 received on wg0, leaving WAN.
CAUTION: Accept in our base chain does NOT override DROP in another firewall
         chain. Global ip_forward MUST already equal 1 for --apply.
No AP-side guest isolation or packet-level ESP leak prevention is provided.
PLAN
}
case "$MODE" in
  --plan)
    readable_plan
    if command -v ip >/dev/null 2>&1; then
      resolve_wan
      printf 'WG=%s ESP=%s WAN=%s\n' "$WG_DEV" "$ESP_IP" "$WAN_DEV"
      echo "Default: $(ip -4 route show default | head -1)"
    fi
    if command -v sysctl >/dev/null 2>&1; then
      echo "IPv4 forwarding: $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo unknown)"
    fi
    echo 'No changes made.'
    ;;
  --status)
    preflight
    echo "WG=$WG_DEV ESP=$ESP_IP WAN=$WAN_DEV"
    echo "IPv4 forwarding: $(sysctl -n net.ipv4.ip_forward)"
    nft -a list table ip "$TABLE" 2>/dev/null || echo 'Not installed.'
    ;;
  --apply)
    [[ "${2:-}" == '--ack-existing-forwarding' ]] || fail 'Use --apply --ack-existing-forwarding'
    [[ $EUID == 0 ]] || fail 'Run with sudo'
    preflight
    [[ "$(sysctl -n net.ipv4.ip_forward)" == 1 ]] || fail 'Global ip_forward=0; review other VPN firewall chains first. No changes made.'
    if nft list table ip "$TABLE" >/dev/null 2>&1; then fail "Existing $TABLE table: use --status/--remove"; fi
    # Atomic batch, no partial rule installation. A separate earlier firewall
    # can still reject the allowed flow; never claim connectivity from an ACCEPT.
    nft -f - <<RULES
add table ip $TABLE
add set ip $TABLE blocked4 { type ipv4_addr; flags interval; elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } ; }
add chain ip $TABLE forward { type filter hook forward priority -50; policy accept; }
add rule ip $TABLE forward iifname "$WG_DEV" ip saddr $ESP_IP ip daddr @blocked4 counter drop
add rule ip $TABLE forward iifname "$WG_DEV" ip saddr $ESP_IP oifname != "$WAN_DEV" counter drop
add rule ip $TABLE forward iifname "$WG_DEV" ip saddr $ESP_IP oifname "$WAN_DEV" counter accept
add chain ip $TABLE postrouting { type nat hook postrouting priority srcnat; policy accept; }
add rule ip $TABLE postrouting iifname "$WG_DEV" oifname "$WAN_DEV" ip saddr $ESP_IP counter masquerade
RULES
    printf 'Installed only %s. NOT persistent across reboot. Use --status to inspect.\n' "$TABLE"
    echo 'Run traffic tests before claiming the home tunnel is carrying clients.'
    ;;
  --remove)
    [[ $EUID == 0 ]] || fail 'Run with sudo'
    need nft
    if nft list table ip "$TABLE" >/dev/null 2>&1; then
      nft delete table ip "$TABLE"
      echo 'Removed Mini Rack gateway table only. Existing sysctl/firewall untouched.'
    else echo 'No Mini Rack table installed.'; fi
    ;;
  *) fail 'Usage: --plan | --status | --apply --ack-existing-forwarding | --remove' ;;
esac
