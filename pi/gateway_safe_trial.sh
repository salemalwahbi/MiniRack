#!/usr/bin/env bash
# Mini Rack V1: guarded, temporary Pi owner tunnel forwarding test.
# Defaults to read-only. No persistent modification. Does not enable guests.
set -Eeuo pipefail
export LC_ALL=C
WG_DEV=wg0
WAN_DEV=wlan0
ESP_IP=10.10.0.3
TABLE=minirack_v1_trial
DURATION=120
MODE="${1:---plan}"

say() { printf '%s\n' "$*"; }
require_root() { if (( EUID != 0 )); then say 'Use sudo for this operation' >&2; exit 1; fi; }
check_dependencies() {
  for cmd in ip nft sysctl wg; do
    command -v "$cmd" >/dev/null || { say "Missing: $cmd" >&2; exit 1; }
  done
}
preflight() {
  check_dependencies
  ip link show dev "$WG_DEV" >/dev/null || { say 'WireGuard wg0 missing' >&2; return 1; }
  ip link show dev "$WAN_DEV" >/dev/null || { say 'Home wlan0 missing' >&2; return 1; }
  local default_dev
  default_dev="$(ip -4 route show default | awk 'NR==1 {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')"
  [[ "$default_dev" == "$WAN_DEV" ]] || { say "Default WAN is '$default_dev', expected '$WAN_DEV'" >&2; return 1; }
  ip -4 addr show dev "$WG_DEV" | grep -q 'inet 10.10.0.1/' || {
    say 'Unexpected wg0 address; expected 10.10.0.1' >&2; return 1;
  }
  wg show "$WG_DEV" allowed-ips | grep -Eq '(^|[[:space:]])10\.10\.0\.3/32([[:space:]]|$)' || {
    say 'ESP WireGuard peer 10.10.0.3/32 not found' >&2; return 1;
  }
  if nft list table ip "$TABLE" >/dev/null 2>&1; then
    say "A $TABLE table already exists. Do not override existing trial." >&2; return 1;
  fi
}
show_plan() {
  say 'MINIRACK V1 GATEWAY PREFLIGHT (read-only)'
  say "ESP=$ESP_IP/32  WG=$WG_DEV  WAN=$WAN_DEV"
  say "Current IPv4 forwarding: $(sysctl -n net.ipv4.ip_forward)"
  say "Forward policy: $(iptables -S FORWARD 2>/dev/null | head -1 || true)"
  say "Default route: $(ip -4 route show default | head -1)"
  say 'Temporary trial would add OWN nft table only, block ESP -> home/private ranges,'
  say 'NAT ESP /32 through wlan0, and temporarily enable IPv4 forwarding.'
  say 'CAUTION: sysctl ip_forward=1 is GLOBAL; other pre-existing FORWARD ACCEPT rules'
  say 'could permit forwarding on other interfaces. Existing VPN and Tailscale are not altered.'
  say 'ESP must independently NAT AP clients into wg0 and be tested; this script CANNOT do it.'
  say 'No commands have been applied.'
}

PREVIOUS_FORWARD=""
ACTIVE=0
cleanup() {
  if (( ACTIVE )); then
    nft delete table ip "$TABLE" >/dev/null 2>&1 || true
    if [[ -n "$PREVIOUS_FORWARD" ]]; then
      sysctl -qw net.ipv4.ip_forward="$PREVIOUS_FORWARD" || true
    fi
    ACTIVE=0
    say 'Mini Rack temporary gateway rules removed; original IPv4 forwarding restored.'
  fi
}

case "$MODE" in
  --plan)
    show_plan
    preflight
    say 'PASS: prerequisites found (no settings changed)'
    ;;
  --trial)
    # Explicit acknowledgement is needed because this changes GLOBAL forwarding temporarily.
    [[ "${2:-}" == '--ack-global-forward-risk' ]] || {
      say 'Trial refused. Require: --trial --ack-global-forward-risk' >&2
      say 'GLOBAL IPv4 forwarding can affect other interfaces with FORWARD ACCEPT.' >&2
      exit 2
    }
    require_root
    preflight
    PREVIOUS_FORWARD="$(sysctl -n net.ipv4.ip_forward)"
    [[ "$PREVIOUS_FORWARD" =~ ^[01]$ ]] || { say 'Invalid original ip_forward state' >&2; exit 1; }
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    # Prevent direct access to home RFC1918/CGNAT/link-local destinations from the ESP.
    # Strictly scoped to ESP /32; do not alter existing Tailscale/IPsec chains.
    nft -f - <<'NFT'
add table ip minirack_v1_trial
add set ip minirack_v1_trial private4 { type ipv4_addr; flags interval; elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } ; }
add chain ip minirack_v1_trial forward { type filter hook forward priority -30; policy accept; }
add rule ip minirack_v1_trial forward iifname "wg0" ip saddr 10.10.0.3 ip daddr @private4 counter drop
add rule ip minirack_v1_trial forward iifname "wg0" ip saddr 10.10.0.3 oifname != "wlan0" counter drop
add rule ip minirack_v1_trial forward iifname "wg0" ip saddr 10.10.0.3 oifname "wlan0" counter accept
add chain ip minirack_v1_trial postrouting { type nat hook postrouting priority 110; policy accept; }
add rule ip minirack_v1_trial postrouting oifname "wlan0" ip saddr 10.10.0.3 counter masquerade
NFT
    ACTIVE=1
    sysctl -qw net.ipv4.ip_forward=1
    say 'Trial active for 120 seconds. Keep this terminal open. Ctrl+C restores settings.'
    say 'This does NOT enable guests or prove that ESP client traffic is tunneled.'
    sleep "$DURATION"
    ;;
  --status)
    show_plan
    nft list table ip "$TABLE" 2>/dev/null || say 'No Mini Rack trial rules are present.'
    ;;
  *)
    say 'Usage: bash gateway_safe_trial.sh --plan | --status' >&2
    say '       sudo bash gateway_safe_trial.sh --trial --ack-global-forward-risk' >&2
    exit 2
    ;;
esac
