from pathlib import Path
s=(Path(__file__).resolve().parents[1]/'pi/minirack_gateway_firewall.sh').read_text()
checks={
  'explicit apply confirmation':'--ack-existing-forwarding' in s,
  'no implicit ip_forward': 'sysctl -qw net.ipv4.ip_forward' not in s and 'sysctl -w net.ipv4.ip_forward' not in s,
  'no existing fw deletion without remove': 'nft delete table ip "$TABLE"' in s and '  --remove)' in s,
  'private ranges blocked':'ip daddr @blocked4 counter drop' in s,
  'anti-spoof path':'iifname "$WG_DEV" oifname "$WAN_DEV" ip saddr $ESP_IP' in s,
  'scoped forward':'ip saddr $ESP_IP oifname != "$WAN_DEV" counter drop' in s,
  'atomic nft batch':'nft -f - <<RULES' in s,
  'no vpn changes':'wg set ' not in s and 'ip route add' not in s,
}
for label,ok in checks.items():print(('PASS' if ok else 'FAIL')+': '+label)
assert all(checks.values())
