"""Source-integration guard only. Not an ESP build or hardware security test."""
from pathlib import Path
r=Path(__file__).resolve().parents[1]
m=(r/'src/main.cpp').read_text()
f=(r/'src/minirack_guest_firewall.cpp').read_text()
pol=(r/'include/minirack_guest_policy.h').read_text()
assert 'MiniRackGuestFirewall::beginInstall();' in m
assert 'MiniRackGuestFirewall::ready()' in m
assert 'mrSyncGuestFirewall();' in m
assert 'if(setPeerAllowed(selectedPeer,true))' in m
assert 'if(slot>=0){' in m and 'if(addPair(mac))continue;' in m
assert 'if(allowed && !isMyDevice(i) && !MiniRackGuestFirewall::ready())' in m
assert 'netif->input' not in f or 'n->input=filterInput;' in f
assert 'pbuf_copy_partial' in f
assert 'return ERR_VAL' in f
assert 'MiniRackGuestPolicy::allowFrame' in f
assert 'MiniRackGuestPolicy::Role::UNKNOWN' in f
assert 'publicIPv4' in pol
assert '0x3fff' in pol  # fragments
print('PASS: guest filter hook/roles/revocation integrated (static only)')
