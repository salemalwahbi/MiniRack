from pathlib import Path
root=Path(__file__).resolve().parents[1]
m=(root/'src/main.cpp').read_text()
p=(root/'src/minirack_peers.cpp').read_text()
checks={
 'separate categories': 'View::MY_DEVICES' in m and 'View::GUESTS' in m and 'drawDeviceGroupArea()' in m,
 'automatic pairing window': 'pendingPairUntil=millis()+120000;' in m and 'go(View::PAIR_CHOICE);' in m,
 'VPN heading': 'eng(102,54,"VPN",WHITE,2)' in m,
 'no MORE navigation': 'scanPage*4' not in m and 'drawWifiListArea()' in m,
 'finger scroll group': 'groupDeviceCount(view),PEERS_PER_PAGE' in m,
 'back to category': 'go(userReturnView);return;' in m,
 'touch-approved owner promotion': 'if(promoteToMyDevices(selectedPeer))' in m and 'go(View::MY_DEVICES);' in m,
 'guest uses packet filter': 'MiniRackGuestFirewall::ready()' in m and 'if(setPeerAllowed(selectedPeer,true))' in m,
 'owner VPN only': 'if(!(isPrimary(selectedPeer) || (forExtraDevice && peerRegistry.isOwnerDevice(selectedPeer))))ownerQrBlock=4;' in m,
 'no owner key revocation on unassign': 'db_->remove("ownerid")' not in p.split('bool Registry::clearPrimary()')[1].split('int Registry::addPending')[0],
 'all braces balanced':m.count('{')==m.count('}'),
 'bounded WiFi reconnect': 'MiniRackReconnect::due(' in m and 'WiFi.reconnect();' in m,
 'public endpoint optional': '#ifdef WG_SERVER_HOST' in m and 'MDNS.queryHost(MINIRACK_PI_MDNS_HOST' in m,
 'one-time rebind same owner slot': 'rebindAuthorizedDevice(slot,newMac)' in m and 'oldMac=peerMacs[slot]' in m,
 'extra device QR': 'openOwnerSetup(true)' in m and 'relinkExtraDevice' in m,
 'strict NAT gate': 'MiniRackEgressPolicy::allowDirectNat(' in m,
 'no unauthorized guest NAT': 'MiniRackRoutePolicy::allowNat' in m and 'mrNatStationsAdmitted()' in m,
}
for name,success in checks.items():print(('PASS' if success else 'FAIL')+': '+name)
assert all(checks.values())
