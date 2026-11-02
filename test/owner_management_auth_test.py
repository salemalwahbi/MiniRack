#!/usr/bin/env python3
"""Source regression for owner-only Wi-Fi configuration endpoints.
These assertions do not prove Wi-Fi MAC cryptographic authenticity.
"""
from pathlib import Path
s=(Path(__file__).resolve().parents[1]/'src/main.cpp').read_text()
a=s[s.index('static bool requirePortalAuth() {'):s.index('static void noteHttpRequest(')]
assert '!primaryMac.isEmpty() && !isOwnerBrowser(portal.client().remoteIP())' in a
assert 'windowOpen(portalOpenUntil)' in a
assert 'submitted!=pin' in a
assert a.index('isOwnerBrowser(') < a.index('submitted!=pin')
for route in ('/wifi/connect', '/ap/change'):
    r=s[s.index('portal.on("'+route+'"'):]
    assert 'if(!requirePortalAuth())return;' in r.split('});',1)[0]
h=s[s.index('static void sendPortalHome(){'):][:1200]
assert '!primaryMac.isEmpty() && !isOwnerBrowser(portal.client().remoteIP())' in h
print('PASS: owner-only configuration and setup window/PIN policy (source check)')
