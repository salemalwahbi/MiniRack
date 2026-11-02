from pathlib import Path
p = Path(__file__).resolve().parent.parent
s = (p/'src/main.cpp').read_text()
start = s.index('void loop() {')
part = s[start:start+3000]
assert part.index('enforcePairing();') < part.index('vpnService();') < part.index('miniNatService();')
script = (p/'pi/gateway_safe_trial.sh').read_text()
assert 'MODE="${1:---plan}"' in script
assert '--ack-global-forward-risk' in script
assert 'trap cleanup EXIT' in script
assert 'ip saddr 10.10.0.3 ip daddr @private4 counter drop' in script
print('PASS: route state checked before NAT, Pi script default read-only and scoped')
