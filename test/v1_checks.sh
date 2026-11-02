#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
bash test/run_checks.sh
for home in 0 1; do
  for experiment in 0 1; do
    g++ -std=c++17 -Wall -Wextra -Werror -Iinclude \
      -DMINIRACK_HOME_EGRESS_REQUIRED="$home" \
      -DMINIRACK_HOME_TUNNEL_EXPERIMENT="$experiment" \
      test/home_egress_test.cpp -o "/tmp/mr_v1_home_${home}_${experiment}"
    "/tmp/mr_v1_home_${home}_${experiment}"
  done
done
python3 - <<'PY'
from pathlib import Path
p=Path('src/main.cpp').read_text()
assert 'MiniRackHomeRoute::linkReady()' in p
assert 'HOME ROUTE: TEST REQUIRED' in p
assert 'WG INIT (UNVERIFIED)' in p
assert 'GUEST: PUBLIC INTERNET ONLY' in p
assert 'MiniRackGuestFirewall::ready()' in p
print('PASS: runtime diagnostics, home-only gated, guest packet filter')
PY

python3 test/guest_runtime_static_test.py
python3 test/owner_management_auth_test.py
python3 test/gateway_firewall_checks.py
bash -n pi/minirack_gateway_firewall.sh
bash -n pi/diagnose_v1.sh
python3 test/merge_smoke_test.py

python3 test/platformio_config_test.py

g++ -std=c++17 -Wall -Wextra -Werror -Iinclude test/guest_security_regression.cpp -o /tmp/mr_v1_guest_security
/tmp/mr_v1_guest_security
bash -n pi/VERIFY_HOME_READONLY.sh
