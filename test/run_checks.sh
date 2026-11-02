#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 test/source_checks.py
for name in registry owner_devices; do
    g++ -std=c++17 -Wall -Wextra -Werror -Itest/shims -Iinclude \
        "test/${name}_test.cpp" src/minirack_peers.cpp -o "/tmp/mr_stage17_${name}"
    "/tmp/mr_stage17_${name}"
done
for name in nat_admission reconnect_policy guest_firewall_policy; do
    g++ -std=c++17 -Wall -Wextra -Werror -Iinclude \
        "test/${name}_test.cpp" -o "/tmp/mr_stage17_${name}"
    "/tmp/mr_stage17_${name}"
    echo "PASS: ${name} policy"
done
for option in 0 1; do
    g++ -std=c++17 -Wall -Wextra -Werror -Iinclude \
        -DMINIRACK_HOME_EGRESS_REQUIRED="$option" \
        test/egress_policy_test.cpp -o "/tmp/mr_stage17_egress_${option}"
    "/tmp/mr_stage17_egress_${option}"
done
