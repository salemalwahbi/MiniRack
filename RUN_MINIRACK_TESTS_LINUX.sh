#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
bash test/v1_checks.sh
python3 -m unittest discover -s test -p 'test_v2*.py' -v
python3 pi/v2_live_demo.py
