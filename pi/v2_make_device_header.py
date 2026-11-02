#!/usr/bin/env python3
"""Create the per-device private ESP32 header from local V2 enrollment.
Run on your PRIVATE machine, never share generated header with anyone.
"""
import argparse
import json
from pathlib import Path
import re

p=argparse.ArgumentParser()
p.add_argument('--device-provision',required=True)
p.add_argument('--gateway',default='SA-TOWER')
p.add_argument('--out',required=True)
a=p.parse_args()
obj=json.loads(Path(a.device_provision).read_text())
if obj.get('role')!='device':raise SystemExit('Not a device enrollment file')
for value in (obj['device_id'],a.gateway):
    if not re.fullmatch(r'[A-Za-z0-9_-]{3,64}',value):raise SystemExit('Bad identifier')
if not re.fullmatch(r'[0-9a-f]{64}',obj['key_hex']):raise SystemExit('Bad key')
dst=Path(a.out)
if dst.exists():raise SystemExit('Refusing to overwrite the header')
dst.write_text('#pragma once\n' +
               f'#define MINIRACK_V2_DEVICE_ID "{obj["device_id"]}"\n' +
               f'#define MINIRACK_V2_DEVICE_KEY_HEX "{obj["key_hex"]}"\n' +
               f'#define MINIRACK_V2_GATEWAY_ID "{a.gateway}"\n')
dst.chmod(0o600)
print('Generated private header:',dst,'(do not share)')
