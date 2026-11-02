#!/usr/bin/env python3
"""One-command V2 functional demo: two countries, terrestrial/satellite, one plan.
Does not modify the existing Pi, ISP router, V1 firmware or Packet Tracer.
"""
import hmac
import json
from pathlib import Path
import tempfile
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import v2_subscription_core as core


def http_auth(url, device, gateway):
    signed = core.create_request(device, gateway)
    request = Request(url + "/v2/authorize", data=json.dumps(signed).encode(),
                      headers={"Content-Type": "application/json"}, method="POST")
    try:
        response = urlopen(request, timeout=5)
    except HTTPError as error:
        response = error
    with response:
        return response.status, json.load(response)


def run():
    print("Mini Rack V2 | entitlement live lab — real HTTP + SQLite + HMAC")
    with tempfile.TemporaryDirectory(prefix="minirack_v2_demo_") as root:
        state = str(Path(root) / "state")
        core.initialize(state)
        device_file = Path(root) / "device.json"
        core.enroll_device(state, "HOME-SUB-001", "One Home Plan", str(device_file))
        device = json.loads(device_file.read_text())
        gateways = []
        for gateway_id, country, access in (
                ("SA-TOWER", "SA", "terrestrial"),
                ("JP-TOWER", "JP", "terrestrial"),
                ("JP-SATELLITE", "JP", "satellite")):
            provision = Path(root) / (gateway_id + ".json")
            core.enroll_gateway(state, gateway_id, country, access, str(provision))
            gateways.append(json.loads(provision.read_text()))
        dbpath, keypath = core.state_paths(state)
        server = core.ThreadingHTTPServer(("127.0.0.1", 0), core.Handler)
        server.dbpath, server.key = dbpath, core.master_key(keypath)
        runner = threading.Thread(target=server.serve_forever, daemon=True)
        runner.start()
        url = "http://127.0.0.1:" + str(server.server_address[1])
        try:
            sessions = []
            for i, gateway in enumerate(gateways):
                code, message = http_auth(url, device, gateway)
                if code != 200 or message.get("decision") != "allow":
                    raise RuntimeError(f"authorization failed: HTTP {code}: {message}")
                signature = message.pop("device_response_sig")
                expected = core.sign(bytes.fromhex(device["key_hex"]), message)
                if not hmac.compare_digest(signature, expected):
                    raise RuntimeError("server response signature rejected")
                sessions.append(message["session_id"])
                print(f"{i + 1}. {message['country']} / {message['access']:11s} | ALLOW | "
                      f"account={message['account_id']} | session={message['session_id']}")
            for session, count in zip(sessions, (500, 1000, 1500)):
                core.record_usage(state, session, count // 2, count)
            print("\nConsolidated usage for ONE home-plan account:")
            core.status(state)
            core.set_active(state, "account", "HOME-SUB-001", 0)
            code, reply = http_auth(url, device, gateways[1])
            print(f"\nSuspend account -> HTTP {code}: {reply.get('reason')}")
            if code != 403:
                raise RuntimeError("fail-closed check failed")
            print("\nPASS: same account on three registered access points, signed device+gateway, "
                  "usage ledger, suspension of new authorizations")
            print("NOTE: locations and satellite access are REGISTERED LAB GATEWAYS; no physical "
                  "international/space transport was used.")
        finally:
            server.shutdown()
            server.server_close()
            runner.join(timeout=2)


if __name__ == "__main__":
    run()
