#!/usr/bin/env python3
"""Live HTTP + SQLite integration checks for the V2 entitlement proof of concept."""
import json
import os
from pathlib import Path
from contextlib import closing
import tempfile
import threading
import time
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pi"))
import v2_subscription_core as v2


class EntitlementIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mr_v2_")
        self.addCleanup(self.tmp.cleanup)
        self.state = str(Path(self.tmp.name) / "private")
        v2.initialize(self.state)
        self.device_path = Path(self.tmp.name) / "device-private.json"
        v2.enroll_device(self.state, "HOME-TEST-001", "Home Internet Entitlement",
                         str(self.device_path))
        self.device = json.loads(self.device_path.read_text())
        self.gateways = []
        for name, country, access in [("SA-TOWER-01", "SA", "terrestrial"),
                                      ("JP-TOWER-01", "JP", "terrestrial"),
                                      ("JP-SAT-01", "JP", "satellite")]:
            path = Path(self.tmp.name) / (name + ".json")
            v2.enroll_gateway(self.state, name, country, access, str(path))
            self.gateways.append(json.loads(path.read_text()))
        dbpath, keypath = v2.state_paths(self.state)
        self.http = v2.ThreadingHTTPServer(("127.0.0.1", 0), v2.Handler)
        self.http.dbpath = dbpath
        self.http.key = v2.master_key(keypath)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.url = "http://127.0.0.1:" + str(self.http.server_address[1])

    def close_server(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(timeout=2)

    def post(self, request):
        payload = json.dumps(request).encode("utf-8")
        req = Request(self.url + "/v2/authorize", data=payload,
                      headers={"Content-Type": "application/json"}, method="POST")
        try:
            resp = urlopen(req, timeout=4)
        except HTTPError as e:
            resp = e
        with resp:
            return resp.status, json.load(resp)

    def test_home_subscription_survives_country_and_link_changes(self):
        session_ids = []
        for gateway in self.gateways:
            status, resp = self.post(v2.create_request(self.device, gateway))
            self.assertEqual(status, 200)
            self.assertEqual(resp["decision"], "allow")
            self.assertEqual(resp["account_id"], "HOME-TEST-001")
            self.assertEqual(resp["country"], "SA" if gateway == self.gateways[0] else "JP")
            self.assertEqual(resp["access"], "satellite" if gateway == self.gateways[2] else "terrestrial")
            signature = resp.pop("device_response_sig")
            self.assertEqual(signature, v2.sign(bytes.fromhex(self.device["key_hex"]), resp))
            session_ids.append(resp["session_id"])
        self.assertEqual(len(set(session_ids)), 3)
        v2.record_usage(self.state, session_ids[0], 100, 1000)
        v2.record_usage(self.state, session_ids[1], 200, 2000)
        v2.record_usage(self.state, session_ids[2], 300, 3000)
        with closing(v2.connect(v2.state_paths(self.state)[0])) as db:
            account = db.execute("SELECT DISTINCT account_id FROM sessions").fetchall()
            usage = db.execute("SELECT SUM(bytes_up),SUM(bytes_down) FROM sessions").fetchone()
        self.assertEqual(len(account), 1)
        self.assertEqual(tuple(usage), (600, 6000))

    def test_replay_and_tampering_denied(self):
        req = v2.create_request(self.device, self.gateways[0])
        self.assertEqual(self.post(req)[0], 200)
        self.assertEqual(self.post(req), (409, {"decision": "deny", "reason": "replayed-request"}))
        forged = v2.create_request(self.device, self.gateways[0])
        forged["payload"]["device_id"] = "MRV2-FAKE-OTHER"
        self.assertEqual(self.post(forged)[0], 403)
        forged2 = v2.create_request(self.device, self.gateways[0])
        forged2["payload"]["gateway_id"] = "JP-SAT-01"
        self.assertEqual(self.post(forged2)[0], 403)

    def test_expired_and_unknown_device_denied(self):
        expired = v2.create_request(self.device, self.gateways[0], ts=int(time.time()) - 121)
        self.assertEqual(self.post(expired)[0], 403)
        fake = dict(self.device)
        fake["device_id"] = "MRV2-UNKNOWN"
        self.assertEqual(self.post(v2.create_request(fake, self.gateways[0]))[0], 403)

    def test_revocation_and_account_suspension(self):
        v2.set_active(self.state, "gateway", "SA-TOWER-01", 0)
        self.assertEqual(self.post(v2.create_request(self.device, self.gateways[0]))[0], 403)
        self.assertEqual(self.post(v2.create_request(self.device, self.gateways[1]))[0], 200)
        v2.set_active(self.state, "account", "HOME-TEST-001", 0)
        self.assertEqual(self.post(v2.create_request(self.device, self.gateways[1]))[0], 403)
        v2.set_active(self.state, "account", "HOME-TEST-001", 1)
        v2.set_active(self.state, "device", self.device["device_id"], 0)
        self.assertEqual(self.post(v2.create_request(self.device, self.gateways[1]))[0], 403)

    def test_no_overwrite_and_safe_defaults(self):
        with self.assertRaises(ValueError):
            v2.initialize(self.state)
        with self.assertRaises(ValueError):
            v2.enroll_device(self.state, "HOME-TEST-001", "Home Internet Entitlement",
                             str(self.device_path))
        with self.assertRaises(ValueError):
            v2.record_usage(self.state, "unknown", 1, 1)
        with self.assertRaises(ValueError):
            v2.serve(self.state, "0.0.0.0", 8872)
        if os.name == "posix":
            self.assertEqual(self.device_path.stat().st_mode & 0o077, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
