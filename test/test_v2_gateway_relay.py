#!/usr/bin/env python3
"""Relay-to-core live tests for the fully bundled MiniRack V2 lab."""
import json
import sys
import tempfile
import threading
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'pi'))
import v2_subscription_core as core
import v2_gateway_relay as relay


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        root = Path(self.t.name)
        state = str(root / 'db')
        core.initialize(state)
        device_file, gw_file = root / 'device.json', root / 'gateway.json'
        core.enroll_device(state, 'HOME-TEST-001', 'Home Internet', str(device_file))
        core.enroll_gateway(state, 'SA-TOWER', 'SA', 'terrestrial', str(gw_file))
        self.dev = json.loads(device_file.read_text())
        self.gw = json.loads(gw_file.read_text())
        dbpath, keypath = core.state_paths(state)
        self.core_server = core.ThreadingHTTPServer(('127.0.0.1', 0), core.Handler)
        self.core_server.dbpath = dbpath
        self.core_server.key = core.master_key(keypath)
        self.relay_server = relay.make_server('127.0.0.1', 0, str(gw_file),
                                             '127.0.0.1', self.core_server.server_address[1])
        self.threads = []
        for server in (self.core_server, self.relay_server):
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()
            self.threads.append(t)
        self.addCleanup(self.close_servers)

    def close_servers(self):
        for server in (self.relay_server, self.core_server):
            server.shutdown()
            server.server_close()
        for t in self.threads:
            t.join(timeout=2)

    def post(self, payload):
        port = self.relay_server.server_address[1]
        req = Request(f'http://127.0.0.1:{port}/v2/device/authorize',
                      data=json.dumps(payload).encode('utf8'),
                      headers={'Content-Type': 'application/json'}, method='POST')
        try:
            answer = urlopen(req, timeout=3)
        except HTTPError as err:
            answer = err
        with answer:
            return answer.status, json.load(answer)

    def test_device_signs_relay_signs_core_authorizes(self):
        raw = core.create_request(self.dev, self.gw)
        status, payload = self.post({'payload': raw['payload']})
        self.assertEqual(status, 200)
        self.assertEqual(payload['decision'], 'allow')
        self.assertEqual(payload['account_id'], 'HOME-TEST-001')
        received_sig = payload.pop('device_response_sig')
        self.assertEqual(received_sig,
                         core.sign(bytes.fromhex(self.dev['key_hex']), payload))
        code, reply = self.post({'payload': raw['payload']})
        self.assertEqual(code, 409)
        self.assertEqual(reply['reason'], 'replayed-request')

    def test_forged_and_wrong_gateway_fail(self):
        raw = core.create_request(self.dev, self.gw)
        raw['payload']['device_sig'] = '0'*64
        self.assertEqual(self.post({'payload': raw['payload']})[0], 403)
        raw = core.create_request(self.dev, self.gw)
        raw['payload']['gateway_id'] = 'JP-TOWER'
        self.assertEqual(self.post({'payload': raw['payload']})[0], 403)

    def test_exact_peer_restriction(self):
        self.relay_server.allow_peer = '10.10.0.3'
        raw = core.create_request(self.dev, self.gw)
        self.assertEqual(self.post({'payload': raw['payload']})[0], 403)

if __name__=='__main__':
    unittest.main()
