#!/usr/bin/env python3
"""Trusted Pi gateway relay for the V2 LAB.

It signs access-gateway attestations and forwards separately signed device
requests to the core on loopback. WG tunnel peer restriction is required.
This has no authority to turn on Internet access or NAT by itself.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import v2_subscription_core as core


class Relay(BaseHTTPRequestHandler):
    server_version = 'MiniRackV2Relay/0.1'

    def do_GET(self):
        if self.path == '/health':
            self.respond(200, {'status': 'ok', 'service': 'gateway-relay-lab'})
        else:
            self.respond(404, {'error': 'not-found'})

    def do_POST(self):
        if self.path != '/v2/device/authorize':
            self.respond(404, {'error': 'not-found'})
            return
        if self.client_address[0] != self.server.allow_peer:
            self.respond(403, {'decision': 'deny', 'reason': 'peer-not-authorized'})
            return
        try:
            length = int(self.headers.get('Content-Length', '-1'))
            if length < 1 or length > 2048:
                self.respond(413, {'decision': 'deny', 'reason': 'invalid-size'})
                return
            req = json.loads(self.rfile.read(length))
            if not isinstance(req, dict) or set(req) != {'payload'}:
                raise ValueError('request schema')
            body = req['payload']
            if not isinstance(body, dict) or set(body) != {'device_id', 'device_sig', 'gateway_id', 'nonce', 'ts'}:
                raise ValueError('payload schema')
            if body['gateway_id'] != self.server.gateway_id:
                self.respond(403, {'decision': 'deny', 'reason': 'wrong-gateway'})
                return
            # Attestation uses the separate registered gateway key (never flashed on ESP).
            # The core does the full anti-replay and entitlement validation.
            signed = {'payload': body,
                      'gateway_sig': core.sign(self.server.gateway_key, body)}
            outbound = Request('http://127.0.0.1:%d/v2/authorize' % self.server.core_port,
                               data=core.canonical(signed),
                               headers={'Content-Type': 'application/json'}, method='POST')
            try:
                response = urlopen(outbound, timeout=2)
            except HTTPError as error:
                response = error
            with response:
                # Never convert core failures to success.
                status = response.status
                raw = response.read(4096)
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            self.respond(400, {'decision': 'deny', 'reason': 'invalid-request'})
        except (URLError, OSError):
            self.respond(503, {'decision': 'deny', 'reason': 'core-unavailable'})

    def respond(self, status: int, payload: dict):
        body = core.canonical(payload)
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def make_server(bind: str, port: int, provisioning: str,
                allowed_client: str, core_port: int) -> ThreadingHTTPServer:
    if bind in ('0.0.0.0', '::', '[::]'):
        raise ValueError('Refusing public wildcard bind. Use Pi wg0 address.')
    if not allowed_client or allowed_client == '0.0.0.0':
        raise ValueError('Must set exact allowed WireGuard peer address.')
    key_path = Path(provisioning).expanduser().resolve()
    if os.name == 'posix' and key_path.stat().st_mode & 0o077:
        raise ValueError('Gateway key permissions too open; chmod 600 first')
    gateway = json.loads(key_path.read_text())
    if gateway.get('role') != 'gateway':
        raise ValueError('Provisioning is not a gateway identity')
    gateway_id = core.validate_id(gateway['gateway_id'], 'gateway')
    key = bytes.fromhex(gateway['key_hex'])
    if len(key) != 32:
        raise ValueError('Invalid gateway key')
    server = ThreadingHTTPServer((bind, port), Relay)
    server.gateway_id = gateway_id
    server.gateway_key = key
    server.allow_peer = allowed_client
    server.core_port = core_port
    return server


def main():
    p = argparse.ArgumentParser(description='WireGuard-scoped MiniRack V2 gateway relay')
    p.add_argument('--gateway-provision', required=True)
    p.add_argument('--host', default='10.10.0.1', help='Pi wg0 address, NOT public 0.0.0.0')
    p.add_argument('--port', type=int, default=8873)
    p.add_argument('--allow-peer', default='10.10.0.3', help='Only ESP WG address')
    p.add_argument('--core-port', type=int, default=8872)
    args = p.parse_args()
    server = make_server(args.host, args.port, args.gateway_provision,
                         args.allow_peer, args.core_port)
    print('V2 gateway relay is up; WG-scoped:', args.host, args.port,
          'registered gateway:', server.gateway_id)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
