#!/usr/bin/env python3
"""Mini Rack V2 experimental entitlement service (stdlib only).

REAL functionality: cryptographically verify a separately enrolled device AND
access gateway, authorize a home-plan entitlement, persist sessions/usage.
NOT: a cellular core, Internet transit, ISP-billing integration, or a satellite link.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ACCESS = ("terrestrial", "satellite", "wifi")
DEVICE_PREFIX = "MRV2-"
ID_RE = re.compile(r"^[A-Za-z0-9_-]{3,64}$")
NONCE_RE = re.compile(r"^[a-f0-9]{32,64}$")
COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
MAX_SKEW = 120


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("ascii")


def sign(secret: bytes, data: dict) -> str:
    return hmac.new(secret, canonical(data), hashlib.sha256).hexdigest()


def derived_secret(master: bytes, kind: str, identifier: str) -> bytes:
    return hmac.new(master, ("minirack-v2:" + kind + ":" + identifier).encode(), hashlib.sha256).digest()


def secure_write_new(file: Path, value: bytes) -> None:
    fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(value)


def state_paths(folder: str) -> tuple[Path, Path]:
    root = Path(folder).expanduser().resolve()
    return root / "core.sqlite", root / "master.key"


def connect(dbpath: Path) -> sqlite3.Connection:
    if not dbpath.is_file():
        raise ValueError("V2 database absent: run init first")
    db = sqlite3.connect(str(dbpath), timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def master_key(path: Path) -> bytes:
    key = path.read_bytes()
    if len(key) != 32:
        raise ValueError("Invalid master key")
    if os.name == "posix" and (path.stat().st_mode & 0o077):
        raise ValueError("Master key file permissions are too open")
    return key


def initialize(folder: str) -> None:
    dbpath, keypath = state_paths(folder)
    dbpath.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix" and (dbpath.parent.stat().st_mode & 0o077):
        raise ValueError("State folder must be private (chmod 700)")
    if dbpath.exists() or keypath.exists():
        raise ValueError("V2 state already exists; refusing to overwrite")
    secure_write_new(keypath, secrets.token_bytes(32))
    secure_write_new(dbpath, b"")
    with closing(connect(dbpath)) as db, db:
        db.executescript("""
          CREATE TABLE accounts (
            account_id TEXT PRIMARY KEY, home_plan TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1
          );
          CREATE TABLE devices (
            device_id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(account_id),
            active INTEGER NOT NULL DEFAULT 1
          );
          CREATE TABLE gateways (
            gateway_id TEXT PRIMARY KEY, country TEXT NOT NULL, access TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
          );
          CREATE TABLE nonces (
            device_id TEXT NOT NULL, nonce TEXT NOT NULL, seen INTEGER NOT NULL,
            PRIMARY KEY(device_id, nonce)
          );
          CREATE TABLE sessions (
            session_id TEXT PRIMARY KEY, device_id TEXT NOT NULL, account_id TEXT NOT NULL,
            gateway_id TEXT NOT NULL, country TEXT NOT NULL, access TEXT NOT NULL,
            started INTEGER NOT NULL, bytes_up INTEGER NOT NULL DEFAULT 0,
            bytes_down INTEGER NOT NULL DEFAULT 0
          );
        """)
    print("V2 core initialized (private state, no V1 changes):", dbpath.parent)


def validate_id(value: str, label: str) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise ValueError(label + " must use 3-64 letters, digits, _ or -")
    return value


def enroll_device(folder: str, account: str, home_plan: str, provision_out: str) -> str:
    validate_id(account, "account")
    if not home_plan or len(home_plan) > 100:
        raise ValueError("Invalid home-plan description")
    dbpath, keypath = state_paths(folder)
    key = master_key(keypath)
    device_id = DEVICE_PREFIX + secrets.token_hex(12)
    provision = {"role": "device", "device_id": device_id,
                 "key_hex": derived_secret(key, "device", device_id).hex(),
                 "account_id": account, "protocol": "minirack-v2-hmac-v1"}
    # Provision before commit: never leave an enrolled device with no key handoff.
    output = Path(provision_out).expanduser().resolve()
    if output.exists():
        raise ValueError("Provision file exists; refusing to overwrite")
    if not output.parent.exists():
        raise ValueError("Provision directory does not exist")
    with closing(connect(dbpath)) as db, db:
        prior = db.execute("SELECT home_plan FROM accounts WHERE account_id=?", (account,)).fetchone()
        if prior and prior[0] != home_plan:
            raise ValueError("Account already exists with a different plan label")
        if not prior:
            db.execute("INSERT INTO accounts(account_id,home_plan) VALUES (?,?)", (account, home_plan))
        db.execute("INSERT INTO devices(device_id,account_id) VALUES (?,?)", (device_id, account))
        secure_write_new(output, (json.dumps(provision, indent=2) + "\n").encode())
    return device_id


def enroll_gateway(folder: str, gateway: str, country: str, access: str, provision_out: str) -> None:
    validate_id(gateway, "gateway")
    if not COUNTRY_RE.fullmatch(country):
        raise ValueError("Country must be an ISO-like two-letter uppercase code")
    if access not in ACCESS:
        raise ValueError("Unknown access type")
    dbpath, keypath = state_paths(folder)
    key = master_key(keypath)
    output = Path(provision_out).expanduser().resolve()
    if output.exists() or not output.parent.exists():
        raise ValueError("Provision destination exists or parent missing")
    provision = {"role": "gateway", "gateway_id": gateway,
                 "key_hex": derived_secret(key, "gateway", gateway).hex(),
                 "protocol": "minirack-v2-hmac-v1"}
    with closing(connect(dbpath)) as db, db:
        db.execute("INSERT INTO gateways(gateway_id,country,access) VALUES (?,?,?)",
                   (gateway, country, access))
        secure_write_new(output, (json.dumps(provision, indent=2) + "\n").encode())


def create_request(device: dict, gateway: dict, *, ts: int | None = None,
                   nonce: str | None = None) -> dict:
    """Helper for tests/protocol clients; caller must have both provisioned credentials."""
    body = {"device_id": device["device_id"], "gateway_id": gateway["gateway_id"],
            "ts": int(time.time()) if ts is None else ts,
            "nonce": secrets.token_hex(16) if nonce is None else nonce}
    body["device_sig"] = sign(bytes.fromhex(device["key_hex"]), body)
    return {"payload": body,
            "gateway_sig": sign(bytes.fromhex(gateway["key_hex"]), body)}


def authorize(db: sqlite3.Connection, key: bytes, request: dict, now: int | None = None) -> tuple[int, dict]:
    """Called on the trusted server: no client-supplied access/country is trusted."""
    if now is None:
        now = int(time.time())
    try:
        if not isinstance(request, dict) or set(request) != {"payload", "gateway_sig"}:
            raise ValueError()
        body = request["payload"]
        if not isinstance(body, dict) or set(body) != {"device_id", "gateway_id", "ts", "nonce", "device_sig"}:
            raise ValueError()
        dev = validate_id(body["device_id"], "device")
        gw = validate_id(body["gateway_id"], "gateway")
        if type(body["ts"]) is not int or abs(now - body["ts"]) > MAX_SKEW:
            raise ValueError()
        if not isinstance(body["nonce"], str) or not NONCE_RE.fullmatch(body["nonce"]):
            raise ValueError()
        for field in (body["device_sig"], request["gateway_sig"]):
            if not isinstance(field, str) or not re.fullmatch(r"[0-9a-f]{64}", field):
                raise ValueError()
        unsigned = {k: body[k] for k in ("device_id", "gateway_id", "ts", "nonce")}
        expected_device = sign(derived_secret(key, "device", dev), unsigned)
        expected_gateway = sign(derived_secret(key, "gateway", gw), body)
        if not (hmac.compare_digest(body["device_sig"], expected_device) and
                hmac.compare_digest(request["gateway_sig"], expected_gateway)):
            raise ValueError()
    except (ValueError, TypeError, KeyError):
        return 403, {"decision": "deny", "reason": "invalid-authentication"}

    row = db.execute("""SELECT d.active AS device_active, a.active AS account_active,
                         d.account_id, a.home_plan, g.country, g.access, g.active AS gw_active
                         FROM devices d JOIN accounts a ON a.account_id=d.account_id
                         JOIN gateways g ON g.gateway_id=? WHERE d.device_id=?""",
                     (gw, dev)).fetchone()
    if not row or not (row["device_active"] and row["account_active"] and row["gw_active"]):
        return 403, {"decision": "deny", "reason": "not-entitled"}
    # This SQL uniqueness constraint is the replay barrier. No race between threads:
    # sqlite serializes writes; insert session only after nonce reservation succeeds.
    with db:
        db.execute("DELETE FROM nonces WHERE seen < ?", (now - 3600,))
        try:
            db.execute("INSERT INTO nonces(device_id,nonce,seen) VALUES (?,?,?)",
                       (dev, body["nonce"], now))
        except sqlite3.IntegrityError:
            return 409, {"decision": "deny", "reason": "replayed-request"}
        session_id = "S-" + secrets.token_hex(12)
        db.execute("""INSERT INTO sessions(session_id,device_id,account_id,gateway_id,
                     country,access,started) VALUES (?,?,?,?,?,?,?)""",
                   (session_id, dev, row["account_id"], gw, row["country"], row["access"], now))
    response = {"decision": "allow", "session_id": session_id,
                "account_id": row["account_id"], "home_plan": row["home_plan"],
                "country": row["country"], "access": row["access"]}
    # Short, nonce-bound proof for constrained MCU clients. It is separate from
    # the full response signature and prevents spoofing a plain HTTP 200/ALLOW.
    response["device_response_proof"] = sign(derived_secret(key, "device", dev), {
        "decision": "allow", "device_id": dev, "gateway_id": gw,
        "nonce": body["nonce"], "session_id": session_id})
    response["device_response_sig"] = sign(derived_secret(key, "device", dev), response)
    return 200, response


class Handler(BaseHTTPRequestHandler):
    server_version = "MiniRackV2Lab/0.1"

    def do_GET(self):
        if self.path == "/health":
            self.reply(200, {"status": "ok", "service": "v2-entitlement-lab"})
        else:
            self.reply(404, {"error": "not-found"})

    def do_POST(self):
        if self.path != "/v2/authorize":
            self.reply(404, {"error": "not-found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            if length < 1 or length > 4096:
                self.reply(413, {"decision": "deny", "reason": "request-size"})
                return
            payload = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            self.reply(400, {"decision": "deny", "reason": "invalid-json"})
            return
        with closing(connect(self.server.dbpath)) as db:
            status, result = authorize(db, self.server.key, payload)
        self.reply(status, result)

    def reply(self, status: int, obj: dict):
        data = canonical(obj)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        # Do not write secret-bearing requests. Keep the default lab quiet.
        pass


def serve(folder: str, host: str, port: int) -> None:
    if host in ("0.0.0.0", "::", "[::]"):
        raise ValueError("Refusing to listen on all interfaces; use loopback or an explicit WG IP")
    dbpath, keypath = state_paths(folder)
    key = master_key(keypath)
    with closing(connect(dbpath)):
        pass
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.dbpath = dbpath
    httpd.key = key
    print(f"Mini Rack V2 entitlement LAB running on http://{host}:{port}; Ctrl+C to stop")
    print("No router, VPN, firewall, ISP account or V1 firmware has been changed.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def record_usage(folder: str, session: str, up: int, down: int) -> None:
    # Trusted administrator/meter only. DO NOT bill based on unsigned client claims.
    if up < 0 or down < 0 or up > 2**40 or down > 2**40:
        raise ValueError("Invalid usage increment")
    dbpath, _ = state_paths(folder)
    with closing(connect(dbpath)) as db, db:
        result = db.execute("""UPDATE sessions SET bytes_up=bytes_up+?, bytes_down=bytes_down+?
                            WHERE session_id=?""", (up, down, session))
        if not result.rowcount:
            raise ValueError("Unknown session")


def status(folder: str) -> None:
    dbpath, _ = state_paths(folder)
    with closing(connect(dbpath)) as db, db:
        for row in db.execute("""SELECT a.account_id, a.home_plan, a.active,
                   COALESCE(SUM(s.bytes_up),0) AS up, COALESCE(SUM(s.bytes_down),0) AS down,
                   COUNT(s.session_id) AS sessions FROM accounts a
                   LEFT JOIN sessions s ON s.account_id=a.account_id
                   GROUP BY a.account_id ORDER BY a.account_id"""):
            print(f"ACCOUNT {row['account_id']} plan={row['home_plan']} active={row['active']} "
                  f"sessions={row['sessions']} up={row['up']} down={row['down']}")
        for row in db.execute("""SELECT session_id,device_id,gateway_id,country,access,started,
                                      bytes_up,bytes_down FROM sessions ORDER BY started"""):
            print(f"SESSION {row['session_id']} device={row['device_id']} "
                  f"gateway={row['gateway_id']} {row['country']}/{row['access']} "
                  f"up={row['bytes_up']} down={row['bytes_down']}")


def set_active(folder: str, table: str, identifier: str, active: int) -> None:
    names = {"account": ("accounts", "account_id"), "device": ("devices", "device_id"),
             "gateway": ("gateways", "gateway_id")}
    table_name, key_name = names[table]
    dbpath, _ = state_paths(folder)
    with closing(connect(dbpath)) as db, db:
        res = db.execute(f"UPDATE {table_name} SET active=? WHERE {key_name}=?",
                         (active, identifier))
        if not res.rowcount:
            raise ValueError("Unknown account/device/gateway")


def main() -> None:
    parser = argparse.ArgumentParser(description="Mini Rack V2 experimental subscription core")
    parser.add_argument("--state-dir", default=str(Path.home() / ".minirack-v2-lab"))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    en = commands.add_parser("enroll-device")
    en.add_argument("--account", required=True)
    en.add_argument("--home-plan", required=True)
    en.add_argument("--provision-out", required=True)
    gt = commands.add_parser("enroll-gateway")
    gt.add_argument("--gateway", required=True)
    gt.add_argument("--country", required=True)
    gt.add_argument("--access", choices=ACCESS, required=True)
    gt.add_argument("--provision-out", required=True)
    sv = commands.add_parser("serve")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8872)
    use = commands.add_parser("usage")
    use.add_argument("--session", required=True)
    use.add_argument("--up", type=int, required=True)
    use.add_argument("--down", type=int, required=True)
    commands.add_parser("status")
    state = commands.add_parser("set-active")
    state.add_argument("--type", choices=("account", "device", "gateway"), required=True)
    state.add_argument("--id", required=True)
    state.add_argument("--value", choices=("0", "1"), required=True)
    args = parser.parse_args()
    try:
        if args.command == "init":
            initialize(args.state_dir)
        elif args.command == "enroll-device":
            print("Enrolled device:", enroll_device(args.state_dir, args.account,
                  args.home_plan, args.provision_out), "(private provisioning file written)")
        elif args.command == "enroll-gateway":
            enroll_gateway(args.state_dir, args.gateway, args.country,
                           args.access, args.provision_out)
            print("Enrolled gateway:", args.gateway, "(private provisioning file written)")
        elif args.command == "serve":
            serve(args.state_dir, args.host, args.port)
        elif args.command == "usage":
            record_usage(args.state_dir, args.session, args.up, args.down)
            print("Usage recorded (trusted lab meter input only)")
        elif args.command == "status":
            status(args.state_dir)
        elif args.command == "set-active":
            set_active(args.state_dir, args.type, args.id, int(args.value))
            print("Changed active state")
    except (ValueError, OSError, sqlite3.Error) as exc:
        print("ERROR:", exc, file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
