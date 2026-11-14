#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""One-shot credential test against node 0x1220 (via functional 0xE442).

This script is the "when we finally have the credential" action. It is the only
place in 04_SOLVE/cgw that intentionally sends state-changing UDS services, so
it refuses to run without --i-have-permission.

Sequence (each step recorded verbatim under 03_EVIDENCE/cgw/):
    RA -> 10 03 -> 27 01 (seed; expected 7F277E today)
       -> [--key] 27 02 <key>            sendKey with the supplied credential
       -> [--did D --write HEX] 2E D <HEX>   write a DID (only if asked)
       -> 22 F1A3                        read the protected DID
       -> [--rid R] 31 01 <R>            start the bridge routine (only if asked)
       -> 31 03 <R>                      read routine results
       -> 13401 TCP probe                see whether the CAN FD bridge opened

Usage examples:
    python try_credential.py --i-have-permission
    python try_credential.py --i-have-permission --key 0011223344556677
    python try_credential.py --i-have-permission --key <k> --rid FF00
    python try_credential.py --i-have-permission --did F1A3 --write <hex>
"""
from __future__ import annotations

import argparse
import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import doip_uds as d  # noqa: E402

HOST = d.DEFAULT_HOST
PORT = d.DEFAULT_PORT
BRIDGE_HOST = d.DEFAULT_HOST
BRIDGE_PORT = 13401
SA = 0x0E00
NODE = d.NODE_1220_TA
PHYS = d.NODE_1220_PHYS


def raw(link, ta, uds: bytes, label: str, purpose: str, quiet=0.5, total=5.0):
    payload = struct.pack(">HH", link.sa, ta) + uds
    t0 = time.time()
    link.conn.send(d.PT_DIAG_MSG, payload)
    frames = link.conn.drain(quiet=quiet, total=total)
    rec = {"label": label, "purpose": purpose, "host": f"{link.host}:{link.port}",
           "tester_sa": f"0x{link.sa:04X}", "target_la": f"0x{ta:04X}",
           "request": {"ptype": "0x8001", "hex": payload.hex().upper(), "uds": uds.hex().upper()},
           "responses": [], "uds": [], "acks": [], "nacks": [],
           "elapsed_ms": round((time.time() - t0) * 1000, 2)}
    for ver, ptype, data in frames:
        link.ev.wire("RX", ptype, data)
        rec["responses"].append({"ptype": f"0x{ptype:04X}", "hex": data.hex().upper()})
        if ptype == d.PT_DIAG_MSG and len(data) >= 4:
            src, dst = struct.unpack(">HH", data[:4])
            rec["uds"].append({"from": f"0x{src:04X}", "to": f"0x{dst:04X}",
                               "hex": data[4:].hex().upper(),
                               "parsed": d.parse_uds_response(data[4:])})
    rec["parsed"] = (" | ".join(u["parsed"] for u in rec["uds"]) if rec["uds"] else "NO RESPONSE")
    link.ev.record(rec)
    print(f"  {label:32s} {uds.hex().upper():16s} -> {rec['parsed']}")
    return rec


def bridge_probe(ev):
    """Does 13401 answer anything now that the routine may have run?"""
    frame = bytes([2, 0xFD]) + struct.pack(">H", 0x0001) + struct.pack(">I", 0)
    try:
        s = socket.create_connection((BRIDGE_HOST, BRIDGE_PORT), timeout=3)
        s.settimeout(2.5)
        s.sendall(frame)
        data = b""
        try:
            while len(data) < 512:
                c = s.recv(512)
                if not c:
                    break
                data += c
        except socket.timeout:
            pass
        s.close()
        note = f"{len(data)}B {data.hex().upper()[:64]}"
    except Exception as exc:  # noqa: BLE001
        note = f"{type(exc).__name__}: {exc}"
    ev.record({"label": "cred_13401_probe", "purpose": "13401 probe after credential/routine",
               "host": f"{BRIDGE_HOST}:{BRIDGE_PORT}",
               "request": {"ptype": "0x0001", "hex": ""},
               "responses": [], "parsed": note})
    print(f"  13401 probe -> {note}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--i-have-permission", action="store_true",
                    help="required: confirms the Lead approved state-changing UDS")
    ap.add_argument("--key", default="", help="SecurityAccess key bytes (hex)")
    ap.add_argument("--did", default="", help="DID for a 0x2E write (hex, e.g. F1A3)")
    ap.add_argument("--write", default="", help="data bytes for the 0x2E write (hex)")
    ap.add_argument("--rid", default="", help="routine id to start, e.g. FF00")
    ap.add_argument("--seed-sub", default="01", help="0x27 seed sub-function (default 01)")
    ap.add_argument("--key-sub", default="02", help="0x27 key sub-function (default 02)")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if not args.i_have_permission:
        print("refused: pass --i-have-permission after the Lead approves the state-changing steps")
        return 2

    ev = d.Evidence(d.EVID)
    link = d.Link(HOST, PORT, ev, SA, 5.0)
    try:
        rec, parsed = link.activate(SA, 0x00, label="cred_ra")
        print("[RA]", parsed)
        if not parsed or parsed.get("code") != "0x10":
            return 3

        raw(link, NODE, bytes.fromhex("1003"), "cred_1003", "extended session")
        seed_sub = int(args.seed_sub, 16)
        raw(link, NODE, bytes([0x27, seed_sub]), "cred_seed", "requestSeed")
        if args.key:
            key = bytes.fromhex(args.key)
            raw(link, NODE, bytes([0x27, int(args.key_sub, 16)]) + key,
                "cred_key", f"sendKey ({len(key)} bytes)")
        if args.did and args.write is not None and args.write != "":
            raw(link, NODE, bytes([0x2E]) + bytes.fromhex(args.did) + bytes.fromhex(args.write),
                "cred_2e_write", f"0x2E write DID {args.did}")
        raw(link, NODE, bytes.fromhex("22F1A3"), "cred_read_f1a3", "read protected DID F1A3")
        if args.rid:
            rid = bytes.fromhex(args.rid)
            raw(link, NODE, bytes([0x31, 0x01]) + rid, "cred_31_01", f"startRoutine {args.rid}")
            raw(link, NODE, bytes([0x31, 0x03]) + rid, "cred_31_03", f"requestRoutineResults {args.rid}")
    finally:
        link.close()
    bridge_probe(ev)
    return 0


if __name__ == "__main__":
    sys.exit(main())
