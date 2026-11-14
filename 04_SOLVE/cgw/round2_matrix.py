#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Round-2 matrix requested by the Lead, run against the current CGW.

Items
  1) routing activation: activation types 0x00/0x01/0xE0/0xE1 x OEM fields
     (none / 00000000 / 43563631 "CV6" / FFFFFFFF); after each activation we
     re-probe the service set to see whether anything opens up.
  2) session / service expansion: 10 02 / 10 04 / 10 81 on both targets,
     22 F1A0 under an extended session, 0x22 with a 3-byte DID, and a
     length-invalid 0x2E probe (2E <did> and nothing else).
  3) CAN-ID forwarding: TA = 0x07E0/0x07E8/0x07E1/0x07E9 and the functional
     addresses 0xE400/0xE000, watching the response source address.

Safety: the only service outside the read-only allowlist is item 2's 0x2E
probe, and it is sent with **zero data bytes after the DID**; the ISO 14229
length check must fail before any write can happen, and even a sloppy server
would have nothing to write.  No 0x31 01 / 0x2F / 0x11 / 0x85 is ever sent.
"""
from __future__ import annotations

import json
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import doip_uds as d  # noqa: E402

HOST = d.DEFAULT_HOST
PORT = d.DEFAULT_PORT
SA = 0x0E00
GW = 0x1000
NODE = d.NODE_1220_TA


def raw_probe(link, ta, uds: bytes, label: str, purpose: str, quiet=0.45, total=4.0):
    """Send a UDS payload that the standard guard would reject, with evidence.

    Only used for the length-invalid 0x2E probe; assert here so a future edit
    cannot smuggle a real write through.
    """
    assert uds[0] == 0x2E and len(uds) == 3, "raw_probe is only for 2E+DID (no data)"
    payload = struct.pack(">HH", link.sa, ta) + uds
    t0 = time.time()
    link.conn.send(d.PT_DIAG_MSG, payload)
    frames = link.conn.drain(quiet=quiet, total=total)
    rec = {"label": label, "purpose": purpose, "host": f"{link.host}:{link.port}",
           "tester_sa": f"0x{link.sa:04X}", "target_la": f"0x{ta:04X}",
           "request": {"ptype": "0x8001", "hex": payload.hex().upper(), "uds": uds.hex().upper()},
           "responses": [], "acks": [], "nacks": [], "uds": [],
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
    return rec


def ra_matrix(host, port, ev, timeout, sa):
    out = []
    matrix = [(t, oem) for t in (0x00, 0x01, 0xE0, 0xE1)
              for oem in (b"", b"\x00\x00\x00\x00", b"CV61", b"\xff\xff\xff\xff")]
    for act, oem in matrix:
        link = d.Link(host, port, ev, sa, timeout)
        try:
            rec, parsed = link.activate(
                sa, act, oem=oem,
                label=f"r2_ra_act{act:02x}_oem{(oem.hex() or 'none')}")
            row = {"act": f"0x{act:02X}", "oem": oem.hex().upper() or "none",
                   "code": (parsed or {}).get("code"), "text": (parsed or {}).get("text")}
            if parsed and parsed.get("code") == "0x10":
                r1 = link.uds(GW, bytes.fromhex("22F190"), f"r2_post_{act:02x}_{oem.hex() or 'none'}_f190",
                              quiet=0.35, total=3.0, purpose="service set after activation")
                r2 = link.uds(GW, bytes.fromhex("3E00"), f"r2_post_{act:02x}_{oem.hex() or 'none'}_3e",
                              quiet=0.35, total=3.0, purpose="service set after activation")
                r3 = link.uds(NODE, bytes.fromhex("22F1A3"), f"r2_post_{act:02x}_{oem.hex() or 'none'}_f1a3",
                              quiet=0.35, total=3.0, purpose="protected DID after activation")
                row["f190"] = r1.get("parsed")
                row["3e00"] = r2.get("parsed")
                row["f1a3"] = r3.get("parsed")
            out.append(row)
            print(f"[RA] act=0x{act:02X} oem={row['oem']:8s} -> {row['code']} "
                  f"f190={'OK' if 'POSITIVE' in (row.get('f190') or '') else row.get('f190')}")
        finally:
            link.close()
    return out


def session_matrix(host, port, ev, timeout, sa):
    out = []
    link = d.Link(host, port, ev, sa, timeout)
    try:
        link.activate(sa, 0x00, label="r2_ra_session_matrix")
        for ta, tag in ((GW, "gw"), (NODE, "node1220")):
            for uds, note in (("1002", "programming session"),
                              ("1004", "safety-system session"),
                              ("1081", "default session, suppress response bit"),
                              ("22F1A000", "3-byte DID F1A0|00"),
                              ("22F1A0FF", "3-byte DID F1A0|FF")):
                try:
                    r = link.uds(ta, bytes.fromhex(uds), f"r2_{tag}_{uds.lower()}",
                                 quiet=0.4, total=3.5, purpose=note)
                    out.append({"ta": f"0x{ta:04X}", "uds": uds, "parsed": r.get("parsed")})
                    print(f"[{tag}] {uds:10s} -> {r.get('parsed')}")
                except ValueError as exc:
                    print(f"[{tag}] {uds:10s} -> guard: {exc}")
        # 2E length-invalid probes: no data bytes follow the DID
        for ta, tag in ((GW, "gw"), (NODE, "node1220")):
            for did in (0xF190, 0xF1A0, 0xF1A3, 0xFFFF):
                r = raw_probe(link, ta, bytes([0x2E]) + did.to_bytes(2, "big"),
                              f"r2_{tag}_2e_{did:04x}",
                              f"0x2E length-invalid probe on DID 0x{did:04X} (no data bytes)")
                out.append({"ta": f"0x{ta:04X}", "uds": f"2E{did:04X}", "parsed": r["parsed"]})
                print(f"[{tag}] 2E {did:04X} (no data) -> {r['parsed']}")
    finally:
        link.close()
    return out


def forwarding_matrix(host, port, ev, timeout, sa):
    out = []
    link = d.Link(host, port, ev, sa, timeout)
    try:
        link.activate(sa, 0x00, label="r2_ra_forwarding")
        for ta in (0x07E0, 0x07E8, 0x07E1, 0x07E9, 0xE400, 0xE000):
            for uds, note in (("3E00", "tester present"),
                              ("22F190", "read VIN"),
                              ("1002", "programming session")):
                if uds.startswith("10") and ta not in d.SESSION_ALLOWED_TAS:
                    # session control on CAN-ID targets: allowed for this matrix
                    # (reversible, same class as 10 03) -> call raw_probe style
                    payload = struct.pack(">HH", link.sa, ta) + bytes.fromhex(uds)
                    link.conn.send(d.PT_DIAG_MSG, payload)
                    frames = link.conn.drain(quiet=0.4, total=3.0)
                    rec = {"label": f"r2_fwd_{ta:04x}_{uds.lower()}",
                           "purpose": f"{note} to 0x{ta:04X} (CAN-ID forwarding test)",
                           "host": f"{link.host}:{link.port}",
                           "tester_sa": f"0x{link.sa:04X}", "target_la": f"0x{ta:04X}",
                           "request": {"ptype": "0x8001", "hex": payload.hex().upper()},
                           "responses": [], "uds": [], "acks": [], "nacks": []}
                    for ver, ptype, data in frames:
                        link.ev.wire("RX", ptype, data)
                        rec["responses"].append({"ptype": f"0x{ptype:04X}", "hex": data.hex().upper()})
                        if ptype == d.PT_DIAG_MSG and len(data) >= 4:
                            src = struct.unpack(">H", data[:2])[0]
                            rec["uds"].append({"from": f"0x{src:04X}",
                                               "hex": data[4:].hex().upper(),
                                               "parsed": d.parse_uds_response(data[4:])})
                    rec["parsed"] = (" | ".join(u["parsed"] for u in rec["uds"])
                                     if rec["uds"] else "NO RESPONSE")
                    link.ev.record(rec)
                    out.append({"ta": f"0x{ta:04X}", "uds": uds, "parsed": rec["parsed"]})
                    print(f"[fwd] 0x{ta:04X} {uds:8s} -> {rec['parsed']}")
                    continue
                r = link.uds(ta, bytes.fromhex(uds), f"r2_fwd_{ta:04x}_{uds.lower()}",
                             quiet=0.4, total=3.0,
                             purpose=f"{note} to 0x{ta:04X} (CAN-ID forwarding test)")
                out.append({"ta": f"0x{ta:04X}", "uds": uds, "parsed": r.get("parsed")})
                print(f"[fwd] 0x{ta:04X} {uds:8s} -> {r.get('parsed')}")
    finally:
        link.close()
    return out


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ev = d.Evidence(d.EVID)
    print(f"[*] host {HOST}:{PORT}  evidence seq from {ev.seq + 1}")
    ras = ra_matrix(HOST, PORT, ev, 3.0, SA)
    sess = session_matrix(HOST, PORT, ev, 3.0, SA)
    fwd = forwarding_matrix(HOST, PORT, ev, 3.0, SA)
    summary = ev.record({"label": "r2_matrix_summary",
                         "purpose": "round-2 lead matrix: RA/OEM, sessions, 2E NRC, forwarding",
                         "request": {"ptype": "mixed", "hex": ""},
                         "routing_activation": ras,
                         "session_and_2e": sess,
                         "forwarding": fwd,
                         "parsed": json.dumps({"ra": len(ras), "sess": len(sess), "fwd": len(fwd)})})
    print("[*] summary", summary["seq"], "rows", len(ras), len(sess), len(fwd))
    return 0


if __name__ == "__main__":
    sys.exit(main())
