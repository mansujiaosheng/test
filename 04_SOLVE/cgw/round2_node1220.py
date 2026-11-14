#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Round-2 attack matrix on the second UDS node 0x1220 (reachable via 0xE442).

Approved by the Lead in session 2026-11-14 10:0x:
  * 0x27 even sub-functions (sendKey direction) with a dummy 4-byte key
  * 0x27 <odd sub> + 4 extra zero bytes
  * 0x2E <did> with **zero data bytes** (length-invalid; nothing can be written)
  * 0x31 01 <rid> with zero parameter bytes (security is locked -> 0x33, no start)
  * 0x23 ReadMemoryByAddress with several ALFIDs (read-only)
  * physical addressing to 0x1220 vs functional 0xE442

The default-session 0x27 variants run on a dedicated fresh socket before any
10 03 is sent, so the "default" context is real.
Everything is recorded under 03_EVIDENCE/cgw/ with the raw bytes.
"""
from __future__ import annotations

import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import doip_uds as d  # noqa: E402

HOST = d.DEFAULT_HOST
PORT = d.DEFAULT_PORT
SA = 0x0E00
NODE_FUNC = d.NODE_1220_TA   # 0xE442
NODE_PHYS = 0x1220


def raw(link, ta, uds: bytes, label: str, purpose: str, quiet=0.45, total=4.0):
    """Send a payload outside the read-only allowlist, under explicit rules."""
    sid = uds[0]
    ok = (
        (sid == 0x2E and len(uds) == 3)                       # zero data bytes only
        or (sid == 0x27 and len(uds) in (2, 4, 6))            # seed/key probe shapes
        or (sid == 0x31 and len(uds) == 4 and uds[1] == 0x01)  # startRoutine, RID only
    )
    assert ok, f"raw_probe refuses shape {uds.hex()}"
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


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ev = d.Evidence(d.EVID)
    print(f"[*] host {HOST}:{PORT}  evidence seq from {ev.seq + 1}")
    rows = []

    # ---- A: physical 0x1220 vs functional 0xE442 (own socket; sends 10 03)
    link = d.Link(HOST, PORT, ev, SA, 3.0)
    try:
        link.activate(SA, 0x00, label="r2n_ra_phys_vs_func")
        for ta, tag in ((NODE_PHYS, "phys1220"), (NODE_FUNC, "funcE442")):
            for uds, note in (("22F1A3", "protected DID"),
                              ("1003", "extended session"),
                              ("2701", "seed level 1"),
                              ("3103FF00", "routine results FF00")):
                r = link.uds(ta, bytes.fromhex(uds), f"r2n_{tag}_{uds.lower()}",
                             quiet=0.4, total=3.5, purpose=f"{note} via {tag}")
                rows.append({"test": f"phys-vs-func/{tag}/{uds}", "parsed": r.get("parsed")})
                print(f"[{tag}] {uds:10s} -> {r.get('parsed')}")
    finally:
        link.close()

    # ---- B: 0x27 variants in three contexts, fresh socket for "default"
    link = d.Link(HOST, PORT, ev, SA, 3.0)
    try:
        link.activate(SA, 0x00, label="r2n_ra_27_contexts")
        for ctx in ("default", "extended", "extended+3e"):
            if ctx == "extended":
                r = link.uds(NODE_FUNC, bytes.fromhex("1003"), "r2n_ctx_1003",
                             purpose="enter extended session before 0x27 variants")
                print("[ctx] 10 03 ->", r.get("parsed"))
            if ctx == "extended+3e":
                r = link.uds(NODE_FUNC, bytes.fromhex("3E00"), "r2n_ctx_3e00",
                             purpose="tester present keep-alive attempt before 0x27 variants")
                print("[ctx] 3E 00 ->", r.get("parsed"))
            for uds in ("2701", "270100000000", "2702", "27020000", "2704", "27040000",
                        "2706", "27060000"):
                r = raw(link, NODE_FUNC, bytes.fromhex(uds), f"r2n_ctx_{ctx}_{uds.lower()}",
                        f"0x27 variant {uds} in context {ctx}")
                rows.append({"test": f"27/{ctx}/{uds}", "parsed": r["parsed"]})
                print(f"[{ctx:11s}] {uds:12s} -> {r['parsed']}")

        # ---- C: 0x23 ReadMemoryByAddress variants
        for tag, uds in (("14-00-1", bytes.fromhex("2314000001")),
                         ("14-00-16", bytes.fromhex("2314000010")),
                         ("24-00-1", bytes.fromhex("233400000001")),
                         ("44-00-1", bytes.fromhex("23440000000001"))):
            r = link.uds(NODE_FUNC, uds, f"r2n_23_{tag}", quiet=0.4, total=3.0,
                         purpose=f"ReadMemoryByAddress {tag}")
            rows.append({"test": f"23/{tag}", "parsed": r.get("parsed")})
            print(f"[0x23] {uds.hex()} -> {r.get('parsed')}")

        # ---- D: 0x31 01 <rid> with zero parameter bytes
        for rid in (0xFF00, 0xFF01, 0x0200, 0x0203, 0x0100, 0xFFFF):
            r = raw(link, NODE_FUNC, bytes([0x31, 0x01]) + rid.to_bytes(2, "big"),
                    f"r2n_3101_{rid:04x}", f"startRoutine 0x{rid:04X} with no parameters")
            rows.append({"test": f"3101/{rid:04x}", "parsed": r["parsed"]})
            print(f"[31 01] {rid:04X} -> {r['parsed']}")

        # ---- E: 0x2E zero-data probes, targeted DIDs
        for did in (0xF190, 0xF1A0, 0xF1A3, 0xF1A4, 0x0000, 0xFFFF):
            r = raw(link, NODE_FUNC, bytes([0x2E]) + did.to_bytes(2, "big"),
                    f"r2n_2e_{did:04x}", f"0x2E zero-data probe DID 0x{did:04X}")
            rows.append({"test": f"2e/{did:04x}", "parsed": r["parsed"]})
            print(f"[2E] {did:04X} -> {r['parsed']}")
    finally:
        link.close()

    ev.record({"label": "r2_node1220_matrix_summary",
               "purpose": "0x1220 attack matrix (physical/functional, 0x27 variants, 0x23, 0x31 01, 2E)",
               "request": {"ptype": "mixed", "hex": ""},
               "rows": rows,
               "parsed": f"{len(rows)} probes"})
    print(f"[*] {len(rows)} probes recorded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
