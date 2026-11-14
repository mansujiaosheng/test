#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unlocked-state capability scans on node 0x1220 (04 -> 05 bridge hunt).

Runs inside ONE unlocked connection (ticket -> 2E F1A1 -> 27 01 -> 27 02):

  1. `2E <DID>` with **zero data bytes** over the whole DID space.
     Locked, every DID answered 7F 2E 31 (security checked before DID lookup).
     Unlocked, the DID lookup happens first, so a *writable* DID should answer
     7F 2E 13 (incorrectMessageLength) instead of 7F 2E 31 -> that is the hit
     that tells us where the bridge-enable slot lives.  Nothing is written:
     the request carries no data bytes at all.

  2. `22 <DID>` over the whole DID space (the unlocked analogue of the earlier
     scan): F1A3 became readable after the unlock, so other security-gated DIDs
     may appear as well.

Evidence: numbered JSONL + summary under 03_EVIDENCE/cgw/.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "04_SOLVE" / "uds"))
sys.path.insert(0, str(ROOT / "04_SOLVE" / "cgw"))

import solve_task04 as st  # noqa: E402
import doip_uds as d  # noqa: E402
import rid_sweep_unlocked_fast as R  # noqa: E402

HOST = d.DEFAULT_HOST
PORT = d.DEFAULT_PORT
SA = 0x0E00
NODE = d.NODE_1220_TA
BATCH = 32


def scan(link, kind: str, lo: int, hi: int, ev):
    """Pipelined scan; returns {value: response_hex}."""
    rows = {}
    pending = []
    t0 = time.time()
    for start in range(lo, hi + 1, BATCH):
        chunk = list(range(start, min(start + BATCH, hi + 1)))
        for v in chunk:
            if kind == "2e":
                uds = bytes([0x2E]) + v.to_bytes(2, "big")          # no data bytes
            else:
                uds = bytes([0x22]) + v.to_bytes(2, "big")
            link.conn.send(d.PT_DIAG_MSG, struct.pack(">HH", SA, NODE) + uds)
        frames = link.collect_n(len(chunk), timeout=3.0, quiet=0.15)
        bodies = [b for (k, s, b) in frames if k == "uds"]
        if len(bodies) != len(chunk):
            pending.extend(chunk)
            continue
        pos = {}
        negs = []
        for body in bodies:
            # positives echo the value: 6E <DID> / 62 <DID>
            if len(body) >= 3 and body[0] == (0x6E if kind == "2e" else 0x62):
                v = struct.unpack(">H", body[1:3])[0]
                pos[v] = body.hex().upper()
            else:
                negs.append(body.hex().upper())
        if len(set(negs)) > 1 or not set(pos).issubset(chunk):
            pending.extend(chunk)
            continue
        neg = negs[0] if negs else ""
        for v in chunk:
            rows[v] = pos.get(v, neg)
        if (start - lo) % (BATCH * 128) == 0 and start > lo:
            rate = (start - lo) / max(time.time() - t0, 1e-6)
            print(f"    ...0x{start:04X}/{hi:04X} {rate:.0f} req/s pending={len(pending)}")

    # re-probe anything ambiguous on the SAME (still unlocked) connection
    for i, v in enumerate(pending):
        if kind == "2e":
            uds = bytes([0x2E]) + v.to_bytes(2, "big")
        else:
            uds = bytes([0x22]) + v.to_bytes(2, "big")
        link.conn.send(d.PT_DIAG_MSG, struct.pack(">HH", SA, NODE) + uds)
        frames = link.conn.drain(quiet=0.35, total=2.5)
        got = [data[4:] for (ver, ptype, data) in frames
               if ptype == d.PT_DIAG_MSG and len(data) >= 4]
        rows[v] = got[0].hex().upper() if got else ""
        if i % 64 == 0 and i:
            print(f"    verified {i}/{len(pending)}")
    return rows, time.time() - t0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan", choices=["2e", "did", "both"], default="both")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    ev = d.Evidence(d.EVID)
    vin, ticket = R.fetch_ticket()
    link = d.Link(HOST, PORT, ev, SA, 4.0)
    out = {}
    try:
        R.unlock(link, vin, ticket)
        for kind, label, purpose in (
            ("2e", "r4_scan_2e_unlocked", "0x2E zero-data writable-DID scan in unlocked state"),
            ("did", "r4_scan_did_unlocked", "0x22 DID scan in unlocked state"),
        ):
            if args.scan not in (kind, "both"):
                continue
            print(f"[*] {purpose}")
            rows, secs = scan(link, kind, 0x0000, 0xFFFF, ev)
            dist = Counter(rows.values())
            baseline = dist.most_common(1)[0][0]
            hits = {v: b for v, b in rows.items() if b != baseline}
            path = ev.numbered_path(label, "jsonl")
            with open(path, "w", encoding="utf-8") as f:
                for v in sorted(rows):
                    f.write(json.dumps({"v": f"0x{v:04X}", "resp": rows[v]}) + "\n")
            ev.record({"label": label + "_summary", "purpose": purpose,
                       "request": {"ptype": "0x8001", "hex": f"{kind} <did>"},
                       "parsed": f"{len(rows)} DIDs, baseline={baseline}, hits={len(hits)}, "
                                 f"elapsed={secs:.1f}s",
                       "distribution": {k: c for k, c in dist.most_common(10)},
                       "hits": [{"v": f"0x{v:04X}", "resp": b} for v, b in list(hits.items())[:300]],
                       "evidence_file": path.name})
            print(f"[+] {kind}: {len(rows)} DIDs, baseline={baseline}, hits={len(hits)}, {secs:.1f}s -> {path.name}")
            for v, b in list(hits.items())[:60]:
                print(f"    HIT 0x{v:04X} -> {b}")
            out[kind] = hits
    finally:
        link.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
