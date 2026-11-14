#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Full RID scan for RoutineControl 0x31 on node 0x1220 (via functional 0xE442).

Request shapes
  --kind 3101       31 01 <RID>                 startRoutine, no parameters
  --kind 3103       31 03 <RID>                 requestRoutineResults (read-only)
  --kind 3101pN     31 01 <RID> + N zero bytes  startRoutine with N parameter bytes

Why: every RID probed so far answers 7F 31 33 (securityAccessDenied), i.e. the
security gate is evaluated first.  A RID that is NOT behind the gate would answer
71 01 <RID> ... (positive) or 7F 31 31/13/22, so the scan records any response
whose first two bytes are not 7F 31.

Method: pipelined batches of 32 (the link answered ~900 req/s for 0x2E).  A batch
is accepted only when the answer count matches and all answers are byte-identical;
every other RID goes into a `pending` list and is re-probed on a **fresh socket,
one request at a time**, so a hit can never be a mis-aligned stale frame.

Evidence: one numbered JSONL (rid -> response hex) plus a numbered summary JSON.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import doip_uds as d  # noqa: E402

HOST = d.DEFAULT_HOST
PORT = d.DEFAULT_PORT
SA = 0x0E00
TARGET = d.NODE_1220_TA  # 0xE442


def build(kind: str, rid: int):
    if kind == "3101":
        return bytes([0x31, 0x01]) + rid.to_bytes(2, "big")
    if kind == "3103":
        return bytes([0x31, 0x03]) + rid.to_bytes(2, "big")
    if kind.startswith("3101p"):
        n = int(kind[5:])
        return bytes([0x31, 0x01]) + rid.to_bytes(2, "big") + b"\x00" * n
    raise SystemExit(f"bad kind {kind}")


def probe_one(rid: int, uds: bytes, ev, timeout=3.0):
    """Fresh socket + routing activation + one request (isolation for hits)."""
    link = d.Link(HOST, PORT, ev, SA, timeout)
    try:
        rec, parsed = link.activate(SA, 0x00, label=f"r3_ra_{rid:04x}")
        if not parsed or parsed.get("code") != "0x10":
            return ""
        payload = struct.pack(">HH", SA, TARGET) + uds
        link.conn.send(d.PT_DIAG_MSG, payload)
        frames = link.conn.drain(quiet=0.45, total=timeout)
        uds_frames = [data[4:] for (ver, ptype, data) in frames
                      if ptype == d.PT_DIAG_MSG and len(data) >= 4]
        return uds_frames[0].hex().upper() if uds_frames else ""
    finally:
        link.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", default="3101")
    ap.add_argument("--lo", default="0000")
    ap.add_argument("--hi", default="FFFF")
    ap.add_argument("--batch", type=int, default=32)
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    lo, hi = int(args.lo, 16), int(args.hi, 16)
    kind = args.kind
    ev = d.Evidence(d.EVID)
    print(f"[*] scan {kind} RID 0x{lo:04X}-0x{hi:04X} on 0x{TARGET:04X} (seq {ev.seq + 1})")

    rows = {}
    pending = []
    t0 = time.time()
    link = d.Link(HOST, PORT, ev, SA, 3.0)
    try:
        rec, parsed = link.activate(SA, 0x00, label=f"r3_ra_scan_{kind}")
        if not parsed or parsed.get("code") != "0x10":
            print("[!] activation failed", parsed)
            return 1
        for start in range(lo, hi + 1, args.batch):
            chunk = list(range(start, min(start + args.batch, hi + 1)))
            for rid in chunk:
                link.conn.send(d.PT_DIAG_MSG,
                               struct.pack(">HH", SA, TARGET) + build(kind, rid))
            frames = link.collect_n(len(chunk), timeout=3.0, quiet=0.15)
            bodies = [b for (k, s, b) in frames if k == "uds"]
            if len(frames) == len(chunk) and len(bodies) == len(chunk) and len(set(bodies)) == 1:
                body = bodies[0].hex().upper()
                for rid in chunk:
                    rows[rid] = body
            else:
                pending.extend(chunk)
            if (start - lo) % (args.batch * 128) == 0 and start > lo:
                rate = (start - lo) / max(time.time() - t0, 1e-6)
                print(f"    ...0x{start:04X}/{hi:04X} {rate:.0f} req/s pending={len(pending)}")
    finally:
        link.close()

    print(f"[*] pipelined pass done in {time.time() - t0:.1f}s, pending={len(pending)}, "
          f"verifying on fresh sockets...")
    for i, rid in enumerate(pending):
        body = probe_one(rid, build(kind, rid), ev)
        rows[rid] = body
        if i % 64 == 0 and i:
            print(f"    verified {i}/{len(pending)}")

    hits = {rid: body for rid, body in rows.items()
            if not body.startswith("7F31")}
    dist = Counter(rows.values())
    path = ev.numbered_path(f"ridscan_{kind}_{lo:04x}_{hi:04x}", "jsonl")
    with open(path, "w", encoding="utf-8") as f:
        for rid in sorted(rows):
            f.write(json.dumps({"rid": f"0x{rid:04X}", "resp": rows[rid]}) + "\n")
    ev.record({"label": f"ridscan_{kind}_{lo:04x}_{hi:04x}_summary",
               "purpose": f"full RID scan {kind} on 0x1220 via 0xE442",
               "request": {"ptype": "0x8001", "hex": f"{kind} <rid>"},
               "parsed": f"{len(rows)} RIDs, hits(non-7F31)={len(hits)}, "
                         f"elapsed={time.time() - t0:.1f}s",
               "distribution": {k: v for k, v in dist.most_common(10)},
               "hits": [{"rid": f"0x{r:04X}", "resp": b} for r, b in list(hits.items())[:200]],
               "evidence_file": path.name})
    print(f"[+] {kind}: {len(rows)} RIDs, non-7F31 hits={len(hits)}, {time.time() - t0:.1f}s -> {path.name}")
    for rid, body in list(hits.items())[:40]:
        print(f"    HIT 0x{rid:04X} -> {body}")
    if not hits:
        print("    (no RID bypassed the security gate)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
