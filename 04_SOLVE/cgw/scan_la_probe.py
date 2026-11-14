#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Full 16-bit logical-address scan with the probe the Lead asked for.

Rationale (Lead, 2026-11-14 10:5x): the earlier 65536-address scan used
`3E 00` (TesterPresent); a node that silently ignores 0x3E would look dead.
`10 03` (DiagnosticSessionControl, extended) and `22 F190` (VIN) are far more
widely implemented, so the space is rescanned with each probe.

Signal used for a hit:
  * response source address != 0x1000  -> routed to a real node, or
  * response body differs from the dominant baseline (e.g. `50 03` vs `7F1031`)

Method: pipelined batches of 32 on one socket; a batch is accepted only when the
answer count matches and every (src, body) pair is identical.  Anything else is
re-probed one address at a time on a **fresh socket**, so no hit can be a
mis-aligned stale frame.

Everything is written to 03_EVIDENCE/cgw/ (numbered JSONL + summary).
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

PROBES = {
    "1003": bytes.fromhex("1003"),
    "22F190": bytes.fromhex("22F190"),
}


def probe_one(la: int, uds: bytes, ev, timeout=3.0):
    """Fresh socket + activation + one request; returns (src, bodyhex)."""
    link = d.Link(HOST, PORT, ev, SA, timeout)
    try:
        rec, parsed = link.activate(SA, 0x00, label=f"r3_ra_la_{la:04x}")
        if not parsed or parsed.get("code") != "0x10":
            return ("", "")
        payload = struct.pack(">HH", SA, la) + uds
        link.conn.send(d.PT_DIAG_MSG, payload)
        frames = link.conn.drain(quiet=0.4, total=timeout)
        for (ver, ptype, data) in frames:
            if ptype == d.PT_DIAG_MSG and len(data) >= 4:
                src = struct.unpack(">H", data[:2])[0]
                return (f"0x{src:04X}", data[4:].hex().upper())
        return ("", "")
    finally:
        link.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", default="1003", choices=sorted(PROBES))
    ap.add_argument("--lo", default="0000")
    ap.add_argument("--hi", default="FFFF")
    ap.add_argument("--batch", type=int, default=32)
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    uds = PROBES[args.probe]
    lo, hi = int(args.lo, 16), int(args.hi, 16)
    ev = d.Evidence(d.EVID)
    print(f"[*] LA scan probe={args.probe} 0x{lo:04X}-0x{hi:04X} (seq {ev.seq + 1})")

    rows = {}
    pending = []
    t0 = time.time()
    link = d.Link(HOST, PORT, ev, SA, 3.0)
    try:
        rec, parsed = link.activate(SA, 0x00, label=f"r3_ra_lascan_{args.probe.lower()}")
        if not parsed or parsed.get("code") != "0x10":
            print("[!] activation failed", parsed)
            return 1
        for start in range(lo, hi + 1, args.batch):
            chunk = list(range(start, min(start + args.batch, hi + 1)))
            for la in chunk:
                link.conn.send(d.PT_DIAG_MSG, struct.pack(">HH", SA, la) + uds)
            frames = link.collect_n(len(chunk), timeout=3.0, quiet=0.15)
            answers = [(s, b) for (k, s, b) in frames if k == "uds"]
            if len(frames) == len(chunk) and len(answers) == len(chunk) and len(set(answers)) == 1:
                src, body = answers[0]
                for la in chunk:
                    rows[la] = (f"0x{src:04X}", body.hex().upper())
            else:
                pending.extend(chunk)
            if (start - lo) % (args.batch * 128) == 0 and start > lo:
                rate = (start - lo) / max(time.time() - t0, 1e-6)
                print(f"    ...0x{start:04X}/{hi:04X} {rate:.0f} req/s pending={len(pending)}")
    finally:
        link.close()

    print(f"[*] pipelined pass {time.time() - t0:.1f}s, pending={len(pending)}; "
          f"verifying on fresh sockets...")
    for i, la in enumerate(pending):
        rows[la] = probe_one(la, uds, ev)
        if i % 64 == 0 and i:
            print(f"    verified {i}/{len(pending)}")

    dist = Counter(rows.values())
    baseline = dist.most_common(1)[0][0]
    hits = {la: v for la, v in rows.items() if v != baseline}
    path = ev.numbered_path(f"lascan_{args.probe.lower()}_{lo:04x}_{hi:04x}", "jsonl")
    with open(path, "w", encoding="utf-8") as f:
        for la in sorted(rows):
            src, body = rows[la]
            f.write(json.dumps({"la": f"0x{la:04X}", "src": src, "resp": body}) + "\n")
    ev.record({"label": f"lascan_{args.probe.lower()}_{lo:04x}_{hi:04x}_summary",
               "purpose": f"full LA scan with probe {args.probe}",
               "request": {"ptype": "0x8001", "hex": args.probe},
               "parsed": f"{len(rows)} LAs, non-baseline={len(hits)}, "
                         f"baseline={baseline}, elapsed={time.time() - t0:.1f}s",
               "baseline": str(baseline),
               "hits": [{"la": f"0x{la:04X}", "src": v[0], "resp": v[1]} for la, v in list(hits.items())[:300]],
               "evidence_file": path.name})
    print(f"[+] {args.probe}: {len(rows)} LAs, non-baseline={len(hits)}, "
          f"{time.time() - t0:.1f}s -> {path.name}")
    for la, (src, body) in list(hits.items())[:60]:
        print(f"    HIT 0x{la:04X} src={src} {body}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
