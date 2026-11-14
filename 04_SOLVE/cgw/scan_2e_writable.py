#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scan the writable-DID table of node 0x1220 with a length-invalid 0x2E.

Request shape: 2E <DID>   (SID + 2-byte DID, **zero data bytes**)

Nothing can be written: the payload carries no data bytes at all, so even a
sloppy server has nothing to store; ISO 14229 requires the length check to fail
with NRC 0x13 before any write.  The NRC therefore tells us only whether the
DID is recognised by the write path:
    0x31 -> DID not in the write table (or service not implemented)
    0x13 -> DID recognised but message length invalid  => WRITABLE DID FOUND
    0x33 -> write path exists but security access denied
    0x22 -> conditions not correct
Any DID whose answer differs from the dominant NRC is reported.

Pipelined in batches; a batch is only accepted when every answer is identical
and the count matches, otherwise the batch is re-probed one DID at a time.
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
TARGET = d.NODE_1220_TA   # 0xE442 -> node 0x1220


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    lo, hi, batch = 0x0000, 0xFFFF, 32
    ev = d.Evidence(d.EVID)
    link = d.Link(HOST, PORT, ev, SA, 3.0)
    rows = []
    slow = 0
    t0 = time.time()
    try:
        rec, parsed = link.activate(SA, 0x00, label="r2_ra_2e_scan")
        if not parsed or parsed.get("code") != "0x10":
            print("[!] routing activation failed", parsed)
            return 1
        for start in range(lo, hi + 1, batch):
            chunk = list(range(start, min(start + batch, hi + 1)))
            for did in chunk:
                link.conn.send(d.PT_DIAG_MSG,
                               struct.pack(">HH", SA, TARGET) + bytes([0x2E]) + did.to_bytes(2, "big"))
            frames = link.collect_n(len(chunk), timeout=3.0, quiet=0.15)
            bodies = {b for (k, s, b) in frames if k == "uds"}
            if (len(frames) != len(chunk)
                    or not all(k == "uds" for k, _, _ in frames)
                    or len(bodies) != 1):
                slow += 1
                for did in chunk:
                    payload = struct.pack(">HH", SA, TARGET) + bytes([0x2E]) + did.to_bytes(2, "big")
                    link.conn.send(d.PT_DIAG_MSG, payload)
                    fr = link.collect_n(1, timeout=2.5, quiet=0.35)
                    u = [b for (k, s, b) in fr if k == "uds"]
                    rows.append({"did": f"0x{did:04X}",
                                 "resp": u[0].hex().upper() if u else ""})
                continue
            body = frames[0][2].hex().upper()
            for did in chunk:
                rows.append({"did": f"0x{did:04X}", "resp": body})
            if (start - lo) % (batch * 128) == 0 and start > lo:
                rate = (start - lo) / max(time.time() - t0, 1e-6)
                print(f"    ...0x{start:04X}/{hi:04X} {rate:.0f} req/s")
    finally:
        link.close()

    from collections import Counter
    dist = Counter(r["resp"] for r in rows)
    baseline = dist.most_common(1)[0][0]
    hits = [r for r in rows if r["resp"] != baseline]
    path = ev.numbered_path("scan2e_0000_ffff", "jsonl")
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    ev.record({"label": "scan2e_0000_ffff_summary",
               "purpose": "0x2E zero-data writable-DID scan on node 0x1220",
               "request": {"ptype": "0x8001", "hex": "2E <did> (no data bytes)"},
               "parsed": f"{len(rows)} DIDs, baseline={baseline}, hits={len(hits)}, "
                         f"slow_batches={slow}, elapsed={time.time() - t0:.1f}s",
               "distribution": dict(dist),
               "hits": hits[:200],
               "evidence_file": path.name})
    print(f"[+] 2E scan: {len(rows)} DIDs, baseline={baseline}, hits={len(hits)}, "
          f"{time.time() - t0:.1f}s -> {path.name}")
    for h in hits[:60]:
        print("    hit", h["did"], h["resp"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
