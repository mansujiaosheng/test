#!/usr/bin/env python3
"""Exhaustive UDS service sweep against the live CGW target (TA 0x1000).

Writes one JSONL line per probe to 04_SOLVE/cgw/services.jsonl and a compact
non-NRC11 report. Resumable: skips SIDs already present in the jsonl.
"""
import sys, json, os, binascii, time
from cli import Cli, pfmt

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "services.jsonl")


def load():
    done = {}
    if os.path.exists(OUT):
        for ln in open(OUT, encoding="utf-8"):
            try:
                j = json.loads(ln)
                done[j["sid"]] = j
            except Exception:
                pass
    return done


def main():
    done = load()
    c = Cli()
    c.ensure_ra()
    ack = None
    f = open(OUT, "a", encoding="utf-8")
    hits = []
    t_start = time.time()
    for sid in range(0x00, 0x100):
        if sid in done:
            continue
        req = bytes([sid, 0x00])
        r = c.uds(req)
        rec = {"sid": sid, "req": binascii.hexlify(req).decode().upper(),
               "kind": ("none" if r["uds"] is None else
                        ("nrc" if r["uds"][0] == 0x7F else "pos")),
               "nrc": (r["uds"][2] if r["uds"] and r["uds"][0] == 0x7F and len(r["uds"]) > 2 else None),
               "uds": binascii.hexlify(r["uds"]).decode().upper() if r["uds"] else "",
               "ms": round(r["ms"], 1), "stale": r["stale"],
               "acks": [a[1] if isinstance(a, (list, tuple)) else a for a in r["acks"]]}
        f.write(json.dumps(rec) + "\n")
        f.flush()
        if not (rec["kind"] == "nrc" and rec["nrc"] == 0x11):
            hits.append(rec)
            print("  *** SID 0x%02X -> %s %s" % (sid, rec["kind"], rec["uds"] or rec["nrc"]), flush=True)
        if (sid % 32) == 0:
            print("  ... 0x%02X  %.0fs" % (sid, time.time() - t_start), flush=True)
    f.close()
    c.close()
    print("=== non-NRC11 services: %d" % len(hits))
    for h in hits:
        print("  0x%02X %s %s" % (h["sid"], h["kind"], h["uds"] or ("NRC%02X" % h["nrc"] if h["nrc"] else "")))


if __name__ == "__main__":
    main()
