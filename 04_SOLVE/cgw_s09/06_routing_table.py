#!/usr/bin/env python3
"""The real ECU behind the alias 0xE442 answers with SA=0x1220.
So the CGW routing table maps TA -> real ECU LA. Find the rest of the table
and probe the real ECU address directly.

Probe payload = 10 03 (a service nearly every flashable ECU answers), plus
3E 00 as a second probe. Flag anything whose NRC != 0x31.
"""
import sys, os, json, binascii
sys.path.insert(0, r"D:\qwb\05_TOOLS")
from cgw_doip import open_session

OUT = r"D:\qwb\03_EVIDENCE\cgw_s09"
rec = []


def hx(b):
    return binascii.hexlify(b).decode().upper() if b else ""


def classify(r):
    if r is None:
        return "EMPTY"
    if r[0] == 0x7F:
        return "NRC%02X" % (r[2] if len(r) >= 3 else 0xFF)
    return "POS:" + hx(r)


# ---------- 1. direct probe of the real ECU LA ----------
print("=== 1. direct probe of real ECU LA 0x1220 ===")
d = open_session(timeout=5.0)
for ta in (0x1220, 0xE442):
    for uds in (b"\x10\x03", b"\x10\x02", b"\x27\x01", b"\x22\xF1\xA3"):
        r, ms = d.uds(uds, ta=ta, extra_timeout=3.0)
        print("  TA=0x%04X %-6s -> %-14s %4.0fms" % (ta, hx(uds), classify(r), ms), flush=True)
        rec.append({"ta": "0x%04X" % ta, "tx": hx(uds), "rx": hx(r), "cls": classify(r), "ms": round(ms)})
d.close()


# ---------- 2. scan ranges with 10 03 ----------
def scan(lo, hi, label, uds=b"\x10\x03"):
    print("\n=== 2. scan 0x%04X-0x%04X (%s) probe=%s ===" % (lo, hi, label, hx(uds)))
    d = open_session(timeout=6.0)
    hits = []
    for ta in range(lo, hi + 1):
        r, ms = d.uds(uds, ta=ta, extra_timeout=2.0)
        c = classify(r)
        rec.append({"ta": "0x%04X" % ta, "scan": label, "tx": hx(uds), "rx": hx(r), "cls": c})
        if c != "NRC31":
            hits.append((ta, c))
            print("  *** TA=0x%04X %s -> %s" % (ta, label, c), flush=True)
    d.close()
    print("  %s: %d/%d non-NRC31" % (label, len(hits), hi - lo + 1))
    return hits


h1 = scan(0x1200, 0x12FF, "0x12xx")
h2 = scan(0xE000, 0xEFFF, "0xE0xx-0xEFxx")

json.dump({"rec": rec, "hits_12xx": [[hex(a), c] for a, c in h1],
           "hits_exxx": [[hex(a), c] for a, c in h2]},
          open(os.path.join(OUT, "0007_routing_table_scan.json"), "w"), indent=1)
print("\nwrote 0007_routing_table_scan.json (%d records)" % len(rec))
