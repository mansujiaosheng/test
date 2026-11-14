#!/usr/bin/env python3
"""Item: deep-dive TA=0xE442 (the one ECU reachable through the CGW DoIP<->CANFD bridge).

Sequence on ONE connection:
  1. 10 03  -> 50 03
  2. from ext session: 10 02, 10 01, 10 04
  3. 27 01 seed
  4. enumerate 10 xx  (all session subfunctions)
  5. 22 DID sweep F180-F1FF + F100-F1FF + common
  6. 31 01 xx routines
  7. 34 RequestDownload
"""
import sys, os, json, time, binascii
sys.path.insert(0, r"D:\qwb\05_TOOLS")
from cgw_doip import DoIP, open_session

OUT = r"D:\qwb\03_EVIDENCE\cgw_s09"
os.makedirs(OUT, exist_ok=True)
TA = 0xE442
rec = []


def hx(b):
    return binascii.hexlify(b).decode().upper() if b else ""


def go(d, uds, to=3.0, tag=""):
    r, ms = d.uds(uds, ta=TA, extra_timeout=to)
    rec.append({"tag": tag, "tx": hx(uds), "rx": hx(r), "ms": round(ms)})
    print("  %-14s %-22s -> %-40s %5.0fms" % (tag, hx(uds), hx(r) or "EMPTY", ms), flush=True)
    return r


def sess(d):
    d.close()
    d = open_session(timeout=5.0)
    return d


# ================= 1. session walk =================
print("=== 1. session walk on TA=0x%04X ===" % TA)
d = open_session(timeout=5.0)
go(d, b"\x10\x03", tag="enter ext")
go(d, b"\x10\x02", tag="ext->prog")
go(d, b"\x10\x01", tag="ext->default")
go(d, b"\x10\x03", tag="default->ext")
go(d, b"\x10\x02", tag="again prog")
go(d, b"\x27\x01", tag="sec seed")
go(d, b"\x22\xF1\x90", tag="VIN")

# ================= 2. enumerate all 10 xx =================
print("\n=== 2. enumerate 10 xx (default session) ===")
d = sess(d)
hits = []
for sf in range(0x00, 0x100):
    r = go(d, bytes([0x10, sf]), to=2.0, tag="10%02X" % sf)
    if r and r[0] != 0x7F:
        hits.append((sf, hx(r)))
    # no print for boring
d.set = None
print("  positive sessions:", [(("0x%02X" % s), v) for s, v in hits])

# ================= 3. from ext session enumerate 10 xx =================
print("\n=== 3. from ext session (10 03) enumerate 10 xx ===")
d = sess(d)
go(d, b"\x10\x03", tag="to ext")
hits2 = []
for sf in range(0x00, 0x100):
    r, ms = d.uds(bytes([0x10, sf]), ta=TA, extra_timeout=2.0)
    h = hx(r)
    rec.append({"tag": "ext10%02X" % sf, "tx": "10%02X" % sf, "rx": h, "ms": round(ms)})
    if r and r[0] != 0x7F:
        hits2.append((sf, h))
        print("  *** ext 10%02X -> %s" % (sf, h), flush=True)
print("  positive from ext:", [(("0x%02X" % s), v) for s, v in hits2])

json.dump(rec, open(os.path.join(OUT, "0004_e442_session_deepdive.json"), "w"), indent=1)
print("\nwrote 0004_e442_session_deepdive.json  (%d records)" % len(rec))
d.close()
