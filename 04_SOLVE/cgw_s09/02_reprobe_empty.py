#!/usr/bin/env python3
"""Item 1-decisive: are the 125 'empty' TAs real ECUs, or scan-timeout artifacts?

Method:
  A) re-probe all 125 with a LONG timeout (5s) on ONE connection
  B) re-probe a control set of equal size drawn from known-31 addresses
  C) probe TA=0x1000 (gateway self) and TA=0xE442 with real service payloads
If A yields 7F3E31 and timings match B, the 'empty' set was a timeout artifact.
"""
import sys, os, json, time, binascii, statistics
sys.path.insert(0, r"D:\qwb\05_TOOLS")
from cgw_doip import DoIP, open_session, TESTER_SA, GW_TA

OUT = r"D:\qwb\03_EVIDENCE\cgw_s09"
os.makedirs(OUT, exist_ok=True)

src = json.load(open(os.path.join(OUT, "0001_lascan_empty_n11.json")))
empty = [int(d["v"], 16) for d in src["empty"]]
n11 = [int(d["v"], 16) for d in src["n11"]]
print("empty=%d n11=%s" % (len(empty), [hex(x) for x in n11]))

log = []


def probe(d, ta, uds=bytes([0x3E, 0x00]), to=5.0):
    r, ms = d.uds(uds, ta=ta, extra_timeout=to)
    hx = binascii.hexlify(r).decode().upper() if r else ""
    return hx, ms


# ---------- A) re-probe the 125 empties, long timeout ----------
print("\n=== A) re-probe 125 empty TAs, timeout=5s ===")
d = open_session(timeout=6.0)
ares, atimes = [], []
for ta in empty:
    hx, ms = probe(d, ta)
    ares.append({"ta": "0x%04X" % ta, "resp": hx, "ms": round(ms)})
    atimes.append(ms)
    print("  0x%04X -> %-20s %5.0fms" % (ta, hx or "EMPTY", ms), flush=True)
d.close()
log.append({"phase": "A_reprobe_empty", "results": ares})

# ---------- B) control set: same size from known-31 addresses ----------
print("\n=== B) control set (known-31 addresses), timeout=5s ===")
ctrl = [0x2000 + i for i in range(0, 250, 2)][:len(empty)]
d = open_session(timeout=6.0)
bres, btimes = [], []
for ta in ctrl:
    hx, ms = probe(d, ta)
    bres.append({"ta": "0x%04X" % ta, "resp": hx, "ms": round(ms)})
    btimes.append(ms)
d.close()
bcount = {}
for b in bres:
    bcount[b["resp"]] = bcount.get(b["resp"], 0) + 1
print("  control resp histogram:", bcount)
print("  control ms  median=%.0f p95=%.0f max=%.0f"
      % (statistics.median(btimes), sorted(btimes)[int(len(btimes) * .95)], max(btimes)))
log.append({"phase": "B_control", "results": bres})

acount = {}
for a in ares:
    acount[a["resp"]] = acount.get(a["resp"], 0) + 1
print("\n  empty-set resp histogram (after reprobe):", acount)
print("  empty-set ms median=%.0f max=%.0f"
      % (statistics.median(atimes), max(atimes)))

# ---------- C) 0x1000 and 0xE442 with real services ----------
print("\n=== C) TA=0x1000 / 0xE442 with real payloads ===")
cres = []
d = open_session(timeout=6.0)
for ta in (0x1000, 0xE442):
    for uds in (b"\x22\xF1\x90", b"\x3e\x00", b"\x10\x02", b"\x10\x03",
                b"\x22\xF1\x87", b"\x22\xF1\x8C", b"\x19\x02\xFF",
                b"\x22", b"\x10", b"\x27\x01"):
        hx, ms = probe(d, ta, uds, 5.0)
        print("  TA=0x%04X UDS=%-10s -> %-24s %5.0fms"
              % (ta, binascii.hexlify(uds).decode().upper(), hx or "EMPTY", ms), flush=True)
        cres.append({"ta": "0x%04X" % ta, "uds": binascii.hexlify(uds).decode().upper(),
                     "resp": hx, "ms": round(ms)})
d.close()
log.append({"phase": "C_self_and_e442", "results": cres})

json.dump(log, open(os.path.join(OUT, "0003_reprobe_empty_and_e442.json"), "w"), indent=1)
print("\nwrote 0003_reprobe_empty_and_e442.json")
