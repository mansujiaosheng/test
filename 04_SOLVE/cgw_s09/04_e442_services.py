#!/usr/bin/env python3
"""Profile the REAL ECU at TA=0xE442: which UDS services are actually parsed,
then sweep 0x27 subfunctions. Marker: anything != NRC 0x11 (serviceNotSupported)
means the service exists on this ECU."""
import sys, os, json, binascii
sys.path.insert(0, r"D:\qwb\05_TOOLS")
from cgw_doip import open_session

OUT = r"D:\qwb\03_EVIDENCE\cgw_s09"
TA = 0xE442
rec = []


def hx(b):
    return binascii.hexlify(b).decode().upper() if b else ""


print("=== service surface of TA=0x%04X (payload = [svc,0x00]) ===" % TA)
d = open_session(timeout=5.0)
supported, other = [], {}
for svc in range(0x00, 0x100):
    tx = bytes([svc, 0x00])
    r, ms = d.uds(tx, ta=TA, extra_timeout=2.0)
    h = hx(r)
    rec.append({"svc": "0x%02X" % svc, "tx": hx(tx), "rx": h, "ms": round(ms)})
    if r is None:
        other.setdefault("EMPTY", []).append(svc)
        continue
    nrc = r[2] if len(r) >= 3 and r[0] == 0x7F else None
    if r[0] == 0x7F and nrc == 0x11:
        continue  # not supported
    supported.append((svc, h))
    print("  0x%02X -> %s" % (svc, h), flush=True)

print("\n  => %d services supported (of 256)" % len(supported))
print("  supported:", [(("0x%02X" % s), v) for s, v in supported])
if other:
    print("  non-responding svcs:", {k: ["0x%02X" % x for x in v] for k, v in other.items()})
d.close()

print("\n=== 0x27 subfunction sweep on TA=0x%04X ===" % TA)
d = open_session(timeout=5.0)
d.uds(b"\x10\x03", ta=TA, extra_timeout=3.0)
seed27 = {}
for sf in range(0x00, 0x80):
    tx = bytes([0x27, sf])
    r, ms = d.uds(tx, ta=TA, extra_timeout=2.0)
    h = hx(r)
    rec.append({"svc": "27%02X" % sf, "tx": hx(tx), "rx": h, "ms": round(ms)})
    if r and r[0] == 0x7F and len(r) >= 3 and r[2] == 0x11:
        continue
    print("  27 %02X -> %s" % (sf, h or "EMPTY"), flush=True)
    seed27[sf] = h
print("  => non-NRC11 27 subfns:", {("0x%02X" % k): v for k, v in seed27.items()})
d.close()

json.dump(rec, open(os.path.join(OUT, "0005_e442_service_surface.json"), "w"), indent=1)
print("\nwrote 0005_e442_service_surface.json (%d records)" % len(rec))
