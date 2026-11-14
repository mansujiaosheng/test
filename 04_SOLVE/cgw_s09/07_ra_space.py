#!/usr/bin/env python3
"""Item 3: Routing Activation full parameter space.
Does the CGW routing table change with SA / activation type / OEM bytes?
After each successful RA, probe TA=0xE442 and a few candidate TAs.
"""
import sys, os, json, binascii, struct
sys.path.insert(0, r"D:\qwb\05_TOOLS")
from cgw_doip import DoIP, pkt

OUT = r"D:\qwb\03_EVIDENCE\cgw_s09"
rec = []


def hx(b):
    return binascii.hexlify(b).decode().upper() if b else ""


def one_ra(sa, act, oem4=b"\x00\x00\x00\x00", extra=b"", to=3.0):
    d = DoIP(timeout=to).connect()
    d.ident()
    payload = struct.pack(">H", sa) + bytes([act]) + oem4 + extra
    d.send(0x0005, payload)
    r = d.recv_pkt()
    out = {"sa": "0x%04X" % sa, "act": "0x%02X" % act,
           "oem": hx(oem4 + extra), "resp": hx(r[2]) if r else None}
    return d, out


print("=== 1. RA parameter sweep: SA x activationType ===")
sas = [0x0E00, 0x0E80, 0x0F00, 0xF000, 0x1000, 0x0E01, 0x0E0F, 0x0EFF]
acts = [0x00, 0x01, 0x02, 0x03, 0xE0, 0xFF]
ok = []
for sa in sas:
    for act in acts:
        d, o = one_ra(sa, act)
        rec.append(o)
        print("  SA=0x%04X act=0x%02X -> %-24s" % (sa, act, o["resp"] or "EMPTY"), flush=True)
        if o["resp"] and o["resp"][8:10] == "10":  # response code 0x10 success
            ok.append((sa, act))
        d.close()
print("  => successful RAs:", [("0x%04X" % s, "0x%02X" % a) for s, a in ok])

print("\n=== 2. RA with extra OEM bytes ===")
for extra in [b"", b"\x00\x00\x00\x00", b"\x01\x00\x00\x00\x00\x00\x00\x00",
              b"\x00" * 8, b"\xFF" * 4, b"\x00" * 16]:
    d, o = one_ra(0x0E00, 0x00, extra=extra)
    rec.append(o)
    print("  extra(%d)=%s -> %s" % (len(extra), hx(extra), o["resp"] or "EMPTY"), flush=True)
    d.close()

print("\n=== 3. does the routing table depend on the last successful RA? ===")
for sa, act in [(0x0E00, 0x00), (0x0E80, 0xE0), (0x0F00, 0x02), (0x0E00, 0xE0)]:
    d, o = one_ra(sa, act, to=4.0)
    if not o["resp"]:
        print("  SA=0x%04X act=0x%02X RA empty, skip" % (sa, act))
        d.close()
        continue
    probe = []
    for ta in (0xE442, 0x1220, 0x1000):
        r, ms = d.uds(b"\x10\x03", ta=ta, extra_timeout=2.5)
        probe.append({"ta": "0x%04X" % ta, "rx": hx(r), "ms": round(ms)})
        print("  SA=0x%04X act=0x%02X TA=0x%04X 10 03 -> %-14s"
              % (sa, act, ta, hx(r) or "EMPTY"), flush=True)
    rec.append({"ra": o, "probe": probe})
    d.close()

json.dump(rec, open(os.path.join(OUT, "0008_ra_parameter_space.json"), "w"), indent=1)
print("\nwrote 0008_ra_parameter_space.json (%d records)" % len(rec))
