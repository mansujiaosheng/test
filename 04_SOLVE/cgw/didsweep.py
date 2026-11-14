#!/usr/bin/env python3
"""Full DID sweep against CGW DoIP, logs positives to stdout (and file given by argv[1])."""
import sys, time, binascii
sys.path.insert(0, r"D:\qwb\05_TOOLS")
from cgw_doip import open_session

host = sys.argv[1] if len(sys.argv) > 1 else "10.229.221.2"
out = sys.argv[2] if len(sys.argv) > 2 else r"D:\qwb\03_EVIDENCE\cgw\didsweep.txt"
ranges = [(0xF000, 0x10000), (0x0000, 0x1000), (0x1000, 0xF000)]

d = open_session(host, timeout=3)
print("session ok", flush=True)
f = open(out, "w", encoding="utf-8")
t0 = time.time()
n = 0
for lo, hi in ranges:
    blk = 0
    for did in range(lo, hi):
        resp, ms = d.uds(bytes([0x22, did >> 8, did & 0xFF]), extra_timeout=0.30)
        n += 1
        if resp is None:
            continue
        if resp[0] == 0x7F:
            if len(resp) >= 3 and resp[2] == 0x31:
                continue
            line = "DID %04X NRC%02X %s" % (did, resp[2], "")
        else:
            line = "DID %04X POS %s" % (did, binascii.hexlify(resp).decode().upper())
            print(line, flush=True)
            f.write(line + "\n"); f.flush()
        blk += 1
    print("block %04X-%04X done, %d hits, total %d, %.0fs" % (lo, hi, blk, n, time.time() - t0), flush=True)
f.close()
print("DONE total=%d elapsed=%.0fs" % (n, time.time() - t0), flush=True)
