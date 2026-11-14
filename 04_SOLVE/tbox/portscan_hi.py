#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Connect-scan remaining high ports on 10.230.164.3 (prior scan covered 1..10000).

Usage: python portscan_hi.py 10001 65535
Notes: target drops (no RST) on unopened ports, so every miss costs the timeout.
"""
import concurrent.futures as cf
import socket
import sys
import time

HOST = "10.230.164.3"
TIMEOUT = 0.6
WORKERS = 64


def probe(p):
    s = socket.socket()
    s.settimeout(TIMEOUT)
    try:
        rc = s.connect_ex((HOST, p))
        return p, rc
    except Exception:
        return p, -1
    finally:
        try:
            s.close()
        except Exception:
            pass


def main():
    lo, hi = int(sys.argv[1]), int(sys.argv[2])
    t0 = time.time()
    opens, errs = [], 0
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for i, (p, rc) in enumerate(ex.map(probe, range(lo, hi + 1), chunksize=32), 1):
            if rc == 0:
                opens.append(p)
                print("[OPEN] %s:%d" % (HOST, p), flush=True)
            elif rc not in (10061, 111, 61):
                errs += 1
            if i % 5000 == 0:
                print("  ... %d/%d (%.1fs)" % (i, hi - lo + 1, time.time() - t0), flush=True)
    print("[*] %s ports=%d..%d open=%s other_errs=%d elapsed=%.1fs"
          % (HOST, lo, hi, opens, errs, time.time() - t0))


if __name__ == "__main__":
    main()
