#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TCP connect sweep of a /24 for a small set of service ports.

Read-only, low rate (capped concurrency), used to find hosts beyond the
already-known .2/.3/.4 on the CyberCar range segment.
"""
import concurrent.futures as cf
import socket
import sys
import time

PORTS = [8080, 8443, 80, 443, 22, 1883, 8883, 3000, 5000, 9090, 13400, 13401]
NET = sys.argv[1] if len(sys.argv) > 1 else "10.230.164."
TIMEOUT = 0.6
WORKERS = 64


def probe(ip, port):
    s = socket.socket()
    s.settimeout(TIMEOUT)
    try:
        s.connect((ip, port))
        try:
            s.settimeout(1.0)
            s.sendall(b"GET /healthz HTTP/1.0\r\nHost: x\r\n\r\n")
            data = s.recv(200)
            return ip, port, data[:120].decode("latin1", "replace").replace("\r\n", " | ")
        except Exception:
            return ip, port, "(connect ok, no http reply)"
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def main():
    t0 = time.time()
    targets = [(NET + str(i), p) for i in range(1, 255) for p in PORTS]
    hits = []
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for r in ex.map(lambda a: probe(*a), targets):
            if r:
                hits.append(r)
                print(f"OPEN {r[0]}:{r[1]}  {r[2]}", flush=True)
    print(f"-- {len(hits)} open of {len(targets)} probes, {time.time()-t0:.1f}s")


if __name__ == "__main__":
    main()
