#!/usr/bin/env python3
"""Sibling-host service location sweep.

Goal (task item: "OTA 定位"): 10.230.164.2:8080 is a 2-route Go stub.
Find whether the real TSP / OTA / signing service lives on a sibling IP
in the same /24s that the VPN routes to.

Only connect() + optional tiny HTTP GET banner. No payloads, no writes.
"""
import socket, sys, time, json
from concurrent.futures import ThreadPoolExecutor

NETS = sys.argv[1].split(",") if len(sys.argv) > 1 else ["10.230.164", "10.229.221"]
PORTS = [22, 80, 443, 1883, 3000, 3001, 5000, 5001, 7001, 7080, 7443, 8000, 8008,
         8080, 8081, 8082, 8083, 8085, 8086, 8088, 8090, 8180, 8443, 8500, 8883,
         8888, 9000, 9090, 9091, 9092, 9093, 9191, 9200, 9300, 9443, 10000,
         10250, 13400, 13401, 18080]
TO = 0.45
W = 400

def probe(hp):
    host, port = hp
    s = socket.socket(); s.settimeout(TO)
    try:
        s.connect((host, port))
    except Exception:
        return None
    finally:
        try: s.close()
        except Exception: pass
    return host, port

def banner(host, port):
    """Send a single GET / and read whatever comes back (<=200 B)."""
    try:
        s = socket.create_connection((host, port), timeout=1.2)
        s.settimeout(1.2)
        s.sendall(b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % host.encode())
        data = s.recv(200)
        s.close()
        return data.replace(b"\r\n", b" | ")[:160]
    except Exception as e:
        return ("<%s>" % type(e).__name__).encode()

jobs = [("%s.%d" % (n, i), p) for n in NETS for i in range(1, 255) for p in PORTS]
print("targets %d" % len(jobs), flush=True)
t0 = time.time()
hits = []
with ThreadPoolExecutor(max_workers=W) as ex:
    for r in ex.map(probe, jobs):
        if r:
            hits.append(r); print("OPEN %s:%d" % r, flush=True)
print("---", flush=True)
print("open_total=%d elapsed=%.1fs" % (len(hits), time.time() - t0))
print("--- banners ---", flush=True)
for h, p in hits:
    print("%s:%d  %r" % (h, p, banner(h, p)), flush=True)
json.dump([{"host": h, "port": p} for h, p in hits],
          open("D:/qwb/03_EVIDENCE/tsp/0302_sibling_open.json", "w"), indent=1)
