#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Two cheap leftovers for T02:

A) the ~20 ports nmap reported as "filtered" on 10.230.164.3 -> re-test with a
   long connect timeout (nmap may have hit RST ratelimiting, not a real drop).
B) 10.230.164.3:8080 host-scoped route hypothesis: Go 1.22+ ServeMux supports
   "host/path" patterns, so a route registered as "tbox/ota" 404s for every
   other Host. All prior brute (1576 paths) used the default Host.
C) query-string variants on /healthz and on likely OTA paths.
"""
import concurrent.futures as cf
import socket
import time

HOST = "10.230.164.3"
FILTERED = [2929, 6295, 10324, 10352, 16591, 24660, 35183, 36317, 39064,
            39929, 41622, 50549, 52753, 54844, 59443, 59861, 60114, 61122,
            62216, 62926, 63786]

PATHS = [
    "/ota", "/ota/", "/ota/check", "/ota/manifest", "/ota/update", "/ota/download",
    "/ota/status", "/ota/campaign", "/ota/package", "/ota/firmware",
    "/update", "/update/check", "/firmware", "/firmware/latest", "/firmware/download",
    "/diagnostics", "/diag", "/diag/session", "/diagnostics/session", "/diag/start",
    "/diagnostics/start", "/diagnostics/read", "/diag/read",
    "/mtls", "/mtls/cert", "/cert", "/certs", "/cert/client", "/certificate",
    "/client.pem", "/client.crt", "/ca.pem", "/ca.crt", "/pki", "/pki/ca",
    "/device", "/device/info", "/device/cert", "/info", "/status", "/version",
    "/api", "/api/v1", "/api/v1/ota", "/api/v1/ota/check", "/api/v1/diagnostics",
    "/api/v1/cert", "/api/v1/device", "/api/ota", "/api/diagnostics",
    "/v1", "/v1/ota", "/v1/ota/check", "/v1/diagnostics", "/v1/cert", "/v1/device",
    "/tbox", "/tbox/ota", "/tbox/diagnostics", "/tbox/health", "/tbox/info",
    "/enroll", "/bootstrap", "/provision", "/provisioning", "/register",
    "/auth", "/auth/cert", "/token", "/session", "/login", "/admin",
    "/debug", "/debug/pprof/", "/debug/pprof/goroutine", "/metrics", "/config",
    "/internal", "/internal/ota", "/internal/cert", "/healthz", "/readyz", "/livez",
    "/vehicles", "/vehicle", "/vehicles/CV6FF52FEE9EDDD86",
    "/vehicles/CV6FF52FEE9EDDD86/ota", "/vehicles/CV6FF52FEE9EDDD86/diagnostics",
]
HOSTS = ["tbox", "tbox.local", "10.230.164.3", "localhost"]
QUERIES = [
    "/healthz?debug=1", "/healthz?verbose=1", "/healthz?ota=1",
    "/healthz?cert=1", "/ota?check=1", "/diagnostics?session=1",
]


def connect_test(port, timeout=4.0):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((HOST, port))
        return True
    except Exception:
        return False
    finally:
        s.close()


def http(req, timeout=4.0):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((HOST, 8080))
        s.sendall(req.encode())
        data = b""
        while len(data) < 4096:
            c = s.recv(4096)
            if not c:
                break
            data += c
        return data.decode("latin1", "replace")
    except Exception as e:
        return f"ERR {type(e).__name__} {e}"
    finally:
        s.close()


def main():
    print("=== A. filtered-port recheck (4s connect timeout) ===")
    for p in FILTERED:
        if connect_test(p):
            print(f"  !! {HOST}:{p} CONNECTED (nmap said filtered)")
    print("  done (no line above = all truly dropped/silent)")

    print("\n=== B. host-scoped route sweep on :8080 ===")
    work = [(h, p) for h in HOSTS for p in PATHS]
    t0 = time.time()
    findings = 0
    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        def job(a):
            h, p = a
            r = http(f"GET {p} HTTP/1.1\r\nHost: {h}\r\nConnection: close\r\n\r\n")
            first = r.split("\r\n")[0] if r and not r.startswith("ERR") else r
            return h, p, first, r
        for h, p, first, r in ex.map(job, work):
            if p == "/healthz" or "404" not in first:
                print(f"  Host: {h:16s} {p:45s} -> {first}")
                findings += 1
    print(f"  {len(work)} probes in {time.time()-t0:.1f}s, {findings} non-404 (incl /healthz)")

    print("\n=== C. query variants on :8080 ===")
    for q in QUERIES:
        r = http(f"GET {q} HTTP/1.1\r\nHost: tbox\r\nConnection: close\r\n\r\n")
        print(f"  {q:36s} -> {r.split(chr(13))[0] if not r.startswith('ERR') else r}")


if __name__ == "__main__":
    main()
