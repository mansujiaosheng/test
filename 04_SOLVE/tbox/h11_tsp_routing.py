#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""T02 H11: routing-only probe of 10.230.164.2:8080 (TSP).

Deliberately NOT GraphQL semantic fuzzing (that is tsp-gql's task). Questions
asked here are purely routing-level, because .2 is the only "cloud side" surface
and the only place a fleet client certificate / OTA URL could be handed out:

  Q1 does the mux have Host-scoped patterns (Go 1.22 "host/path")?
  Q2 does it have method-scoped patterns for OTA/cert paths?
  Q3 does it expose a cert-bundle / enrollment endpoint at all?

Budget: a few hundred requests, <=20 req/s.
"""
import socket
import time

HOST_IP, PORT = "10.230.164.2", 8080

PATHS = [
    "/ota", "/ota/check", "/ota/manifest", "/ota/update", "/ota/download",
    "/ota/package", "/ota/campaign", "/ota/campaigns", "/ota/jobs",
    "/firmware", "/firmware/latest", "/firmware/download", "/update", "/updates",
    "/diagnostics", "/diag", "/diagnostics/session", "/diag/session",
    "/cert", "/certs", "/cert/client", "/cert/bundle", "/certs/client",
    "/ca.pem", "/client.pem", "/client.crt", "/ca.crt", "/pki", "/pki/ca",
    "/enroll", "/enrollment", "/bootstrap", "/provision", "/provisioning",
    "/register", "/token", "/auth", "/auth/token", "/login", "/session",
    "/mtls", "/mtls/cert", "/device", "/devices", "/vehicle", "/vehicles",
    "/vehicles/CV6FF52FEE9EDDD86", "/vehicles/CV6FF52FEE9EDDD86/ota",
    "/v1/ota", "/api/v1/ota", "/api/ota", "/api/v1/cert", "/api/v1/vehicles",
    "/graphql", "/api/graphql", "/gql", "/query",
]
HOSTS = ["tsp", "tsp.local", "10.230.164.2", "tbox", "fleet", "cv6"]


def http(method, path, host, body=None, timeout=6.0):
    hdr = (f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: tbox-h11\r\n"
           f"Accept: */*\r\nConnection: close\r\n")
    payload = b""
    if body is not None:
        payload = body.encode()
        hdr += f"Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n"
    req = (hdr + "\r\n").encode() + payload
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((HOST_IP, PORT))
        s.sendall(req)
        data = b""
        while len(data) < 1024:
            c = s.recv(1024)
            if not c:
                break
            data += c
        return data.decode("latin1", "replace")
    except Exception as e:
        return f"ERR {type(e).__name__}"
    finally:
        s.close()


def main():
    t0 = time.time()
    hits = []
    n = 0
    for host in HOSTS:
        for p in PATHS:
            for method, body in (("GET", None), ("POST", "{}")):
                n += 1
                r = http(method, p, host, body)
                first = r.split("\r\n")[0] if not r.startswith("ERR") else r
                # 404 = route absent; 405 = route exists but method wrong; 200/400/401/403 = interesting
                if "404" not in first and p not in ("/graphql",):
                    line = f"Host:{host:14s} {method:4s} {p:34s} {first}"
                    print("  HIT " + line)
                    hits.append((host, method, p, first, r))
                elif p == "/graphql" and method == "GET" and "405" not in first:
                    print(f"  !! graphql GET changed: Host:{host} -> {first}")
                time.sleep(0.02)
    print(f"\n{n} requests in {time.time()-t0:.1f}s; non-404 hits (excl /graphql control): {len(hits)}")
    for h in hits[:10]:
        print("   ", h[:4])


if __name__ == "__main__":
    main()
