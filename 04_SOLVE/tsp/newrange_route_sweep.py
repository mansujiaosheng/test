#!/usr/bin/env python3
"""
New-range TSP route sweep with the JSON-404 oracle.

The old TSP (10.230.164.2) went dark ~09:55 and the range was re-provisioned.
The new TSP is 10.225.139.2:8080 (identical signature: /healthz 200, GET /graphql 405,
POST /graphql canned, /internal/audit 404 application/json {"error":"not found"}).

Critical point: the 8000+ path sweeps in the workspace were all run against the OLD
instance. The NEW instance may be a different build (the design doc says the TSP is
supposed to expose a maintenance/OTA package readable via BOLA/IDOR).

Oracle (the only reliable one on this service):
   unregistered  -> 404  text/plain  "404 page not found\n"          (19 B)
   registered    -> anything else, notably 404 application/json {"error":"not found"} (22 B)
"""
import sys
import time

import requests

HOST = sys.argv[1] if len(sys.argv) > 1 else "10.225.139.2"
PORT = sys.argv[2] if len(sys.argv) > 2 else "8080"
BASE = f"http://{HOST}:{PORT}"
GO404 = b"404 page not found\n"

PATHS = r"""
/healthz
/graphql
/internal/audit
/internal/audit/1
/internal
/internal/
/internal/health
/internal/status
/internal/vehicles
/internal/ota
/internal/package
/internal/packages
/internal/maintenance
/internal/audit-log
/internal/audits
/internal/events
/internal/metrics
/internal/debug
/internal/config
/internal/version
/internal/info
/internal/token
/internal/auth
/debug/vars
/debug/pprof/
/metrics
/version
/ota
/ota/
/ota/package
/ota/packages
/ota/packages/1
/ota/manifest
/ota/manifests
/ota/download
/ota/update
/ota/updates
/ota/campaign
/ota/campaigns
/ota/artifact
/ota/artifacts
/ota/sign
/ota/verify
/package
/packages
/packages/1
/package/1
/artifacts
/artifact
/artifacts/1
/maintenance
/maintenance/
/maintenance/package
/maintenance/packages
/maintenance/packages/1
/maintenance/1
/maint
/pcap
/pcaps
/pcap/1
/capture
/captures
/trace
/traces
/vehicles
/vehicles/1
/vehicles/CV6FF52FEE9EDDD86
/vehicle/CV6FF52FEE9EDDD86
/vehicles/CV6000000DEMO0001
/vins
/vins/CV6FF52FEE9EDDD86
/v1/ota/packages
/v1/vehicles
/api
/api/
/api/v1
/api/v1/
/api/v1/ota
/api/v1/packages
/api/v1/vehicles
/api/v1/audit
/api/v1/internal/audit
/api/v1/auth
/api/v1/auth/token
/api/v1/auth/login
/api/v1/token
/api/health
/api/status
/api/packages
/api/vehicles
/api/ota
/tsp
/tsp/ota
/tsp/packages
/tsp/vehicles
/tsp/internal
/key
/keys
/key/1
/cert
/certs
/ca
/ca.pem
/sign
/signature
/signatures
/verify
/jwks
/jwks.json
/.well-known/jwks.json
/admin
/admin/ota
/admin/packages
/admin/audit
/console
/graphiql
/graphql/
/graphql/schema
/download
/downloads
/download/1
/files
/files/1
/file/1
/objects
/objects/1
/blob
/storage
/bucket
""".strip().splitlines()

METHODS = ["GET", "POST"]

S = requests.Session()
S.headers.update({"User-Agent": "tsp-probe/3.0",
                  "Content-Type": "application/json"})


def main():
    print("=" * 78)
    print(f"NEW-RANGE TSP route sweep  target={BASE}  paths={len(PATHS)}")
    print("oracle: 404 text/plain 19B = unregistered; anything else = registered")
    print("=" * 78)
    hits = []
    errs = 0
    for m in METHODS:
        for p in PATHS:
            p = p.strip()
            if not p:
                continue
            try:
                if m == "GET":
                    r = S.get(BASE + p, timeout=10)
                else:
                    r = S.post(BASE + p, data=b"{}", timeout=10)
            except Exception as e:
                errs += 1
                print(f"  {m:4s} {p:44s} EXC {type(e).__name__}")
                continue
            unregistered = (r.status_code == 404 and r.content == GO404)
            if not unregistered:
                hits.append((m, p, r.status_code, r.headers.get("Content-Type"), r.content))
                body = r.content[:100].replace(b"\n", b"\\n")
                print(f"  {m:4s} {r.status_code} {p:44s} "
                      f"ct={r.headers.get('Content-Type')!r} body={body!r}")
    print("-" * 78)
    print(f"hits={len(hits)}  transport_errors={errs}  paths={len(PATHS)} x {len(METHODS)}")
    seen = set()
    for m, p, sc, ct, b in hits:
        key = (p, sc)
        if key in seen:
            continue
        seen.add(key)
        print(f"  REGISTERED: {p:44s} {m:4s} {sc} {ct}")
    print("=" * 78)
    print("done", time.strftime("%Y-%m-%dT%H:%M:%S"))


if __name__ == "__main__":
    main()
