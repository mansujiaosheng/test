#!/usr/bin/env python3
"""Last untested dimensions on T01: /graphql query-string params, and non-GET/POST
methods on likely OTA paths. Read-only."""
import requests

BASE = "http://10.230.164.2:8080"
S = requests.Session()

CANNED = b'{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}\n'
VIN = "CV6FF52FEE9EDDD86"

print("=" * 76)
print("A. POST /graphql + query string ?k=v  (handler may read r.URL.Query())")
print("=" * 76)
qs = [
    "vin=" + VIN, "vin=*", "vin=all", "debug=1", "debug=true", "admin=1",
    "internal=1", "token=test", "role=admin", "raw=1", "full=1", "all=1",
    "mode=prod", "mode=debug", "env=prod", "op=vehicles", "operationName=GetVehicles",
    "tenant=internal", "scope=admin", "include=all", "format=json",
    "query={vehicles{vin}}", "d=true", "trace=1", "verbose=1", "ota=1",
]
for q in qs:
    try:
        r = S.post(f"{BASE}/graphql?{q}", data=b"{}",
                   headers={"Content-Type": "application/json"}, timeout=15)
        same = (r.content == CANNED and r.status_code == 200)
        print(f"  ?{q:36s} -> {r.status_code} {'SAME-as-canned' if same else 'DIFF: ' + repr(r.content[:140])}")
    except Exception as e:
        print(f"  ?{q:36s} -> EXC {type(e).__name__}")

print()
print("=" * 76)
print("B. non-GET/POST methods on likely OTA / key paths")
print("=" * 76)
paths = [
    "/ota", "/ota/manifest", "/ota/packages", "/ota/download", "/ota/package",
    "/firmware", "/firmware/latest", "/firmware/download", "/packages",
    "/download", "/upload", "/sign", "/verify", "/keys", "/pki", "/certs",
    "/ca", "/admin", "/internal", "/debug/vars", "/graphql", "/healthz",
]
methods = ["PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "PROPFIND", "MKCOL"]
for p in paths:
    row = []
    for m in methods:
        try:
            r = S.request(m, BASE + p, data=b"{}",
                          headers={"Content-Type": "application/json"}, timeout=15)
            is404 = (r.status_code == 404 and r.content == b"404 page not found\n")
            tag = f"{r.status_code}" + ("" if is404 and r.status_code == 404 else "*")
            if not is404:
                row.append(f"{m}={r.status_code}:{r.content[:60]!r}")
            else:
                row.append(f"{m}=404")
        except Exception as e:
            row.append(f"{m}=EXC({type(e).__name__})")
    line = "  ".join(row)
    if any(":" in x or "EXC" in x for x in row):
        print(f"  {p:20s} {line}")
print("  (paths whose 8 methods were all plain 404 are omitted)")
