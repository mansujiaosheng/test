#!/usr/bin/env python3
"""Final exhaustive route sweep on TSP 10.230.164.2:8080 using the strong oracle.

Oracle: a path exists iff its response is NOT exactly 404 + "404 page not found\\n".
  200/401/403/405/500  -> route exists
  404 + application/json {"error":"not found"} -> route exists (handler-level 404)
So ANY deviation proves existence. This is stronger than status-code-only sweeps.
"""
import http.client, json, time
from concurrent.futures import ThreadPoolExecutor

HOST, PORT = "10.230.164.2", 8080
DEF = b"404 page not found\n"

PREFIX = ["", "/internal", "/api", "/api/v1", "/api/v2", "/v1", "/v2", "/public",
          "/admin", "/manage", "/console", "/ops", "/service", "/services", "/tsp",
          "/fleet", "/ota", "/sign", "/signer", "/diag", "/device", "/devices"]
NOUN = """audit audits auditlog audit-log log logs event events trace traces
vehicle vehicles vin vins fleet fleets device devices tbox tboxes ecu ecus
ota ota/update ota/packages ota/package ota/manifest ota/campaign ota/campaigns
campaign campaigns release releases release/create release/generate
release/publish release/sign release/approve build builds image images image/new
firmware firmwares package packages artifact artifacts bundle bundles blob blobs
sign signer signing signature signatures verify verification attest attestation
key keys keyring cert certs certificate certificates pki ca chain crl
diag diagnostics dtc dtcs report reports job jobs task tasks queue queues
status info version versions config configs setting settings
health healthz readyz livez metrics stats stat debug pprof
user users me profile account accounts session sessions token tokens auth
oauth login logout refresh revoke introspect provision enroll enrollments
bootstrap register registration activation activate claim claims grant grants
role roles permission permissions policy policies scope scopes tenant tenants
org orgs project projects environment environments secret secrets credential credentials
vault rolebinding rbac acl rules rule
download downloads upload uploads manifest manifests index search query graphql
fleet/manifest fleet/campaigns fleet/vehicles archive archives export import
update updates check poll notify hook hooks webhook webhooks callback
flash flash/request flash/status dump snapshot restore backup restore
""".split()

paths = []
for p in PREFIX:
    for n in NOUN:
        paths.append((p + "/" + n).replace("//", "/"))
paths = list(dict.fromkeys(paths))
print("paths=%d" % len(paths), flush=True)


def probe(path):
    c = http.client.HTTPConnection(HOST, PORT, timeout=7.0)
    try:
        c.request("GET", path, headers={"Accept": "application/json", "Connection": "close"})
        r = c.getresponse()
        d = r.read(8192)
        return path, r.status, r.getheader("Content-Type"), d
    except Exception as e:
        return path, -1, "<%s>" % type(e).__name__, b""
    finally:
        try: c.close()
        except Exception: pass


t0 = time.time()
hits, errs = [], 0
with ThreadPoolExecutor(max_workers=8) as ex:
    for path, st, ct, d in ex.map(probe, paths):
        if st == -1:
            errs += 1
            continue
        if st == 404 and d == DEF:
            continue
        hits.append({"path": path, "status": st, "ct": ct,
                     "body": d.decode("utf-8", "replace")})
        print("HIT %-42s %s ct=%s %r" % (path, st, ct, d[:140]), flush=True)

print("--- done %.1fs  paths=%d  hits=%d  transport_errors=%d"
      % (time.time() - t0, len(paths), len(hits), errs))
json.dump({"probed": len(paths), "errors": errs, "hits": hits},
          open("D:/qwb/03_EVIDENCE/tsp/0330_route_sweep_final.json", "w"), indent=1)
