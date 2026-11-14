#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stage B: enumerate the REST surfaces for an OTA-signing endpoint.

Targets:
  TSP   10.225.139.2:8080   (known real routes: /graphql, /api/v1/objectives/final)
  TBOX  10.225.139.3:8080   (known real routes: /healthz, /api/v1/ota/engineering-bundle)
  CGW   10.226.193.2:8080
  CGW alias 10.225.139.4:8080
"""
import json, os, sys
import requests
from concurrent.futures import ThreadPoolExecutor
from requests.auth import HTTPBasicAuth

HERE = os.path.dirname(os.path.abspath(__file__))
EV = os.path.abspath(os.path.join(HERE, "..", "..", "03_EVIDENCE", "sign"))

VIN = "CV622697F82A936A1"
CAMP = "CAMP-243892C376D4CB2D5F826953"
CRED = "5e7f07b4a81153ecd5868cc02557f823"

TSP = "http://10.225.139.2:8080"
TBOX = "http://10.225.139.3:8080"
CGW = "http://10.226.193.2:8080"
CGW2 = "http://10.225.139.4:8080"

PREFIXES = ["", "/api", "/api/v1", "/api/v2", "/v1", "/internal/api/v1"]

NOUNS = """
objectives objective final flag flags
ota ota/sign ota/signature ota/update ota/firmware ota/package ota/campaign ota/campaigns
ota/bundle ota/release ota/authorize ota/authorization ota/submit ota/commit ota/verify
ota/signed ota/manifest ota/vcu ota/status ota/rollback
sign signature signatures sign/firmware sign/update sign/ota sign/vcu sign/package sign/campaign
firmware firmware/sign firmware/signature firmware/update firmware/package firmware/verify
firmwares update update/sign update/authorize update/package updates
campaign campaigns campaign/sign campaign/update campaign/authorize campaign/package
campaigns/sign
vehicle vehicle/sign vehicle/update vehicle/campaign vehicle/ota vehicle/signature
vehicles vehicles/sign
vcu vcu/sign vcu/signature vcu/update vcu/package vcu/firmware vcu/authorize
package package/sign packages
authorize authorization authorize/update authorization/update attest attestation
release release/sign releases
software software/sign software/update
ecu ecu/sign ecu/update
commit commits submit submission
audit audit/log audits
diagnostics diagnostic
auth auth/token token tokens login session sessions
keys key public-key publickey cert certs certificate certificates ca
health healthz status version info metrics
""".split()

PATHS = []
for p in PREFIXES:
    for n in NOUNS:
        PATHS.append(f"{p}/{n}".replace("//", "/"))
# vehicle/campaign scoped forms
for p in ["/api/v1", "/api/v1/ota", "/api/v1/vehicle", "/api/v1/campaigns"]:
    for suf in ["sign", "signature", "sign/vcu", "update", "authorize"]:
        PATHS.append(f"{p}/{VIN}/{suf}")
        PATHS.append(f"{p}/{CAMP}/{suf}")
# explicit known-good controls
CONTROL = ["/graphql", "/api/v1/objectives/final"]
PATHS = sorted(set(PATHS) | set(CONTROL))

AUTHMODES = [("none", None), ("diag", HTTPBasicAuth("diag", CRED))]


def probe(args):
    base, path, mode, method = args
    auth = dict(AUTHMODES)[mode]
    url = base + path
    rec = {"base": base, "path": path, "mode": mode, "method": method}
    try:
        r = requests.request(method, url, auth=auth, timeout=6, allow_redirects=False)
        rec["status"] = r.status_code
        rec["len"] = len(r.content)
        rec["ct"] = r.headers.get("content-type", "")
        rec["body"] = r.text[:400]
    except Exception as e:
        rec["err"] = type(e).__name__
    return rec


def main():
    jobs = []
    for base in (TSP, TBOX):
        for path in PATHS:
            for mode, _ in AUTHMODES:
                jobs.append((base, path, mode, "GET"))
                jobs.append((base, path, mode, "POST"))
    for base in (CGW, CGW2):
        for path in PATHS:
            jobs.append((base, path, "none", "GET"))
            jobs.append((base, path, "none", "POST"))

    print(f"[*] {len(jobs)} REST probes")
    # baseline: what does a definitely-absent path look like on each host?
    res = []
    with ThreadPoolExecutor(max_workers=24) as ex:
        for r in ex.map(probe, jobs):
            res.append(r)
    json.dump(res, open(os.path.join(EV, "B_rest_sweep.json"), "w"), indent=1)

    # group by host, print the "not 404" rows
    for base in (TSP, TBOX, CGW, CGW2):
        rows = [r for r in res if r["base"] == base]
        nf = {}
        for r in rows:
            if "status" in r:
                nf[r["status"]] = nf.get(r["status"], 0) + 1
        print(f"\n===== {base}  status histogram {nf}")
        for r in rows:
            st = r.get("status")
            if st and st not in (404,):
                print(f"  {r['method']:4s} {st} {r['len']:6d} {r['mode']:4s} {r['path']}"
                      f"  {r.get('body','')[:150]!r}")


if __name__ == "__main__":
    main()
