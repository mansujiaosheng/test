#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stage E: larger exact-path brute force on T-BOX 8080 / TSP 8080.

Go ServeMux reports 404 "404 page not found\n" (text/plain, 19 B) for anything
unregistered.  A 405 or any other body means the path IS registered.
"""
import json, os
import requests
from concurrent.futures import ThreadPoolExecutor
from requests.auth import HTTPBasicAuth

HERE = os.path.dirname(os.path.abspath(__file__))
EV = os.path.abspath(os.path.join(HERE, "..", "..", "03_EVIDENCE", "sign"))
CRED = "5e7f07b4a81153ecd5868cc02557f823"
DEFAULT = "404 page not found\n"

TAILS = """
sign signature signing signed sign-request sign-requests sign-request-vcu
sign-firmware sign-vcu sign-update sign-package sign-campaign signing-request
signature-request signatures firmware-signature vcu-signature ota-signature
update-signature signature-requests
authorize authorization authorized authorization-request authorize-update
authorize-firmware authorize-vcu authorize-ota authorize-package authorization-code
update updated update-request update-package update-manifest update-status
commit committed submit submitted submission final complete completed
package packages manifest bundle bundles artifact artifacts firmware firmwares
vcu vcus ota otas campaign campaigns campaign-id campaign-status
objective objectives flag flags credential credentials key keys public-key
certificate certificates cert ca pki diagnostics diagnostic uds can canfd
health healthz status version info metrics debug
engineering engineering-bundle engineering-sign engineering-signature
""".split()
SEP = ["", "-", "_", ".", "/"]
PREFIXES = ["", "/api", "/api/v1", "/api/v1/ota", "/api/v1/firmware", "/api/v1/vcu",
            "/api/v1/vehicle", "/api/v1/vehicles", "/api/v1/campaign", "/api/v1/campaigns",
            "/api/v1/objectives", "/api/v1/sign", "/api/v1/signature", "/api/v1/update",
            "/internal", "/internal/ota", "/internal/api", "/api/v2", "/v1"]

TARGETS = [
    ("tbox", "http://10.225.139.3:8080", [("none", None), ("diag", HTTPBasicAuth("diag", CRED))]),
    ("tsp", "http://10.225.139.2:8080", [("none", None), ("diag", HTTPBasicAuth("diag", CRED))]),
]


def build_paths():
    p = set()
    for pre in PREFIXES:
        for t in TAILS:
            p.add(f"{pre}/{t}")
    return sorted(p)


def probe(args):
    name, base, path, method, auth = args
    rec = {"t": name, "m": method, "p": path}
    try:
        r = requests.request(method, base + path, auth=auth, timeout=5, allow_redirects=False)
        rec["s"] = r.status_code
        rec["n"] = len(r.content)
        rec["b"] = r.text[:120]
        rec["ct"] = r.headers.get("content-type", "")
    except Exception as e:
        rec["e"] = type(e).__name__
    return rec


def main():
    paths = build_paths()
    print(f"[*] {len(paths)} paths")
    jobs = []
    for name, base, auths in TARGETS:
        for p in paths:
            for m in ("GET", "POST"):
                for aname, a in auths:
                    jobs.append((name, base, p, m, a))
    print(f"[*] {len(jobs)} requests")
    out = []
    with ThreadPoolExecutor(max_workers=32) as ex:
        for r in ex.map(probe, jobs):
            out.append(r)
    json.dump(out, open(os.path.join(EV, "E_route_brute.json"), "w"), indent=1)
    hits = [r for r in out if "s" in r and r["s"] != 404]
    print(f"[*] non-404: {len(hits)}")
    seen = set()
    for r in hits:
        k = (r["s"], r["n"], r["ct"][:22])
        if k in seen:
            continue
        seen.add(k)
        print(f"  {r['t']:4s} {r['m']} {r['s']} {r['n']:5d} {r['ct'][:22]:22s} {r['p']:40s} {r['b'][:70]!r}")
    print("[*] all non-404 rows:")
    for r in hits:
        print(f"  {r['t']:4s} {r['m']} {r['s']} {r['n']:5d} {r['p']:44s} {r['b'][:60]!r}")


if __name__ == "__main__":
    main()
