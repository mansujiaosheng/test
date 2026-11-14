#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stage C: subtree oracle on every HTTP surface.

Go's ServeMux returns a bare "404 page not found\n" (19 B, text/plain) for an
unregistered path.  But /internal/audit returned {"error":"not found"} (22 B,
application/json) - i.e. some *other* handler owns that subtree.  Any path whose
404 body differs from the default therefore sits under a registered handler.

This script probes <prefix>/__probe__ for a large set of prefixes and reports
every prefix whose 404 (or any) response differs from the default body.
"""
import json, os, ssl, socket
import requests
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
EV = os.path.abspath(os.path.join(HERE, "..", "..", "03_EVIDENCE", "sign"))
B = os.path.abspath(os.path.join(HERE, "..", "..", "work", "bundle2", "x", "diagnostics"))

CRED = "5e7f07b4a81153ecd5868cc02557f823"
DEFAULT = "404 page not found\n"

PREFIXES = """
/
/internal /internal/ /internal/api /internal/api/ /internal/api/v1 /internal/debug
/internal/ota /internal/sign /internal/audit /internal/v1 /internal/admin
/api /api/ /api/v1 /api/v1/ /api/v1/ota /api/v1/vehicle /api/v1/vehicles
/api/v1/campaign /api/v1/campaigns /api/v1/firmware /api/v1/sign /api/v1/signature
/api/v1/objectives /api/v1/objectives/final /api/v1/admin /api/v1/internal
/api/v1/diagnostics /api/v1/vcu /api/v1/update /api/v1/auth /api/v1/pki
/api/v1/cert /api/v1/certs /api/v1/keys /api/v1/v2 /api/v2 /api/v2/
/admin /debug /ota /sign /firmware /campaign /campaigns /vehicle /vehicles /vcu
/v1 /v1/ /v2 /graphql/ /diagnostics /diag /tbox /ecu /cloud /service /services
""".split()

TARGETS = [
    ("tsp-8080", "http://10.225.139.2:8080", None),
    ("tbox-8080", "http://10.225.139.3:8080", None),
    ("cgw-8080", "http://10.226.193.2:8080", None),
    ("cgw-alias-8080", "http://10.225.139.4:8080", None),
]


def mk_mtls():
    return ("https://10.225.139.3:8443",
            os.path.join(B, "client.pem"), os.path.join(B, "client-key.pem"),
            os.path.join(B, "ca.pem"))


def probe(args):
    name, base, prefix, method, mtls = args
    path = prefix.rstrip("/") + "/__probe_zz__"
    rec = {"target": name, "prefix": prefix, "method": method, "path": path}
    try:
        kw = dict(timeout=8, allow_redirects=False)
        if mtls:
            kw["cert"] = (mtls[1], mtls[2])
            kw["verify"] = mtls[3]
            kw["headers"] = {"Host": "tbox"}
        r = requests.request(method, base + path, **kw)
        rec.update(status=r.status_code, ct=r.headers.get("content-type", ""),
                   len=len(r.content), body=r.text[:200])
        rec["default"] = (r.text == DEFAULT)
    except Exception as e:
        rec["err"] = f"{type(e).__name__}: {e}"[:150]
    return rec


def main():
    jobs = []
    for name, base, _ in TARGETS:
        for p in PREFIXES:
            jobs.append((name, base, p, "GET", None))
            jobs.append((name, base, p, "POST", None))
    base, cert, key, ca = mk_mtls()
    for p in PREFIXES:
        jobs.append(("tbox-8443", base, p, "GET", (base, cert, key, ca)))
        jobs.append(("tbox-8443", base, p, "POST", (base, cert, key, ca)))

    print(f"[*] {len(jobs)} prefix probes")
    out = []
    with ThreadPoolExecutor(max_workers=16) as ex:
        for r in ex.map(probe, jobs):
            out.append(r)
    json.dump(out, open(os.path.join(EV, "C_prefix_oracle.json"), "w"), indent=1)

    interesting = [r for r in out if r.get("err") or not r.get("default", True)]
    print(f"[*] non-default responses: {len(interesting)}")
    for r in interesting:
        print(f"  {r['target']:15s} {r['method']:4s} {r['prefix']:28s} "
              f"{r.get('status')} {r.get('len')} {r.get('ct','')[:28]:28s} "
              f"{r.get('body','')[:110]!r}")


if __name__ == "__main__":
    main()
