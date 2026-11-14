#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stage G: brute force the mTLS diagnostic endpoint 10.225.139.3:8443.

The campaign record advertises diagnosticEndpoint=https://tbox:8443 and the
engineering bundle ships a client cert that verifies against it.  A Go server
that answers 404 on "/" must still have SOMETHING registered, otherwise the
endpoint would be pointless.  Use one Session (keep-alive) to make the sweep
cheap, and only report non-404.
"""
import json, os, warnings
import requests
from requests.adapters import HTTPAdapter
from concurrent.futures import ThreadPoolExecutor
from urllib3.exceptions import InsecureRequestWarning

warnings.simplefilter("ignore", InsecureRequestWarning)

HERE = os.path.dirname(os.path.abspath(__file__))
EV = os.path.abspath(os.path.join(HERE, "..", "..", "03_EVIDENCE", "sign"))
DIAG = os.path.abspath(os.path.join(HERE, "..", "..", "work", "bundle2", "x", "diagnostics"))
BASE = "https://10.225.139.3:8443"
DEFAULT = "404 page not found\n"

TAILS = """
sign signature signing sign-request signing-request firmware-signature vcu-signature
ota-signature update-signature authorize authorization authorize-update commit submit
package manifest bundle artifact firmware firmwares vcu ota campaign campaigns
objective objectives flag credential credentials key keys public-key publickey
certificate certificates cert ca pki
diagnostics diagnostic diag diagnostics/vcu diagnostics/ota diagnostics/sign
ota/engineering-bundle engineering-bundle engineering ota/firmware ota/vcu
vcu/reference vcu-reference vcu/sign reference reference-firmware
health healthz status version info metrics debug
update updates update/package update/manifest
vehicle vehicles vehicle/vcu vin
uds can canfd doip session session/start
transfer transfer/start upload download
""".split()
PREFIXES = ["", "/api", "/api/v1", "/api/v1/ota", "/api/v1/diagnostics", "/api/v1/firmware",
            "/api/v1/vcu", "/api/v1/vehicle", "/api/v1/campaigns", "/api/v1/sign",
            "/api/v1/objectives", "/internal", "/v1", "/diagnostics", "/diag", "/tbox"]
EXTRA = """
/api/v1/ota/engineering-bundle /graphql /internal/audit /healthz /
""".split()


def build():
    p = set(EXTRA)
    for pre in PREFIXES:
        for t in TAILS:
            p.add(f"{pre}/{t}")
    return sorted(p)


def mk_session():
    s = requests.Session()
    s.mount("https://", HTTPAdapter(pool_connections=4, pool_maxsize=4, max_retries=0))
    s.cert = (os.path.join(DIAG, "client.pem"), os.path.join(DIAG, "client-key.pem"))
    s.verify = False
    return s


_local = []


def get_session():
    import threading
    tid = threading.get_ident()
    for t, s in _local:
        if t == tid:
            return s
    s = mk_session()
    _local.append((tid, s))
    return s


def probe(args):
    path, method = args
    s = get_session()
    rec = {"p": path, "m": method}
    try:
        r = s.request(method, BASE + path, timeout=10, allow_redirects=False,
                      headers={"Host": "tbox"})
        rec.update(s=r.status_code, n=len(r.content), ct=r.headers.get("content-type", ""),
                   b=r.text[:200], default=(r.text == DEFAULT))
    except Exception as e:
        rec["e"] = f"{type(e).__name__}"
    return rec


def main():
    paths = build()
    jobs = [(p, m) for p in paths for m in ("GET", "POST")]
    print(f"[*] {len(jobs)} mTLS requests over {len(paths)} paths")
    out = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        for r in ex.map(probe, jobs):
            out.append(r)
    json.dump(out, open(os.path.join(EV, "G_tbox8443_routes.json"), "w"), indent=1)
    hits = [r for r in out if r.get("e") or not r.get("default", True)]
    print(f"[*] non-default: {len(hits)}")
    for r in hits:
        print(f"  {r['m']} {r['p']:46s} {r.get('s')} {r.get('n')} "
              f"{r.get('ct','')[:22]:22s} {r.get('b','')[:80]!r} {r.get('e','')}")


if __name__ == "__main__":
    main()
