#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Round 2: targeted expansion around /api/v1/diag/* and neighbouring roots.

GET is the oracle: a POST-only route answers 405 {"error":"method not allowed"},
an unregistered path answers 19-byte '404 page not found'.
"""
import itertools
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mtls_client import MTLSClient  # noqa: E402

MATDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "..", "..", "03_EVIDENCE", "ticket", "b1")

CHILD = ["session", "sessions", "ticket", "tickets", "ticket/issue", "issue",
         "issue/ticket", "challenge", "nonce", "seed", "key", "key/exchange",
         "unlock", "unlocked", "status", "state", "info", "health", "healthz",
         "version", "verify", "validate", "check", "redeem", "use", "consume",
         "renew", "refresh", "rotate", "revoke", "close", "end", "logout",
         "auth", "authorize", "token", "tokens", "grant", "lease", "attest",
         "attestation", "enroll", "enrollment", "cert", "certs", "certificate",
         "whoami", "metrics", "debug", "trace", "log", "logs", "audit",
         "vehicle", "vehicles", "campaign", "campaigns", "vin", "ecu", "ecus",
         "cgw", "doip", "uds", "request", "open", "start", "begin", "new",
         "create", "init", "handshake", "challenge/sign", "sign", "signature",
         "policy", "policies", "acl", "roles", "me", "self", "ping", "readyz",
         "livez", "config", "settings", "capabilities", "features", "routes",
         "endpoints", "schema", "openapi.json", "swagger.json", "docs"]

ROOTS = ["/api/v1/diag", "/api/v1/diagnostics", "/api/v1", "/api", "/v1",
         "/diag", "/diagnostics", "/api/v1/tbox", "/api/v1/cgw", "/api/v2",
         "/api/v1/agent", "/api/v1/fleet", "/fleet", "/internal",
         "/api/v1/session", "/api/v1/auth", "/api/v1/ticket", "/api/v1/uds"]

EXTRA = [
    "/api/v1/diag/session", "/api/v1/diag", "/api/v1/diag/",
    "/api/v1/diag/session/", "/api/v1/diag/session/ticket",
    "/api/v1/diag/session/status", "/api/v1/diag/session/verify",
    "/api/v1/diag/ticket", "/api/v1/diag/tickets",
    "/api/v1/diag/session/issue", "/api/v1/diag/session/redeem",
    "/api/v1/diag/unlock", "/api/v1/diag/uds", "/api/v1/diag/doip",
    "/api/v1/securityaccess", "/api/v1/security-access",
    "/api/v1/security/access", "/api/v1/seed", "/api/v1/key",
    "/.well-known/openapi.json", "/openapi.json", "/swagger.json",
    "/api/v1/diag/session/open", "/api/v1/diag/open",
    "/api/v1/diag/session/challenge", "/api/v1/diag/challenge",
]


def build():
    out, seen = [], set()

    def add(p):
        p = "/" + p.strip("/")
        if p not in seen and len(p) > 1:
            seen.add(p)
            out.append(p)
    for p in EXTRA:
        add(p)
    for r, c in itertools.product(ROOTS, CHILD):
        add("%s/%s" % (r, c))
    # deeper: /api/v1/diag/session/<x>
    for c in CHILD:
        add("/api/v1/diag/session/%s" % c)
    return out


def probe(path):
    c = None
    try:
        c = MTLSClient(matdir=MATDIR, timeout=8.0)
        st, hd, bb = c.request("GET", path)
        miss = (st == 404 and bb == b"404 page not found\n")
        return {"method": "GET", "path": path, "status": st, "len": len(bb),
                "ct": hd.get("Content-Type"), "allow": hd.get("Allow"),
                "body_head": bb[:400].decode("utf-8", "replace"), "miss": miss}
    except Exception as e:
        return {"method": "GET", "path": path, "error": "%s: %s" % (type(e).__name__, e)}
    finally:
        if c:
            c.close()


def main():
    paths = build()
    print("paths: %d" % len(paths), flush=True)
    rows, t0 = [], time.time()
    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(probe, p) for p in paths]
        for f in as_completed(futs):
            r = f.result()
            rows.append(r)
            if not r.get("miss", True):
                print("HIT %-46s %s %4s %s" % (r.get("path"), r.get("status"),
                                               r.get("len"), repr(r.get("body_head", "")[:110])),
                      flush=True)
    hits = [r for r in rows if not r.get("miss", True)]
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "..", "..", "03_EVIDENCE", "ticket", "0202_route_sweep_get_r2.json")
    json.dump({"generated": time.strftime("%FT%T"), "total": len(paths),
               "hits": hits, "all": rows}, open(out, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("\n== %d hits / %d paths in %.1fs ==" % (len(hits), len(paths), time.time() - t0))


if __name__ == "__main__":
    main()
