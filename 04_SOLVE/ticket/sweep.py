#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate routes on the mTLS 8443 endpoint.

Oracle: Go net/http default NotFound = 19 bytes, 'text/plain; charset=utf-8',
body '404 page not found\n'.  Anything else (200/400/401/403/405/500, or a 404
with a different body/content-type) means the path reached a handler.
"""
import itertools
import json
import os
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mtls_client import MTLSClient  # noqa: E402

MATDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "..", "..", "03_EVIDENCE", "ticket", "b1")

PREFIXES = [
    "", "/api", "/api/v1", "/api/v2", "/v1", "/v2",
    "/diag", "/diagnostics", "/diagnostic", "/tbox", "/cv6", "/fleet",
    "/internal", "/rpc", "/agent", "/session", "/mtls", "/edge",
    "/api/v1/diag", "/api/v1/diagnostics", "/api/v1/tbox",
]

NOUNS = [
    "ticket", "tickets", "session", "sessions", "auth", "token", "tokens",
    "challenge", "nonce", "issue", "issueticket", "issue-ticket",
    "diagnostic", "diagnostics", "diagnose", "scan", "scans",
    "status", "health", "healthz", "version", "info", "manifest",
    "vehicle", "vehicles", "campaign", "campaigns", "ota", "bundle",
    "firmware", "enroll", "enrollment", "cert", "certs", "attest",
    "attestation", "lease", "grant", "credential", "credentials",
    "access", "seed", "key", "keys", "pair", "pairing", "provision",
    "provisioning", "authorize", "authorization", "verify", "sign",
    "signature", "start", "begin", "open", "new", "create", "issue/v1",
    "whoami", "metrics", "debug", "readyz", "livez", "ping", "root",
]

EXTRA = [
    "/", "/healthz", "/api", "/api/v1", "/diagnostics", "/diag", "/ticket",
    "/tickets", "/session", "/auth", "/token", "/ota", "/campaigns",
    "/vehicles", "/manifest", "/status", "/version",
    "/api/v1/diagnostics/ticket", "/api/v1/diag/ticket",
    "/diagnostics/ticket", "/diag/ticket", "/diag/session",
    "/v1/diagnostics/ticket", "/api/v1/ticket", "/api/v1/session",
    "/api/v1/auth/ticket", "/api/v1/auth/token", "/api/v1/tickets/issue",
    "/api/v1/diagnostics/session", "/api/v1/diagnostics/challenge",
    "/api/v1/diagnostics/nonce", "/api/v1/diag/session",
    "/api/v1/ticket/issue", "/ticket/issue", "/tickets/issue",
    "/diagnostics/issue", "/diag/issue", "/issue", "/challenge", "/nonce",
    "/api/v1/challenge", "/api/v1/nonce", "/api/v1/issue",
    "/securityaccess", "/security-access", "/api/v1/securityaccess",
    "/api/v1/uds", "/uds", "/doip", "/api/v1/doip", "/api/v1/seed",
    "/api/v1/27", "/api/v1/diagnostics/seed",
    "/api/v1/diagnostics/ticket/issue", "/api/v1/diag/ticket/issue",
    "/api/v1/diagnostics/session/ticket", "/api/v1/vehicle/CV622697F82A936A1",
    "/api/v1/vehicles/CV622697F82A936A1", "/vehicle/CV622697F82A936A1",
    "/api/v1/vehicles", "/api/v1/campaigns", "/api/v1/manifest",
    "/api/v1/status", "/api/v1/version", "/api/v1/healthz",
    "/__debug", "/debug/pprof/", "/api/v1/ota/bundle",
    "/api/v1/ota/engineering-bundle", "/api/v1/campaigns/CAMP-243892C376D4CB2D5F826953",
]


def build_paths():
    paths = list(EXTRA)
    for pre, n in itertools.product(PREFIXES, NOUNS):
        paths.append("%s/%s" % (pre, n))
    # two-level tails for the most likely prefixes
    tails = ["ticket", "session", "challenge", "issue", "nonce", "auth", "seed"]
    mids = ["diagnostics", "diag", "tickets", "session", "auth"]
    for pre in ["", "/api", "/api/v1", "/v1", "/diag", "/diagnostics"]:
        for m, t in itertools.product(mids, tails):
            paths.append("%s/%s/%s" % (pre, m, t))
    seen, out = set(), []
    for p in paths:
        p = "/" + p.lstrip("/")
        p = p.replace("//", "/")
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def is_miss(status, hdrs, body):
    ct = ""
    for k, v in hdrs.items():
        if k.lower() == "content-type":
            ct = v.lower()
    return status == 404 and len(body) == 19 and body == b"404 page not found\n"


def probe(path, method="GET", body=None):
    c = None
    try:
        c = MTLSClient(matdir=MATDIR, timeout=8.0)
        st, hd, bb = c.request(method, path, body=body)
        return {
            "method": method, "path": path, "status": st,
            "len": len(bb),
            "content_type": hd.get("Content-Type"),
            "allow": hd.get("Allow"),
            "server": hd.get("Server"),
            "body_head": bb[:400].decode("utf-8", "replace"),
            "miss": is_miss(st, hd, bb),
        }
    except Exception as e:
        return {"method": method, "path": path, "error": "%s: %s" % (type(e).__name__, e)}
    finally:
        if c:
            c.close()


def main():
    paths = build_paths()
    print("paths: %d" % len(paths), flush=True)
    rows = []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = {}
        for p in paths:
            futs[ex.submit(probe, p, "GET")] = (p, "GET")
        done = 0
        for f in as_completed(futs):
            r = f.result()
            rows.append(r)
            done += 1
            if not r.get("miss", True):
                print("HIT", r.get("method"), r.get("path"), r.get("status"),
                      r.get("len"), repr(r.get("body_head", "")[:120]), flush=True)
            if done % 100 == 0:
                print("... %d/%d  %.1fs" % (done, len(paths), time.time() - t0), flush=True)

    hits = [r for r in rows if not r.get("miss", True)]
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "..", "..", "03_EVIDENCE", "ticket", "0201_route_sweep_get.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"generated": time.strftime("%FT%T"), "total": len(paths),
                   "hits": hits, "all": rows}, fh, ensure_ascii=False, indent=1)
    print("\n== %d hits / %d paths in %.1fs ==" % (len(hits), len(paths), time.time() - t0))
    for r in sorted(hits, key=lambda x: str(x.get("path"))):
        print("%-4s %-56s %s %4s %s" % (r.get("method"), r.get("path"), r.get("status"),
                                        r.get("len"), repr(r.get("body_head", "")[:100])))


if __name__ == "__main__":
    main()
