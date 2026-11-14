#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Probe the discovered application route /internal/audit on the CGW control plane.

The route answers 404 + {"error":"not found"} (application JSON, distinct from
Go's text/plain "404 page not found"), so the handler ran and looked something
up by a key we did not supply.  This script enumerates plausible keys.
"""
from __future__ import annotations

import json
import itertools
import sys
import time
from pathlib import Path

import urllib3
import requests

urllib3.disable_warnings()

ROOT = Path(__file__).resolve().parents[2]
EVID = ROOT / "03_EVIDENCE" / "cgwweb"

BASE = "http://10.229.221.2:8080"
VIN = "CV6FF52FEE9EDDD86"

PARAM_NAMES = ["vin", "id", "ecu", "target", "name", "node", "addr", "address",
               "la", "canid", "frame", "file", "path", "log", "q", "query", "key",
               "from", "since", "ts", "date", "level", "limit", "offset", "page",
               "session", "task", "job", "trace", "event", "user", "token"]

VALUES = [VIN, "1", "0", "0x1000", "1000", "bcm", "BMS", "vcu", "can0", "canfd0",
          "0x7E0", "7E0", "all", "*", "audit.log", "/var/log/audit.log", "true",
          "default", "gateway", "cgw"]

HEADERS = [{}, {"X-Audit-Token": "0"}, {"Authorization": "Bearer 0"},
           {"X-Internal": "1"}, {"X-Forwarded-For": "127.0.0.1"},
           {"Host": "localhost"}]

METHODS = ["GET", "POST", "HEAD"]


def req(method, url, **kw):
    t0 = time.time()
    try:
        r = requests.request(method, url, timeout=6, allow_redirects=False,
                             verify=False, **kw)
        return {"method": method, "url": url, "status": r.status_code,
                "len": len(r.content), "body": r.text[:400],
                "hdrs": dict(r.headers), "ms": round((time.time() - t0) * 1000, 1)}
    except Exception as e:
        return {"method": method, "url": url, "status": -1,
                "error": f"{type(e).__name__}: {e}", "ms": round((time.time() - t0) * 1000, 1)}


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "/internal/audit"
    results = []
    baseline = req("GET", BASE + path)
    print("baseline:", json.dumps(baseline, ensure_ascii=False))
    results.append(baseline)

    def is_new(r):
        if r.get("status") == -1:
            return True
        if r.get("status") == 404 and (r.get("body") or "").strip() == '{"error":"not found"}':
            return False
        if r.get("status") == 404 and "404 page not found" in (r.get("body") or ""):
            return False
        return True

    # 1) single query param
    for name in PARAM_NAMES:
        for val in VALUES[:6]:
            r = req("GET", f"{BASE}{path}?{name}={requests.utils.quote(str(val))}")
            results.append(r)
            if is_new(r):
                print(f"  [{r['status']}] ?{name}={val} {r['body'][:150]!r}")

    # 2) header variants
    for h in HEADERS[1:]:
        r = req("GET", BASE + path, headers=h)
        results.append(r)
        if is_new(r):
            print(f"  [{r['status']}] hdr={h} {r['body'][:150]!r}")

    # 3) POST bodies
    for body in [{"vin": VIN}, {"id": VIN}, {"file": "audit.log"},
                 {"ecu": "bcm"}, {"limit": 10}, {}]:
        r = req("POST", BASE + path, json=body)
        results.append(r)
        if is_new(r):
            print(f"  [{r['status']}] POST {body} {r['body'][:200]!r}")

    # 4) path variants around /internal/audit
    for p in ["/internal/audit", "/internal/audit/log", "/internal/audit/1",
              "/internal/audit?vin=" + VIN, "/internal/audits", "/internal/audit.json"]:
        r = req("GET", BASE + p)
        results.append(r)
        print(f"  [{r['status']} {r['len']}] {p} {r['body'][:100]!r}")

    out = {"path": path, "results": results}
    (EVID / "4110_internal_audit_probe.json").write_text(
        json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"\nwrote 03_EVIDENCE/cgwweb/4110_internal_audit_probe.json ({len(results)} rows)")


if __name__ == "__main__":
    main()
