#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""刻画 /internal/audit 这个「JSON-404 路由」，并枚举同族路由。

判据：
  A = Go 默认 404        -> b'404 page not found\\n'  (len 19)
  B = JSON 404 (真路由)  -> b'{"error":"not found"}\\n' (len 22)
其余状态/长度一律原文打印。
"""
import sys
import time

import requests
import urllib3

urllib3.disable_warnings()
BASE = "http://10.230.164.2:8080"
TIMEOUT = 4.0
A = b"404 page not found\n"
B = b'{"error":"not found"}\n'
VIN = "CV6FF52FEE9EDDD86"


def cls(body):
    if body == A:
        return "A-go404"
    if body == B:
        return "B-JSON404"
    return "??"


def call(method, path, body=None, headers=None):
    h = dict(headers or {})
    if body is not None and "Content-Type" not in h:
        h["Content-Type"] = "application/json"
    try:
        r = requests.request(method, BASE + path, data=body, headers=h,
                             timeout=TIMEOUT, allow_redirects=False)
        return r.status_code, r.content
    except Exception as e:
        return "EXC", f"{type(e).__name__}: {e}".encode()


def main():
    print("=" * 78)
    print(f"/internal/audit 刻画  {time.strftime('%Y-%m-%dT%H:%M:%S%z')}")
    print(f"A(go404)={A!r}  B(json404)={B!r}")
    print("=" * 78)

    print("\n-- 1. 方法矩阵 on /internal/audit --")
    for m in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
              "TRACE"]:
        st, body = call(m, "/internal/audit", b"{}" if m in ("POST", "PUT",
                                                            "PATCH") else None)
        print(f"  {m:7s} /internal/audit        -> {str(st):4s} len={len(body):5d} "
              f"{cls(body)} {body[:120]!r}", flush=True)

    print("\n-- 2. 子树 vs 精确匹配 --")
    subs = ["", "/", "//", "/x", "/x/y", "/1", "/log", "/logs", "/events",
            "/event", "/records", "/list", "/search", "/query", "/export",
            "/download", "/tail", "/recent", "/latest", "/all", "/summary",
            "/stats", "/count", "/csv", "/json", "/index", "/.", "/..",
            "/%2e", "/audit", "/../audit"]
    for s in subs:
        p = "/internal/audit" + s
        st, body = call("GET", p)
        print(f"  GET  {p:32s} -> {str(st):4s} len={len(body):5d} "
              f"{cls(body)} {body[:100]!r}", flush=True)

    print("\n-- 3. 大小写 / 编码变体 --")
    for p in ["/internal/Audit", "/Internal/audit", "/INTERNAL/AUDIT",
              "/internal/%61udit", "/internal/audi%74", "/internal/audit%00",
              "/internal/audit;", "/internal/audit;x=1", "/internal/audit?a=1",
              "/internal/audit#x", "/internal//audit", "//internal/audit"]:
        st, body = call("GET", p)
        print(f"  GET  {p:36s} -> {str(st):4s} len={len(body):5d} "
              f"{cls(body)} {body[:100]!r}", flush=True)

    print("\n-- 4. /internal/* 同族枚举（找其它 JSON404 路由）--")
    names = ["audit", "audits", "auditing", "log", "logs", "events", "event",
             "sign", "signing", "ota", "keys", "key", "certs", "cert", "ca",
             "pki", "config", "conf", "settings", "status", "health", "metrics",
             "stats", "version", "debug", "tokens", "token", "sessions",
             "session", "users", "user", "admin", "backup", "db", "database",
             "seed", "flag", "flags", "secret", "secrets", "firmware", "vcu",
             "campaign", "campaigns", "package", "packages", "artifact",
             "artifacts", "manifest", "manifests", "rollback", "signature",
             "signatures", "verify", "provision", "enroll", "device", "devices",
             "vehicle", "vehicles", "vin", "tbox", "ecu", "ecus", "diag",
             "diagnostics", "report", "reports", "rule", "rules", "policy",
             "policies", "job", "jobs", "task", "tasks", "queue", "worker",
             "cache", "storage", "file", "files", "upload", "download",
             "api", "v1", "v2", "graphql", "rpc", "grpc", "socket", "ws",
             "internal", "system", "sys", "ops", "monitor", "trace", "span",
             "migrate", "schema", "openapi", "swagger", "docs", "info",
             "ping", "readyz", "livez", "startup", "shutdown", "restart",
             "reload", "dump", "export", "import", "sync", "reset"]
    found = []
    for n in names:
        for pat in (f"/internal/{n}", f"/internal/{n}/"):
            st, body = call("GET", pat)
            if cls(body) == "B-JSON404" or st not in (404,):
                found.append((pat, st, len(body), cls(body)))
                print(f"  HIT  GET {pat:34s} -> {str(st):4s} len={len(body):5d} "
                      f"{cls(body)} {body[:120]!r}", flush=True)

    print("\n-- 5. 其它前缀子树探测（admin/debug/sys/_internal/…）--")
    for pre in ["/admin/audit", "/debug/audit", "/sys/audit", "/_internal/audit",
                "/api/internal/audit", "/v1/internal/audit", "/tsp/audit",
                "/internal-audit", "/internal.audit", "/audit",
                "/audit/internal", "/manage/audit", "/management/audit",
                "/mgmt/audit", "/console/audit", "/ops/audit"]:
        st, body = call("GET", pre)
        if cls(body) != "A-go404":
            print(f"  HIT  GET {pre:32s} -> {str(st):4s} len={len(body):5d} "
                  f"{cls(body)} {body[:120]!r}", flush=True)

    print("\n[done]", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
