#!/usr/bin/env python3
"""httpenum.py -- 只读 HTTP 端点枚举，完整保存响应体

用法：
  python httpenum.py http://10.230.164.3:8080 03_EVIDENCE/fleet/tbox_8080
  python httpenum.py https://10.230.164.3:8443 out --insecure

行为：对每个路径依次发 GET / HEAD，保存：
  <out>/<slug>.meta.txt   状态行 + 全部响应头 + 时间
  <out>/<slug>.body       原始响应体（二进制安全）
  <out>/_index.txt        汇总表
只发 GET/HEAD，不发写方法、不带 payload。
"""
import argparse
import hashlib
import os
import re
import ssl
import sys
import urllib.error
import urllib.request

DEFAULT_PATHS = [
    "/", "/api", "/api/v1", "/health", "/healthz", "/version", "/docs",
    "/openapi.json", "/swagger.json", "/metrics", "/ota", "/firmware",
    "/update", "/diag", "/diagnostics", "/debug", "/status", "/info",
    "/config", "/download", "/manifest", "/.well-known/",
    "/robots.txt", "/favicon.ico", "/ota/manifest", "/ota/firmware",
    "/firmware/manifest", "/api/ota", "/api/firmware", "/api/version",
    "/api/status", "/api/diag", "/v1", "/v2", "/admin", "/login",
    "/cert", "/certs", "/ca", "/ca.crt", "/mtls",
]


def slugify(path):
    s = path.strip("/").replace("/", "_")
    s = re.sub(r"[^A-Za-z0-9_.-]", "-", s)
    return s or "root"


def fetch(url, method="GET", timeout=8, insecure=False, headers=None):
    ctx = None
    if url.startswith("https"):
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", "recon/1.0 (read-only)")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, dict(r.headers), r.read(), None
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read(), None
    except Exception as e:
        return None, {}, b"", f"{type(e).__name__}: {e}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base", help="http://host:port")
    ap.add_argument("outdir")
    ap.add_argument("--paths", nargs="*", default=None)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--timeout", type=float, default=8)
    args = ap.parse_args()

    base = args.base.rstrip("/")
    paths = args.paths or DEFAULT_PATHS
    os.makedirs(args.outdir, exist_ok=True)

    rows = []
    for p in paths:
        url = base + p
        slug = slugify(p)
        status, hdrs, body, err = fetch(url, "GET", args.timeout, args.insecure)
        if err:
            meta = f"URL: {url}\nMETHOD: GET\nRESULT: ERROR {err}\n"
            rows.append((p, "ERR", 0, "-", err[:60]))
        else:
            meta = [f"URL: {url}", "METHOD: GET", f"STATUS: {status}"]
            for k, v in hdrs.items():
                meta.append(f"H: {k}: {v}")
            meta.append(f"BODY_LEN: {len(body)}")
            meta.append(f"BODY_SHA256: {hashlib.sha256(body).hexdigest()}")
            meta = "\n".join(meta) + "\n"
            ct = hdrs.get("Content-Type", hdrs.get("content-type", "-"))
            rows.append((p, str(status), len(body), ct,
                         hashlib.sha256(body).hexdigest()[:16]))
        with open(os.path.join(args.outdir, slug + ".meta.txt"), "w",
                  encoding="utf-8", errors="replace") as f:
            f.write(meta)
        with open(os.path.join(args.outdir, slug + ".body"), "wb") as f:
            f.write(body)
        print(f"  {p:28s} {rows[-1][1]:>4s} {rows[-1][2]:>7} {rows[-1][3][:40]}")

    with open(os.path.join(args.outdir, "_index.txt"), "w",
              encoding="utf-8") as f:
        f.write(f"# endpoint enumeration {base}\n")
        f.write(f"{'PATH':30s} {'STATUS':>6s} {'LEN':>8s} CT / SHA256[:16]\n")
        for p, st, ln, ct, sh in rows:
            f.write(f"{p:30s} {st:>6s} {ln:>8d} {ct[:40]} {sh}\n")
    print(f"\n[+] {len(rows)} paths -> {args.outdir}/_index.txt")


if __name__ == "__main__":
    sys.exit(main())
