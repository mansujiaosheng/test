#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Extension-oriented OTA/asset path probe for T-BOX 10.230.164.3:8080.

Earlier passes (wave1 407 paths, wave2 1169 paths) used mostly bare directory
names. This pass is deliberately extension-first: OTA packages, firmware blobs,
PKI material and Go runtime endpoints, and it records status + Content-Length +
Content-Type for EVERY response (not just non-404), so "is it really absent"
is decidable from the log alone.

Read-only GET/HEAD. Concurrency 4, timeout 5 s. No fuzzing of credentials.
"""
import concurrent.futures
import http.client
import json
import sys
import time

HOST = "10.230.164.3"
PORT = 8080
TIMEOUT = 5

DIRS = [
    "", "ota", "ota/packages", "ota/firmware", "ota/campaigns", "ota/download",
    "ota/manifests", "ota/sign", "otas", "firmware", "firmwares", "packages",
    "pkg", "artifacts", "releases", "images", "static", "assets", "public",
    "download", "downloads", "files", "blobs", "data", "storage", "media",
    "campaigns", "campaign", "ref", "refs", "reference", "sample", "samples",
    "vcu", "vcu/firmware", "vcu/ref", "firmware/vcu", "firmware/ref",
    "fleet", "fleet/ota", "tbox", "tbox/ota", "tbox/firmware", "tbox/certs",
    "tbox/cert", "pki", "pki/ca", "certs", "cert", "ca", "keys", "crypto",
    "sign", "signer", "signing", "keys/vcu", "verify", "api", "api/v1",
    "api/ota", "api/v1/ota", "api/v1/firmware", "v1", "v1/ota",
    ".well-known", ".well-known/pki-validation", "debug", "debug/pprof",
    "internal", "admin", "config", "status", "info", "version", "metrics",
]
NAMES = [
    "index", "manifest", "manifest.json", "index.json", "catalog", "catalog.json",
    "list", "list.json", "latest", "latest.json", "current", "current.json",
    "ca", "ca.crt", "ca.pem", "root.crt", "root.pem", "chain.pem",
    "client.crt", "client.pem", "server.crt", "tls.crt", "bundle.pem",
    "vcu", "vcu.bin", "vcu-ref", "vcu_ref", "vcu-ref.bin", "vcu_ref.bin",
    "ref", "ref.bin", "reference.bin", "sample.bin", "sample.zip",
    "firmware", "firmware.bin", "firmware.zip", "ota", "ota.zip", "ota.tar.gz",
    "package", "package.zip", "packages.zip", "update.bin", "update.zip",
    "CV6FF52FEE9EDDD86", "CV6FF52FEE9EDDD86.bin", "CV6FF52FEE9EDDD86.zip",
    "healthz", "healthz.json", "health", "readyz", "livez",
    "pprof", "goroutine", "heap", "profile", "trace", "cmdline", "symbol",
    "version", "buildinfo", "metrics", "vars", "config.json", "settings.json",
]
EXTS = [".zip", ".bin", ".tar.gz", ".tgz", ".img", ".json", ".txt", ".pem",
        ".crt", ".sig", ".der", ".manifest", ".elf", ".hex", ".pkg"]

SPECIAL = [
    "/healthz", "/healthz/", "/debug/pprof/", "/debug/pprof/goroutine",
    "/debug/pprof/heap", "/debug/pprof/profile", "/debug/pprof/cmdline",
    "/debug/pprof/symbol", "/debug/pprof/trace", "/metrics", "/version",
    "/.well-known/security.txt", "/robots.txt", "/sitemap.xml", "/favicon.ico",
    "/ca.crt", "/pki/ca.crt", "/certs/ca.crt", "/ota/", "/firmware/",
]


def gen_paths():
    seen = set()
    out = []

    def add(p):
        p = p.strip("/")
        if p not in seen:
            seen.add(p)
            out.append(p)

    for s in SPECIAL:
        add(s)
    for d in DIRS:
        for n in NAMES:
            add(f"{d}/{n}" if d else n)
        for e in EXTS:
            add(f"{d}/index{e}" if d else f"index{e}")
    # directory-extension combos: /ota/<name>.<ext>
    for d in ["ota", "firmware", "packages", "download", "static", "assets",
              "ref", "vcu", "pki", "certs", "campaigns"]:
        for n in ["vcu", "ref", "reference", "firmware", "package", "sample",
                  "ca", "bundle", "CV6FF52FEE9EDDD86"]:
            for e in EXTS:
                add(f"{d}/{n}{e}")
    return out


def probe(path):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=TIMEOUT)
    try:
        conn.request("GET", "/" + path,
                     headers={"Host": "tbox", "User-Agent": "tbox-ota-probe",
                              "Accept": "*/*", "Connection": "close"})
        r = conn.getresponse()
        body = r.read(4096)
        return {
            "path": "/" + path,
            "status": r.status,
            "len": r.getheader("Content-Length"),
            "ctype": r.getheader("Content-Type"),
            "loc": r.getheader("Location"),
            "bytes_read": len(body),
            "head": body[:80].decode("latin1").replace("\n", "\\n"),
        }
    except Exception as e:
        return {"path": "/" + path, "error": f"{type(e).__name__}: {e}"}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    paths = gen_paths()
    print(f"###### T-BOX 8080 extension-oriented OTA probe  "
          f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} ######")
    print(f"## target {HOST}:{PORT}  paths={len(paths)}  method=GET  timeout={TIMEOUT}s")
    print("## every response is logged; status!=404 lines are marked HIT")
    print()
    t0 = time.time()
    rows = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        for r in ex.map(probe, paths):
            rows.append(r)
    hits = [r for r in rows if r.get("status") not in (404, None)]
    errs = [r for r in rows if "error" in r]
    for r in hits:
        print(f"HIT  {r['status']}  {r['path']}  len={r['len']}  "
              f"ctype={r['ctype']}  loc={r['loc']}  head={r['head']!r}")
    print()
    print(f"## total={len(rows)} hits={len(hits)} errors={len(errs)} "
          f"elapsed={time.time()-t0:.1f}s")
    if errs:
        print("## errors:")
        for r in errs[:20]:
            print("   ", r["path"], r["error"])
    # distribution of 404 body sizes, to prove the "all 404" is uniform
    sizes = {}
    for r in rows:
        if r.get("status") == 404:
            sizes[r.get("len")] = sizes.get(r.get("len"), 0) + 1
    print(f"## 404 Content-Length distribution: {sizes}")
    with open(sys.argv[1] if len(sys.argv) > 1 else "ota_probe_rows.json",
              "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
