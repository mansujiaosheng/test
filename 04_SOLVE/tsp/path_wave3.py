#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TSP 路径 wave3：>=8000 条 API 风格路径 × GET/POST，带 404 基线漂移判定。

基线（已实测）：Go 默认 404 page not found\\n  len=19
判定：任何 (status, body) != 基线 的响应都算 hit，单独输出。
      /graphql 这类「路径存在但有方法检查」会以 405 暴露，因此 GET 扫描
      足以发现 POST-only 路由。

写盘：只写 03_EVIDENCE/tsp/。只读探测，20 线程，3s 超时。
"""
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import product

import requests
import urllib3

urllib3.disable_warnings()
HOST = "10.230.164.2:8080"
BASE = f"http://{HOST}"
TIMEOUT = 3.0
WORKERS = 20
VIN = "CV6FF52FEE9EDDD86"
BASELINE = b"404 page not found\n"
CAP = 12000


def load_wave2(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    except OSError:
        return []


def gen_paths():
    """按优先级生成路径，去重保序。"""
    S1 = ["", "api", "api/v1", "api/v2", "api/v3", "v1", "v2", "v3",
          "internal", "admin", "tsp", "fleet", "svc", "service",
          "ota", "ota/v1", "ota/api", "backend", "mgmt", "management"]
    S2 = ["ota", "otas", "firmware", "firmwares", "campaign", "campaigns",
          "package", "packages", "sign", "signature", "signatures", "signer",
          "keys", "key", "cert", "certs", "pki", "vcu", "ecu", "ecus",
          "image", "images", "bundle", "bundles", "artifact", "artifacts",
          "job", "jobs", "task", "tasks", "release", "releases", "update",
          "updates", "upgrade", "upgrades", "vehicle", "vehicles", "device",
          "devices", "manifest", "manifests", "rollback", "calibration"]
    S3 = ["sign", "signature", "signatures", "verify", "verification",
          "create", "new", "generate", "gen", "issue", "request", "submit",
          "apply", "bind", "attach", "approve", "commit", "status", "result",
          "download", "upload", "list", "get", "post", "run", "exec",
          "invoke", "enroll", "enrollment", "provision", "push", "start",
          "sign-firmware", "signFirmware", "createSign", "sign_offline"]

    seen = set()
    out = []

    def add(p):
        p = p.strip("/")
        if p and p not in seen:
            seen.add(p)
            out.append(p)

    # 0) 已知存在（回归）
    for p in ["healthz", "graphql"]:
        add(p)

    # 1) 单段高频
    for a in S2:
        add(a)
    for a in S1:
        if a:
            add(a)

    # 2) a/b
    for a, b in product(S1, S2):
        add(f"{a}/{b}" if a else b)

    # 3) b/c
    for b, c in product(S2, S3):
        add(f"{b}/{c}")

    # 4) a/b/c  (a 取 API 前缀，b 取核心资源)
    core_b = ["ota", "firmware", "campaign", "campaigns", "sign", "cert",
              "vehicle", "vehicles", "vcu", "package", "job", "artifact"]
    for a, b, c in product(["api/v1", "api/v2", "api/v3", "v1", "v2",
                            "internal", "admin", "ota"], core_b, S3):
        add(f"{a}/{b}/{c}")

    # 5) 带 VIN / campaign id 的实参路径
    ids = [VIN, "demo", "1", "default", "{id}"]
    for pre in ["ota", "api/v1/ota", "firmware", "vehicles", "campaigns",
                "internal/ota", "admin/ota"]:
        for i in ids:
            add(f"{pre}/{i}")
            for leaf in ["sign", "ota", "signatures", "firmware", "manifest"]:
                add(f"{pre}/{i}/{leaf}")
    for pre in ["campaigns", "ota/campaigns", "api/v1/campaigns"]:
        for leaf in ["sign", "firmware", "packages"]:
            add(f"{pre}/c1/{leaf}")

    # 6) OTA 语义穷举：资源 × 动作 × 常见 API 前缀
    for pre, res in product(["ota", "api/v1", "internal", "admin", "v1", "v2"],
                            S2):
        add(f"{pre}/{res}/sign")
        add(f"{pre}/{res}/verify")
    for pre, res in product(["api/v1", "ota"], S2):
        add(f"{pre}/{res}/create")
        add(f"{pre}/{res}/status")

    # 7) 显式指定的「最像答案」的形状
    for p in [
        "api/v1/ota/campaigns/CV6FF52FEE9EDDD86/sign",
        "api/v1/ota/firmware/sign", "api/v1/ota/signatures",
        "api/v1/firmware/sign", "api/v1/sign", "api/ota/sign",
        "ota/sign/firmware", "ota/firmware/sign", "ota/signature/create",
        "ota/campaign/create", "ota/campaign/sign", "ota/packages/sign",
        "ota/v1/sign", "ota/v2/sign", "ota/api/v1/sign",
        "internal/ota/sign", "internal/sign", "internal/api/sign",
        "admin/ota/sign", "admin/sign", "sign/firmware", "sign/ota",
        "signature/firmware", "signatures/ota", "firmware/signature",
        "vcu/firmware/sign", "vcu/sign", "ecu/vcu/sign",
        "fleet/ota/sign", "fleet/sign", "tsp/ota/sign", "tsp/sign",
        "ota/sign/p256", "ota/sign/ecdsa", "sign/ecdsa", "sign/p256",
        "cv6/sign", "cv6/ota/sign", "campaign/sign", "campaigns/sign",
        "rollback/2", "ota/rollback", "ota/campaign/rollback",
        "ota/manifest/sign", "manifest/sign", "package/sign",
        "packages/sign", "artifact/sign", "artifacts/sign",
        "key/sign", "keys/sign", "pki/sign", "ca/sign", "cert/sign",
        "signer", "signers", "signer/create", "signing", "signing/sign",
        "api/sign", "api/v1/signature", "api/v1/signatures/create",
        "graphql/ota", "graphql/sign", "gql", "api/graphql", "v1/graphql",
        "query", "mutation", "api/query", "api/mutation",
    ]:
        add(p)

    # 8) camelCase / 连字符动作名（Go/Python 框架常见命名差异）
    for pre, res, act in product(["api/v1", "ota", "internal", "v1"], S2,
                                 ["signFirmware", "sign-firmware",
                                  "sign_firmware", "createSignature",
                                  "campaigns/sign"]):
        add(f"{pre}/{res}/{act}")

    return out[:CAP]


def gen_variants():
    """路径规范化 / 路由匹配变体（探测 mux 是否子树注册、是否有重写）。"""
    base = ["healthz", "graphql", "api", "ota", "sign", "graphql/"]
    vs = []
    for b in base:
        vs += [f"/{b}/", f"/{b}//", f"/./{b}", f"/{b}/.", f"//{b}",
               f"/{b};", f"/{b};x=1", f"/{b}%00", f"/{b}%20",
               f"/{b.upper()}", f"/{b.capitalize()}", f"/{b}%2f",
               f"/%2e%2e/{b}", f"/..%2f{b}", f"/{b}/../{b}",
               f"/{b}?a=1", f"/{b}#x", f"/{b}..;/", f"/{b}%09",
               f"/{b}/index.html", f"/./././{b}"]
    vs += ["/%2e%2e%2fhealthz", "/%2e%2e/graphql", "/a/../graphql",
           "/graphql/../healthz", "/;/graphql", "/graphql/;/",
           "/*", "/%2a", "/.", "/..", "/%2f", "/%00",
           "/graphql.json", "/healthz.json", "/graphql/ ", "/ graphql"]
    return vs


def probe(path, method):
    url = f"{BASE}/{path}"
    t0 = time.time()
    try:
        if method == "POST":
            r = requests.post(url, data=b"{}",
                              headers={"Content-Type": "application/json"},
                              timeout=TIMEOUT, allow_redirects=False)
        else:
            r = requests.get(url, timeout=TIMEOUT, allow_redirects=False)
        dt = time.time() - t0
        return (path, method, r.status_code, len(r.content),
                r.headers.get("Content-Type", ""),
                r.headers.get("Location", ""), r.content[:160], dt)
    except Exception as e:
        return (path, method, "EXC", -1, type(e).__name__, "", str(e)[:120],
                time.time() - t0)


def is_hit(res):
    path, method, status, ln, ct, loc, body, dt = res
    if status == "EXC":
        return True
    if status != 404:
        return True
    if isinstance(body, bytes) and body != BASELINE:
        return True
    return False


def main():
    paths = gen_paths()
    variants = gen_variants()
    wave2 = load_wave2("04_SOLVE/web/tools/wordlist_wave2.txt")
    allp = []
    seen = set()
    for p in paths + variants + wave2:
        q = p.strip("/")
        if q and q not in seen:
            seen.add(q)
            allp.append(q)
    jobs = [(p, m) for m in ("GET", "POST") for p in allp]

    print("=" * 78)
    print(f"TSP path wave3  target={BASE}")
    print(f"unique paths={len(allp)}  jobs={len(jobs)}  workers={WORKERS} "
          f"timeout={TIMEOUT}")
    print(f"baseline 404 = {BASELINE!r} len={len(BASELINE)}")
    print(f"started {time.strftime('%Y-%m-%dT%H:%M:%S%z')}")
    print("=" * 78)

    hits = []
    excs = []
    done = 0
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = [ex.submit(probe, p, m) for p, m in jobs]
        for f in as_completed(futs):
            res = f.result()
            done += 1
            if res[2] == "EXC":
                excs.append(res)
            elif is_hit(res):
                hits.append(res)
                path, method, status, ln, ct, loc, body, dt = res
                b = body.decode("utf-8", "replace")[:160].replace("\n", "\\n")
                print(f"  HIT {method:4s} /{path:52s} {status} len={ln:5d} "
                      f"ct={ct!r} loc={loc!r} {dt:.2f}s {b!r}", flush=True)
            if done % 2000 == 0:
                el = time.time() - t0
                print(f"  ... {done}/{len(jobs)} ({el:.0f}s, {done/el:.0f} r/s, "
                      f"hits={len(hits)}, exc={len(excs)})", flush=True)

    el = time.time() - t0
    print("-" * 78)
    print(f"total={len(jobs)} elapsed={el:.1f}s hits={len(hits)} exc={len(excs)}")
    print("\n--- exceptions (dedup by type) ---")
    seenx = {}
    for e in excs:
        seenx.setdefault(e[4], []).append(e[0])
    for k, v in seenx.items():
        print(f"  {k}: {len(v)} e.g. {v[:4]}")
    print("\n--- all hits (dedup) ---")
    for h in sorted(hits, key=lambda x: (x[0], x[1])):
        path, method, status, ln, ct, loc, body, dt = h
        b = body.decode("utf-8", "replace")[:120].replace("\n", "\\n")
        print(f"  {method:4s} /{path:48s} {status} len={ln:5d} {b!r}")
    print(f"\nfinished {time.strftime('%Y-%m-%dT%H:%M:%S%z')}")

    with open("03_EVIDENCE/tsp/0302_path_wave3.json", "w", encoding="utf-8") as f:
        json.dump({"host": HOST, "n_paths": len(allp), "n_jobs": len(jobs),
                   "elapsed": el, "baseline": BASELINE.decode(),
                   "hits": [{"path": h[0], "method": h[1], "status": h[2],
                             "len": h[3], "ct": h[4], "loc": h[5],
                             "body": h[6].decode("utf-8", "replace")
                             if isinstance(h[6], bytes) else h[6],
                             "sec": round(h[7], 3)} for h in hits],
                   "exceptions": [{"path": e[0], "method": e[1],
                                   "err": e[4], "detail": str(e[6])}
                                  for e in excs]},
                  f, indent=1, ensure_ascii=False)
    print("[*] wrote 03_EVIDENCE/tsp/0302_path_wave3.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
