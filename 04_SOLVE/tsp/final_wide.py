#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TSP 最终宽扫：14 个前缀 × wave2 全部 1169 词，body 漂移判定。

判定：响应 body != b'404 page not found\\n' 即为 hit（不改状态码也能抓 JSON-404 桩）。
低并发（20），3s 超时，只读。
"""
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

urllib3.disable_warnings()
BASE = "http://10.230.164.2:8080"
TIMEOUT = 3.0
WORKERS = 20
A = b"404 page not found\n"
PREFIXES = ["api", "api/v1", "api/v2", "v1", "v2", "admin", "internal",
            "api/internal", "debug", "sys", "_internal", "console", "mgmt",
            "ota", "fleet", "tsp", "backend", "private", "system"]


def main():
    words = []
    try:
        with open("04_SOLVE/web/tools/wordlist_wave2.txt", encoding="utf-8",
                  errors="replace") as f:
            for ln in f:
                w = ln.strip().strip("/")
                if w and not w.startswith("#"):
                    words.append(w)
    except OSError as e:
        print("cannot load wordlist", e)
        return 2

    paths, seen = [], set()
    for w in words:                       # 单段（body 漂移复核）
        if w not in seen:
            seen.add(w)
            paths.append(w)
    for pre in PREFIXES:
        for w in words:
            p = f"{pre}/{w}"
            if p not in seen:
                seen.add(p)
                paths.append(p)

    print("=" * 78)
    print(f"TSP final wide sweep  {time.strftime('%Y-%m-%dT%H:%M:%S%z')}")
    print(f"words={len(words)} prefixes={len(PREFIXES)} paths={len(paths)} "
          f"workers={WORKERS}")
    print(f"baseline={A!r}")
    print("=" * 78)

    def probe(p):
        try:
            r = requests.get(f"{BASE}/{p}", timeout=TIMEOUT,
                             allow_redirects=False)
            return p, r.status_code, r.content, r.headers.get("Location", "")
        except Exception as e:
            return p, "EXC", type(e).__name__.encode(), ""

    hits, excs = [], []
    done = 0
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = [ex.submit(probe, p) for p in paths]
        for f in as_completed(futs):
            p, st, body, loc = f.result()
            done += 1
            if st == "EXC":
                excs.append((p, body.decode()))
            elif body != A:
                hits.append((p, st, body, loc))
                print(f"  HIT /{p:50s} {str(st):4s} len={len(body):5d} "
                      f"{body[:120]!r}", flush=True)
            if done % 4000 == 0:
                el = time.time() - t0
                print(f"  ... {done}/{len(paths)} ({el:.0f}s, {done/el:.0f} r/s, "
                      f"hits={len(hits)}, exc={len(excs)})", flush=True)

    el = time.time() - t0
    print("-" * 78)
    print(f"total={len(paths)} elapsed={el:.1f}s hits={len(hits)} exc={len(excs)}")
    if excs:
        print("exceptions:", excs[:20])
    print("\n--- hit summary (dedup by status+len+head) ---")
    summ = {}
    for p, st, body, loc in hits:
        k = (st, len(body), body[:40], loc)
        summ.setdefault(k, []).append(p)
    for k, v in summ.items():
        print(f"  {k} x{len(v)} e.g. {v[:6]}")

    with open("03_EVIDENCE/tsp/0306_final_wide_sweep.json", "w",
              encoding="utf-8") as f:
        json.dump({"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                   "paths": len(paths), "hits": len(hits),
                   "elapsed": round(el, 1),
                   "detail": [{"path": p, "status": st, "len": len(b),
                               "loc": loc,
                               "body": b.decode("utf-8", "replace")[:300]}
                              for p, st, b, loc in hits],
                   "exceptions": excs[:50]}, f, indent=1, ensure_ascii=False)
    print("[*] wrote 03_EVIDENCE/tsp/0306_final_wide_sweep.json")
    print("[done]", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
