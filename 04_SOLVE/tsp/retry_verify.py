#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""低速率 + 重试的复核扫描：解决 0306 里 587 条 ConnectionError/Timeout。

0306 在 20 线程、98~188 r/s 下出现 2.6% 连接被丢，且随时间递增，
判定为限流/连接churn 而非路由信号。本脚本用 10 线程 + 每条最多 3 次重试
+ 指数退避，把「到底有没有第三条路由」钉死，并保存所有最终失败项。
"""
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

urllib3.disable_warnings()
BASE = "http://10.230.164.2:8080"
TIMEOUT = 5.0
WORKERS = 10
A = b"404 page not found\n"
PREFIXES = ["api", "api/v1", "api/v2", "v1", "v2", "admin", "internal",
            "api/internal", "debug", "sys", "_internal", "console", "mgmt",
            "ota", "fleet", "tsp", "backend", "private", "system"]


def load_words():
    words = []
    with open("04_SOLVE/web/tools/wordlist_wave2.txt", encoding="utf-8",
              errors="replace") as f:
        for ln in f:
            w = ln.strip().strip("/")
            if w and not w.startswith("#"):
                words.append(w)
    return words


def probe_retry(p, tries=3):
    last = ""
    for i in range(tries):
        try:
            r = requests.get(f"{BASE}/{p}", timeout=TIMEOUT,
                             allow_redirects=False)
            return p, r.status_code, r.content, r.headers.get("Location", ""), \
                "", i + 1
        except Exception as e:
            last = type(e).__name__
            time.sleep(0.25 * (2 ** i))
    return p, "EXC", b"", "", last, tries


def main():
    words = load_words()
    paths, seen = [], set()
    for w in words:
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
    print(f"复核扫描（低速率+重试） {time.strftime('%Y-%m-%dT%H:%M:%S%z')}")
    print(f"paths={len(paths)} workers={WORKERS} timeout={TIMEOUT}")
    print("=" * 78, flush=True)

    hits, fail = [], []
    done = 0
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = [ex.submit(probe_retry, p) for p in paths]
        for f in as_completed(futs):
            p, st, body, loc, err, ntry = f.result()
            done += 1
            if st == "EXC":
                fail.append((p, err, ntry))
            elif body != A:
                hits.append((p, st, body, loc))
                print(f"  HIT /{p:50s} {st} len={len(body)} {body[:120]!r}",
                      flush=True)
            if done % 5000 == 0:
                el = time.time() - t0
                print(f"  ... {done}/{len(paths)} ({el:.0f}s, "
                      f"{done/el:.0f} r/s, hits={len(hits)}, fail={len(fail)})",
                      flush=True)

    el = time.time() - t0
    print("-" * 78)
    print(f"total={len(paths)} elapsed={el:.1f}s hits={len(hits)} "
          f"unresolved={len(fail)}")
    if fail:
        print("unresolved (still failing after 3 tries):")
        for p, e, n in fail:
            print(f"  {p} {e} x{n}")
    print("\n--- hits ---")
    for p, st, b, loc in sorted(hits):
        print(f"  /{p:46s} {st} len={len(b)} loc={loc!r} {b[:110]!r}")

    with open("03_EVIDENCE/tsp/0309_retry_verify.json", "w",
              encoding="utf-8") as f:
        json.dump({"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                   "paths": len(paths), "elapsed": round(el, 1),
                   "hits": [{"path": p, "status": st, "len": len(b),
                             "loc": loc,
                             "body": b.decode("utf-8", "replace")[:300]}
                            for p, st, b, loc in hits],
                   "unresolved": [{"path": p, "err": e, "tries": n}
                                  for p, e, n in fail]},
                  f, indent=1, ensure_ascii=False)
    print("[*] wrote 03_EVIDENCE/tsp/0309_retry_verify.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
