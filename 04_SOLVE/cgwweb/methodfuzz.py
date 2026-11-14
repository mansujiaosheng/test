#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multi-method path fuzzer for the CGW 8080 control plane.

Why multi-method: Go 1.22 net/http ServeMux answers 405 (Method Not Allowed)
for a registered path when the method does not match.  A GET-only sweep
therefore cannot see POST-only routes.  Conversely a 400/500 means the route
exists and rejected our body.

Oracle:
  404 page not found -> no route
  405                -> ROUTE EXISTS, wrong method
  400/415/422        -> ROUTE EXISTS, body rejected
  200/201/204        -> hit
  anything else      -> interesting, print it

Also tries trailing-slash variants and ?-query probes, because a bridge API
that takes its payload from the query string will 400 without it.
"""
from __future__ import annotations

import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import urllib3
import requests
from requests.adapters import HTTPAdapter

urllib3.disable_warnings()

ROOT = Path(__file__).resolve().parents[2]
EVID = ROOT / "03_EVIDENCE" / "cgwweb"
TOOLS = ROOT / "04_SOLVE" / "web" / "tools"

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
TIMEOUT = 6


def load_words() -> list[str]:
    words = set()
    wl = TOOLS / "wordlist_wave2.txt"
    if wl.exists():
        for line in wl.read_text(encoding="utf-8", errors="replace").splitlines():
            w = line.strip()
            if w and not w.startswith("#"):
                words.add(w)
    # extra seeds specific to a CAN-FD / DoIP bridge control plane
    extra = """
frame frames can canfd can_fd bus busframe send tx inject transmit write raw
canbridge bridge doip gateway cgw ecu ecus node nodes target targets
vm vmm hil bench testbed rig
v1/api api/v1 v1/can v1/frame api/can api/frame api/send api/tx api/inject
can/send can/frame can/tx can/raw frame/send frame/tx frame/inject
send/frame send/can inject/frame tx/frame
health healthz readyz livez ping version build info status state
admin internal debug config setting settings
uds diag diagnostic diagnostics service services session
trace traces log logs event events
ws websocket socket stream events/stream sse
auth login token apikey api_key key
vehicle vehicles vin info
route routes routing table tables map mapping
bus/0 bus/1 channel channels ch0 ch1
lin flexray ethernet someip
security secoc crypto key derive kdf hsm
ota flash update
"""
    for line in extra.split():
        words.add(line.strip())
    words.discard("")
    return sorted(words)


def build_urls(base: str, words) -> list[str]:
    out = []
    for w in words:
        w = w.strip("/")
        if not w:
            continue
        out.append(f"{base}/{w}")
    return out


def session() -> requests.Session:
    s = requests.Session()
    ad = HTTPAdapter(pool_connections=64, pool_maxsize=64, max_retries=0)
    s.mount("http://", ad)
    s.mount("https://", ad)
    s.headers.update({"User-Agent": "cgw-probe/1.0", "Accept": "*/*"})
    return s


class Counter:
    def __init__(self):
        self.lock = threading.Lock()
        self.n = 0

    def inc(self):
        with self.lock:
            self.n += 1
            return self.n


def probe(sess, method, url, body=None, ctype=None):
    hdrs = {}
    if ctype:
        hdrs["Content-Type"] = ctype
    t0 = time.time()
    try:
        r = sess.request(method, url, data=body, headers=hdrs, timeout=TIMEOUT,
                         allow_redirects=False, verify=False)
        return {"method": method, "url": url, "status": r.status_code,
                "len": len(r.content), "ms": round((time.time() - t0) * 1000, 1),
                "body": r.text[:300], "headers": dict(r.headers)}
    except Exception as e:
        return {"method": method, "url": url, "status": -1,
                "error": f"{type(e).__name__}: {e}", "ms": round((time.time() - t0) * 1000, 1)}


def is_boring(r) -> bool:
    if r.get("status") == 404:
        b = (r.get("body") or "").strip()
        # Go's ServeMux default
        if b.startswith("404 page not found") or b == "":
            return True
    return False


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://10.229.221.2:8080"
    words = load_words()
    urls = build_urls(base, words)
    print(f"[*] base={base} words={len(words)} urls={len(urls)}")

    sess = session()
    results = []
    hits = []
    cnt = Counter()
    lock = threading.Lock()

    bodies = [
        ("application/json", json.dumps({"id": 0x7E0, "data": "0000000000000000", "canid": 0x7E0,
                                         "data_hex": "00", "bus": 0, "frame": "..."})),
        ("application/x-www-form-urlencoded", "id=0x7E0&data=0000&canid=0x7E0&bus=0"),
        ("text/plain", "0x7E0 00 11 22"),
    ]

    tasks = []
    for m in METHODS:
        for u in urls:
            tasks.append((m, u, None, None))
    # a small POST body matrix on the most likely bridge paths only
    likely = [u for u in urls if any(k in u for k in
              ("frame", "can", "send", "tx", "inject", "bridge", "doip", "bus", "raw"))]
    for u in likely:
        for ctype, body in bodies:
            tasks.append(("POST", u, body, ctype))
    print(f"[*] total requests={len(tasks)}")

    def work(t):
        m, u, body, ctype = t
        r = probe(sess, m, u, body, ctype)
        n = cnt.inc()
        if n % 500 == 0:
            print(f"  ... {n}/{len(tasks)}")
        with lock:
            results.append(r)
            if not is_boring(r) and r.get("status") != -1:
                hits.append(r)
                print(f"  [{r['status']:>3}] {m:6} {u.replace(base, '')} "
                      f"len={r['len']} {r['body'][:90]!r}")

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=48) as ex:
        list(ex.map(work, tasks))
    el = round(time.time() - t0, 1)

    # dedupe hits by (status, path)
    hist = {}
    for r in results:
        k = r.get("status")
        hist[k] = hist.get(k, 0) + 1
    out = {"base": base, "elapsed_s": el, "probed": len(results),
           "status_histogram": hist, "words": len(words),
           "hits": hits}
    p = EVID / "4100_methodfuzz_221_8080.json"
    p.write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"\n=== histogram {hist}")
    print(f"=== {len(hits)} non-404 hits -> {p}")


if __name__ == "__main__":
    main()
