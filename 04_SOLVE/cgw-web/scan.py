#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Route scanner for the CGW :8080 web face.

Signal definition (confirmed by 0100_fingerprint.json):
    canonical miss = 404 with Content-Length 19 and body "404 page not found\\n"
    -> ANY deviation (other status, other length) is a registered route or at
       least a different handler.  There is no 405 oracle on this server: it
       registers method-less patterns, so every method hits the handler.

Usage:
    python scan.py --host 10.230.164.4 --file wordlist.txt --out hits.jsonl
Resumable: realpaths already present in --out are skipped.
"""
import argparse
import json
import os
import sys
import threading
import time

import requests
from requests.adapters import HTTPAdapter

CANON_STATUS = 404
CANON_LEN = 19
WORKERS = 6
TIMEOUT = 8.0

lock = threading.Lock()
counters = {"done": 0, "hit": 0, "err": 0}


def make_session():
    s = requests.Session()
    ad = HTTPAdapter(pool_connections=2, pool_maxsize=2, max_retries=0)
    s.mount("http://", ad)
    s.headers.update({"User-Agent": "cgw-web-recon/1.0", "Accept": "*/*"})
    return s


def classify(status, body, headers):
    """Return (is_hit, reason)."""
    blen = len(body)
    if status != CANON_STATUS:
        return True, "status %d (not 404)" % status
    if blen != CANON_LEN:
        return True, "404 but body %d bytes" % blen
    return False, ""


def probe(sess, base, path):
    url = base + path
    t0 = time.time()
    try:
        r = sess.get(url, allow_redirects=False, timeout=TIMEOUT)
    except Exception as e:
        return {"path": path, "error": "%s: %s" % (type(e).__name__, e)}
    dt = time.time() - t0
    body = r.content
    hit, reason = classify(r.status_code, body, r.headers)
    rec = {
        "path": path,
        "status": r.status_code,
        "len": len(body),
        "ct": r.headers.get("Content-Type", ""),
        "loc": r.headers.get("Location", ""),
        "allow": r.headers.get("Allow", ""),
        "ms": int(dt * 1000),
    }
    if hit:
        rec["reason"] = reason
        rec["body"] = body[:600].decode("utf-8", "replace")
        rec["headers"] = dict(r.headers)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="10.230.164.4")
    ap.add_argument("--port", default=8080, type=int)
    ap.add_argument("--file", default="wordlist.txt")
    ap.add_argument("--out", default="hits.jsonl")
    ap.add_argument("--all", default="", help="also dump every miss to this file")
    args = ap.parse_args()

    base = "http://%s:%d" % (args.host, args.port)

    todo = []
    seen = set()
    if os.path.exists(args.out):
        with open(args.out, encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    d = json.loads(ln)
                except Exception:
                    continue
                if d.get("path"):
                    seen.add(d["path"])
    with open(args.file, encoding="utf-8") as f:
        for ln in f:
            p = ln.strip()
            if p and p.startswith("/") and p not in seen:
                todo.append(p)

    print("[*] host=%s  file=%s  total=%d  already=%d" % (base, args.file, len(todo), len(seen)))
    if not todo:
        return

    out_f = open(args.out, "a", encoding="utf-8")
    all_f = open(args.all, "a", encoding="utf-8") if args.all else None
    q = todo[:]
    q.reverse()
    t_start = time.time()

    def worker():
        sess = make_session()
        while True:
            with lock:
                if not q:
                    return
                path = q.pop()
            rec = probe(sess, base, path)
            if "error" in rec:
                with lock:
                    counters["err"] += 1
                    counters["done"] += 1
                    out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    out_f.flush()
                    print("  [ERR] %-42s %s" % (rec["path"], rec["error"]), flush=True)
                    n = counters["done"]
                    if n % 200 == 0:
                        print("    .. %d/%d hits=%d err=%d (%.0fs)"
                              % (n, len(todo), counters["hit"], counters["err"],
                                 time.time() - t_start), flush=True)
                continue
            hit = "reason" in rec
            with lock:
                counters["done"] += 1
                if hit:
                    counters["hit"] += 1
                    out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    out_f.flush()
                    print("  [HIT] %-42s %d  %dB  %s | %s"
                          % (rec["path"], rec["status"], rec["len"],
                             rec.get("reason"), rec.get("loc") or rec.get("body", "")[:60].replace("\n", "\\n")),
                          flush=True)
                elif all_f:
                    all_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                n = counters["done"]
                if n % 200 == 0:
                    print("    .. %d/%d hits=%d err=%d (%.0fs)"
                          % (n, len(todo), counters["hit"], counters["err"],
                             time.time() - t_start), flush=True)

    ts = [threading.Thread(target=worker, daemon=True) for _ in range(WORKERS)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    out_f.close()
    if all_f:
        all_f.close()
    print("[+] done %d probes in %.1fs  hits=%d  errors=%d"
          % (counters["done"], time.time() - t_start, counters["hit"], counters["err"]))


if __name__ == "__main__":
    main()
