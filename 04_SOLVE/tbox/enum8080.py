#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""T-BOX 10.230.164.3:8080 route enumeration.

Phase 1 (this file, mode=get): GET every path in wl_big.txt over 8 keep-alive
connections, 3s timeout, 20ms pacing per worker (~<=400 rps ceiling, real ~250).
Any HTTP status != 404 is a hit; Go 1.22 ServeMux answers 405 for a registered
path hit with a wrong method, so a GET-only sweep still surfaces POST-only routes.

Usage: python enum8080.py get <wordlist> <out.jsonl>
"""
import http.client
import json
import queue
import sys
import threading
import time

HOST = "10.230.164.3"
PORT = 8080
TIMEOUT = 3.0
NTHREADS = 8
PACE = 0.020

lock = threading.Lock()
hits = []
stats = {"n": 0, "err": 0, "status": {}}
t0 = time.time()


def open_conn():
    c = http.client.HTTPConnection(HOST, PORT, timeout=TIMEOUT)
    c.connect()
    return c


def worker(q, out, method):
    conn = None
    while True:
        try:
            path = q.get_nowait()
        except queue.Empty:
            break
        status = None
        length = 0
        snippet = ""
        err = None
        for _ in range(2):
            try:
                if conn is None:
                    conn = open_conn()
                conn.request(method, path,
                             headers={"Host": "tbox",
                                      "User-Agent": "tbox-enum/2",
                                      "Connection": "keep-alive",
                                      "Accept": "*/*"})
                r = conn.getresponse()
                body = r.read()
                status = r.status
                length = len(body)
                if status != 404:
                    snippet = body[:300].decode("utf-8", "replace")
                err = None
                break
            except Exception as e:
                err = "%s: %s" % (type(e).__name__, e)
                try:
                    if conn:
                        conn.close()
                except Exception:
                    pass
                conn = None
        with lock:
            stats["n"] += 1
            if err:
                stats["err"] += 1
                stats["status"]["ERR"] = stats["status"].get("ERR", 0) + 1
            else:
                stats["status"][status] = stats["status"].get(status, 0) + 1
            if status is not None and status != 404:
                rec = {"path": path, "method": method, "status": status,
                       "len": length, "body": snippet}
                hits.append(rec)
                out.write(json.dumps(rec, ensure_ascii=False) + "\n")
                out.flush()
        if PACE:
            time.sleep(PACE)
    try:
        if conn:
            conn.close()
    except Exception:
        pass


def main():
    mode = sys.argv[1]
    wl = sys.argv[2]
    outf = sys.argv[3]
    method = {"get": "GET"}.get(mode, mode.upper())
    paths = [l.strip() for l in open(wl, encoding="utf-8", errors="replace")
             if l.strip() and not l.startswith("#")]
    q = queue.Queue()
    for p in paths:
        q.put(p)
    with open(outf, "w", encoding="utf-8", newline="\n") as out:
        ths = [threading.Thread(target=worker, args=(q, out, method), daemon=True)
               for _ in range(NTHREADS)]
        for t in ths:
            t.start()
        for t in ths:
            t.join()
    dt = time.time() - t0
    print(json.dumps({"mode": method, "paths": len(paths), "done": stats["n"],
                      "errors": stats["err"], "elapsed_s": round(dt, 1),
                      "rate": round(stats["n"] / dt, 1),
                      "status_hist": stats["status"], "hits": len(hits)},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
