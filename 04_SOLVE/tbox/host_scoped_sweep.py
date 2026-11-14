#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""T02 hypothesis A: Go 1.22+ ServeMux "Host/path" scoped routes on
10.230.164.3:8080.

Prior brute (1576 paths) always used an IP/plain Host. Go 1.22 patterns like
"tbox/ota" only match when r.Host == "tbox", so such a route is invisible to a
default-Host sweep. This runs the merged wordlist against several Host values,
plus a header-variant pass, and reports every non-404.
"""
import concurrent.futures as cf
import socket
import sys
import time

HOST_IP = "10.230.164.3"
PORT = 8080
WL = [r"D:\qwb\04_SOLVE\web\tools\wordlist_wave2.txt"]
EXTRA = [r"D:\qwb\04_SOLVE\tbox\wordlist_tbox_extra.txt"]

HOSTS = ["tbox", "tbox.local", "10.230.164.3"]
UA = "tbox-probe"


def load_words():
    words = []
    for f in WL + EXTRA:
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    w = line.strip()
                    if not w or w.startswith("#"):
                        continue
                    if not w.startswith("/"):
                        w = "/" + w
                    words.append(w)
        except FileNotFoundError:
            pass
    seen, out = set(), []
    for w in words:
        if w not in seen:
            seen.add(w)
            out.append(w)
    return out


def http(path, host, extra_headers=""):
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\n"
           f"{extra_headers}Accept: */*\r\nConnection: close\r\n\r\n")
    s = socket.socket()
    s.settimeout(5.0)
    try:
        s.connect((HOST_IP, PORT))
        s.sendall(req.encode())
        data = b""
        while len(data) < 2048:
            c = s.recv(2048)
            if not c:
                break
            data += c
        return data.decode("latin1", "replace")
    except Exception as e:
        return f"ERR {type(e).__name__}"
    finally:
        s.close()


def main():
    words = load_words()
    print(f"wordlist merged: {len(words)} unique paths")
    t0 = time.time()
    hits = []

    def job(a):
        h, p = a
        return h, p, http(p, h)

    work = [(h, p) for h in HOSTS for p in words]
    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        for h, p, r in ex.map(job, work):
            first = r.split("\r\n")[0] if not r.startswith("ERR") else r
            if "404" not in first:
                print(f"  HIT Host:{h:15s} {p:48s} {first}")
                hits.append((h, p, first, r))
    print(f"[pass1] {len(work)} probes, {time.time()-t0:.1f}s, hits={len(hits)}")

    # header-variant pass on a focused subset
    print("\n[pass2] header variants (X-Forwarded-For / X-Real-IP / host+port) on OTA/diag paths")
    focus = [p for p in words if any(k in p.lower() for k in
                                    ("ota", "diag", "cert", "mtls", "firmware",
                                     "update", "healthz", "pki", "ca"))][:400]
    variants = [
        ("tbox", "X-Forwarded-For: 127.0.0.1\r\nX-Real-IP: 127.0.0.1\r\nX-Forwarded-Host: tbox\r\n"),
        ("10.230.164.3:8080", ""),
        ("tbox:8080", ""),
        ("tbox.local:8080", ""),
    ]
    t1 = time.time()
    hits2 = 0
    for host, hdrs in variants:
        for p in focus:
            r = http(p, host, hdrs)
            first = r.split("\r\n")[0] if not r.startswith("ERR") else r
            if "404" not in first:
                print(f"  HIT2 Host:{host:20s} {p:44s} {first}")
                hits2 += 1
    print(f"[pass2] {len(focus)*len(variants)} probes, {time.time()-t1:.1f}s, hits={hits2}")

    print(f"\nTOTAL hits (excluding /healthz): "
          f"{len([1 for _, p, _, _ in hits if p != '/healthz']) + hits2}")


if __name__ == "__main__":
    main()
