#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""10.230.164.3:8080 — method / path-normalisation / Host-vhost matrix.

Rationale: the 29k-path GET sweep found exactly one route (/healthz), and the
server answers 404 (never 405) for unknown paths under every method tried so
far, which means either a plain http.HandleFunc mux (no method patterns) or a
router that hides method-restricted routes behind 405. This matrix separates
those two cases and checks the three remaining ways to reach a route that a
naive path sweep cannot see: method switch, path normalisation, Host routing.

Raw sockets: http.client refuses some of these request lines/methods.
"""
import json
import socket
import time

HOST, PORT = "10.230.164.3", 8080
TIMEOUT = 3.0
out = []

KEY_PATHS = ["/healthz", "/", "/graphql", "/api/v1/health", "/ota", "/diagnostics"]
METHODS = ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"]

NORM = [
    "/healthz", "/healthz/", "//healthz", "///healthz", "/./healthz",
    "/healthz/.", "/healthz/..", "/healthz/../healthz", "/../healthz",
    "/%68ealthz", "/he%61lthz", "/healthz%20", "/healthz%09", "/healthz;x",
    "/healthz;a=b", "/HEALTHZ", "/Healthz", "/healthz%00", "/healthz\x00",
    "/healthz%2f", "/%2Fhealthz", "/healthz\\", "/healthz\\..\\healthz",
    "/." + "/healthz", "/healthz?", "/healthz#x", "/./", "/..",
]

VHOSTS = ["tbox", "tbox.local", "tbox.cybercar.local", "tbox.cybercar",
          "cybercar", "cybercar.local", "cv6", "cv6.local", "fleet",
          "fleet.local", "ota", "ota.local", "diagnostics", "localhost",
          "127.0.0.1", "10.230.164.3", "", "tbox:8080", "tbox:8443"]
VHOST_PATHS = ["/healthz", "/", "/graphql", "/api", "/ota/manifest", "/v1/vehicles"]


def raw(req, label):
    s = socket.socket()
    s.settimeout(TIMEOUT)
    try:
        s.connect((HOST, PORT))
        s.sendall(req)
        buf = b""
        while True:
            try:
                d = s.recv(4096)
            except socket.timeout:
                break
            if not d:
                break
            buf += d
            if len(buf) > 8192:
                break
    except Exception as e:
        out.append({"label": label, "error": "%s: %s" % (type(e).__name__, e)})
        s.close()
        return
    s.close()
    head, _, body = buf.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1", "replace").split("\r\n")
    status = lines[0] if lines else ""
    hdrs = {}
    for l in lines[1:]:
        if ":" in l:
            k, v = l.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    rec = {"label": label, "status": status, "len": len(body),
           "body": body[:200].decode("utf-8", "replace")}
    if "allow" in hdrs:
        rec["allow"] = hdrs["allow"]
    if "content-type" in hdrs:
        rec["ctype"] = hdrs["content-type"]
    out.append(rec)
    time.sleep(0.03)


def main():
    print("### A. method x path")
    for p in KEY_PATHS:
        for m in METHODS:
            body = b"" if m in ("GET", "HEAD", "OPTIONS", "TRACE", "CONNECT") else b"{}"
            req = ("%s %s HTTP/1.1\r\nHost: tbox\r\nUser-Agent: mx\r\n"
                   "Content-Type: application/json\r\nContent-Length: %d\r\n"
                   "Connection: close\r\n\r\n" % (m, p, len(body))).encode() + body
            raw(req, "A %s %s" % (m, p))

    print("### B. path normalisation (GET)")
    for p in NORM:
        req = ("GET %s HTTP/1.1\r\nHost: tbox\r\nUser-Agent: mx\r\n"
               "Connection: close\r\n\r\n" % p).encode()
        raw(req, "B GET %r" % p)

    print("### C. Host header virtual hosts")
    for h in VHOSTS:
        for p in VHOST_PATHS:
            req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: mx\r\n"
                   "Connection: close\r\n\r\n" % (p, h)).encode()
            raw(req, "C Host=%r %s" % (h, p))

    print("### D. HTTP/1.0 and absolute-form")
    raw(b"GET / HTTP/1.0\r\n\r\n", "D HTTP/1.0 no host /")
    raw(b"GET /healthz HTTP/1.0\r\n\r\n", "D HTTP/1.0 no host /healthz")
    raw(b"GET http://tbox/healthz HTTP/1.1\r\nHost: tbox\r\nConnection: close\r\n\r\n",
        "D absolute-form http://tbox/healthz")
    raw(b"GET http://10.230.164.3:8080/healthz HTTP/1.1\r\nHost: 10.230.164.3:8080\r\n"
        b"Connection: close\r\n\r\n", "D absolute-form ip:port /healthz")
    raw(b"GET /healthz HTTP/1.1\r\nHost: tbox\r\nHost: evil\r\nConnection: close\r\n\r\n",
        "D duplicate Host")

    with open(r"D:\qwb\03_EVIDENCE\tbox\0106_http_matrix.json", "w",
              encoding="utf-8", newline="\n") as f:
        for r in out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # console: everything that is not a plain 404
    print("\n### non-404 results")
    n_404 = 0
    for r in out:
        if r.get("status", "").startswith("HTTP/1.1 404") or "404" in r.get("status", ""):
            n_404 += 1
            continue
        print(json.dumps(r, ensure_ascii=False))
    print("\ntotal=%d 404=%d non404=%d" % (len(out), n_404, len(out) - n_404))


if __name__ == "__main__":
    main()
