#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fingerprint + identity comparison of the two CGW :8080 web faces.

Raw-socket based so we can send non-standard request lines that
requests/curl would normalise away (OPTIONS *, absolute-form URI,
HTTP/1.0, double slashes, encoded dots, ...).

Usage: python fp.py [outfile]
"""
import socket
import sys
import json
import hashlib

HOSTS = ["10.229.221.2", "10.230.164.4"]
PORT = 8080
TIMEOUT = 8.0

# (label, raw request bytes)   request line + headers, CRLF, blank line
REQS = [
    # --- baseline
    ("GET /healthz",        b"GET /healthz HTTP/1.1\r\nHost: H\r\nConnection: close\r\n\r\n"),
    ("GET /",               b"GET / HTTP/1.1\r\nHost: H\r\nConnection: close\r\n\r\n"),
    # --- asterisk-form (Go 1.21 http.Server answers 200/CL:0 via globalOptionsHandler)
    ("OPTIONS *",           b"OPTIONS * HTTP/1.1\r\nHost: H\r\nConnection: close\r\n\r\n"),
    # --- absolute-form URI (proxy style)
    ("GET absform /healthz", b"GET http://H/healthz HTTP/1.1\r\nHost: H\r\nConnection: close\r\n\r\n"),
    ("GET absform /nope",    b"GET http://H/nope HTTP/1.1\r\nHost: H\r\nConnection: close\r\n\r\n"),
    # --- HTTP/1.0
    ("GET /healthz HTTP/1.0", b"GET /healthz HTTP/1.0\r\n\r\n"),
    # --- path normalisation / traversal-ish
    ("GET //healthz",       b"GET //healthz HTTP/1.1\r\nHost: H\r\nConnection: close\r\n\r\n"),
    ("GET /./healthz",      b"GET /./healthz HTTP/1.1\r\nHost: H\r\nConnection: close\r\n\r\n"),
    ("GET /a/../healthz",   b"GET /a/../healthz HTTP/1.1\r\nHost: H\r\nConnection: close\r\n\r\n"),
    ("GET /healthz/",       b"GET /healthz/ HTTP/1.1\r\nHost: H\r\nConnection: close\r\n\r\n"),
    ("GET /healthz/x",      b"GET /healthz/x HTTP/1.1\r\nHost: H\r\nConnection: close\r\n\r\n"),
    ("GET /healthz?x=1",    b"GET /healthz?x=1 HTTP/1.1\r\nHost: H\r\nConnection: close\r\n\r\n"),
    ("GET /HealthZ",        b"GET /HealthZ HTTP/1.1\r\nHost: H\r\nConnection: close\r\n\r\n"),
    ("GET /%68ealthz",      b"GET /%68ealthz HTTP/1.1\r\nHost: H\r\nConnection: close\r\n\r\n"),
    ("GET /healthz%2f",     b"GET /healthz%2f HTTP/1.1\r\nHost: H\r\nConnection: close\r\n\r\n"),
    ("GET /healthz%00",     b"GET /healthz%00 HTTP/1.1\r\nHost: H\r\nConnection: close\r\n\r\n"),
    ("GET /nope%00",        b"GET /nope%00 HTTP/1.1\r\nHost: H\r\nConnection: close\r\n\r\n"),
    # --- method quirks
    ("FOO /healthz",        b"FOO /healthz HTTP/1.1\r\nHost: H\r\nConnection: close\r\n\r\n"),
    ("TRACE /healthz",      b"TRACE /healthz HTTP/1.1\r\nHost: H\r\nConnection: close\r\n\r\n"),
    ("POST /healthz",       b"POST /healthz HTTP/1.1\r\nHost: H\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"),
    ("DELETE /healthz",     b"DELETE /healthz HTTP/1.1\r\nHost: H\r\nConnection: close\r\n\r\n"),
    ("OPTIONS /healthz",    b"OPTIONS /healthz HTTP/1.1\r\nHost: H\r\nConnection: close\r\n\r\n"),
    # --- host / protocol quirks
    ("GET /healthz noHost", b"GET /healthz HTTP/1.1\r\nConnection: close\r\n\r\n"),
    ("GET /nope noHost",    b"GET /nope HTTP/1.1\r\nConnection: close\r\n\r\n"),
    ("GET /healthz HTTP/2.0", b"GET /healthz HTTP/2.0\r\nHost: H\r\n\r\n"),
    ("garbage line",        b"GARBAGE\r\n\r\n"),
    # --- keep-alive count: two requests on one conn
    ("pipeline x2",         b"GET /healthz HTTP/1.1\r\nHost: H\r\n\r\nGET /nope HTTP/1.1\r\nHost: H\r\nConnection: close\r\n\r\n"),
]


def send_raw(host, payload):
    """Return (raw_response_bytes, error_or_None)."""
    s = None
    try:
        s = socket.create_connection((host, PORT), timeout=TIMEOUT)
        s.settimeout(TIMEOUT)
        s.sendall(payload)
        chunks = []
        while True:
            try:
                b = s.recv(65536)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
            if sum(len(c) for c in chunks) > 200000:
                break
        return b"".join(chunks), None
    except Exception as e:
        return b"", "%s: %s" % (type(e).__name__, e)
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


def summarise(raw):
    """Compact, diffable summary of a raw HTTP response."""
    if not raw:
        return {"empty": True}
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = lines[0].decode("latin-1") if lines else ""
    hdrs = []
    for ln in lines[1:]:
        if not ln.strip():
            continue
        k, _, v = ln.decode("latin-1").partition(":")
        k = k.strip()
        if k.lower() == "date":       # noise for diffing
            v = "<date>"
        hdrs.append([k, v.strip()])
    hdrs.sort()
    return {
        "status": status,
        "headers": hdrs,
        "body_len": len(body),
        "body_sha1_12": hashlib.sha1(body).hexdigest()[:12],
        "body_repr": body[:300].decode("latin-1"),
    }


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "fp.json"
    results = {}
    for host in HOSTS:
        results[host] = {}
        for label, payload in REQS:
            p = payload.replace(b"Host: H", ("Host: %s" % host).encode())
            p = p.replace(b"http://H/", ("http://%s/" % host).encode())
            raw, err = send_raw(host, p)
            summ = summarise(raw)
            summ["error"] = err
            summ["raw_len"] = len(raw)
            results[host][label] = summ

    # --- diff between the two hosts
    diffs = []
    for label, _ in REQS:
        a = results[HOSTS[0]][label]
        b = results[HOSTS[1]][label]
        if json.dumps(a, sort_keys=True) != json.dumps(b, sort_keys=True):
            diffs.append(label)

    print("=== per-case summary ===")
    for label, _ in REQS:
        a = results[HOSTS[0]][label]
        b = results[HOSTS[1]][label]
        same = "SAME" if label not in diffs else "DIFF"
        print("[%s] %-26s %-28s len=%-6s sha=%s err=%s"
              % (same, label, a.get("status", "")[:28], a.get("body_len"),
                 a.get("body_sha1_12"), (a.get("error") or "")[:40]))
    print()
    print("=== bodies (host %s) ===" % HOSTS[0])
    for label, _ in REQS:
        a = results[HOSTS[0]][label]
        if a.get("body_len"):
            print("  %-26s %r" % (label, a.get("body_repr")[:160]))
    print()
    print("IDENTICAL BEHAVIOUR:" if not diffs else "DIFFS: %s" % diffs)

    with open(out, "w", encoding="utf-8") as f:
        json.dump({"results": results, "diffs": diffs}, f, indent=2)
    print("written -> %s" % out)


if __name__ == "__main__":
    main()
