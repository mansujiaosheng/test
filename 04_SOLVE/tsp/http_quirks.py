#!/usr/bin/env python3
"""TSP 10.230.164.2:8080 -- HTTP layer quirk matrix (raw socket).

Covers dimensions NOT covered by earlier evidence:
  * path-encoding variants of /graphql (case, %, ;, //, ./.., NUL, unicode)
  * rare/unknown HTTP methods
  * duplicate / conflicting Content-Length, chunk extensions, TE oddities
  * HTTP/0.9, absolute-form, asterisk-form with body
Each request is sent on a fresh socket; response is captured verbatim (first 400 B).
Verdict per line: status + whether body equals one of the three known canonical bodies.
"""
import socket
import sys
import time

HOST, PORT = "10.230.164.2", 8080
CANON = {
    b'{"status":"ok"}\n': "HEALTHZ",
    b'{"data":{"vehicles":[{"label":"Guest demo vehicle","vin":"CV6000000DEMO0001"}]}}\n': "CANNED-GQL",
    b'{"error":"invalid GraphQL request"}\n': "GQL-BADJSON",
    b'{"error":"method not allowed"}\n': "GQL-BADMETHOD",
}


def send(raw, wait=2.0):
    try:
        s = socket.create_connection((HOST, PORT), timeout=4)
    except Exception as e:
        return b"", "CONNFAIL:%r" % (e,)
    s.settimeout(wait)
    try:
        s.sendall(raw)
    except Exception as e:
        s.close()
        return b"", "SENDFAIL:%r" % (e,)
    buf = b""
    t0 = time.time()
    while time.time() - t0 < wait:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        except Exception:
            break
        if not d:
            break
        buf += d
        if len(buf) > 8192:
            break
    s.close()
    return buf, ""


def classify(resp):
    if not resp:
        return "EMPTY", ""
    head, _, body = resp.partition(b"\r\n\r\n")
    first = head.split(b"\r\n")[0].decode("latin1", "replace")
    body = body.split(b"HTTP/1.1 ")[0]  # keep only first response body
    tag = CANON.get(body, "OTHER")
    return first, tag


def req(method, path, headers=None, body=b"", version="HTTP/1.1", host=True):
    hs = ""
    if host:
        hs += "Host: %s:%d\r\n" % (HOST, PORT)
    for k, v in (headers or []):
        hs += "%s: %s\r\n" % (k, v)
    head = ("%s %s %s\r\n" % (method, path, version) + hs + "\r\n").encode("latin1")
    return head + body


def run_block(title, cases):
    print("=" * 78)
    print(title)
    print("=" * 78)
    for i, (label, raw) in enumerate(cases, 1):
        resp, err = send(raw)
        st, tag = classify(resp)
        shown = resp[:200].replace(b"\r\n", b" | ") if resp else b""
        print("  [%02d] %-46s -> %-34s %-14s %s%s"
              % (i, label, st or err, tag, shown.decode("latin1", "replace")[:90], ""))
    print()


def main():
    print("# http_quirks.py  target=%s:%d  %s" % (HOST, PORT, time.strftime("%Y-%m-%dT%H:%M:%S%z")))
    print()

    # ---- A. path encoding variants (POST, canonical JSON body) ----
    body = b"{}"
    hdr = [("Content-Type", "application/json"), ("Content-Length", "2")]
    paths = [
        "/graphql", "/graphql/", "//graphql", "/./graphql", "/graphql/.", "/graphql/..",
        "/x/../graphql", "/GRAPHQL", "/Graphql", "/gRaPhQl",
        "/%67raphql", "/graphql%2f", "/graphql%2F", "/%2fgraphql", "/graphql;", "/graphql;x=1",
        "/graphql%00", "/graphql%20", "/graphql.", "/graphql..;/", "/..;/graphql",
        "/graphql?a=1", "/graphql#x", "/graphql\n", "/graphql\t",
        "/graphql%c0%af", "/graphql\\", "/%2e%2e/graphql", "/graphql/;/",
        "/graphql?query=%7Bvehicles%7Bvin%7D%7D", "/api/graphql", "/v1/graphql",
        "/graphql/v1", "/graphql?", "///graphql/", "/graphql;/../graphql",
    ]
    run_block("A. POST path-encoding variants of /graphql (body={})",
              [(p, req("POST", p, hdr, body)) for p in paths])

    # ---- B. rare / unknown methods on /graphql and / ----
    methods = ["CONNECT", "FOOBAR", "BREW", "LINK", "UNLINK", "SEARCH", "REPORT",
               "MKACTIVITY", "CHECKOUT", "MERGE", "M-SEARCH", "NOTIFY", "SUBSCRIBE",
               "PURGE", "PATCH", "PROPFIND", "ACL", "COPY", "MOVE", "TRACE", "DELETE"]
    cases = []
    for m in methods:
        if m == "CONNECT":
            cases.append(("CONNECT host-form", b"CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
                          % (HOST.encode(), PORT, HOST.encode(), PORT)))
            continue
        cases.append(("%s /graphql" % m, req(m, "/graphql", [("Content-Length", "2")], body)))
    run_block("B. rare/unknown methods on /graphql", cases)

    # ---- C. framing oddities ----
    cases = [
        ("dup CL 2 and 5",
         b"POST /graphql HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n"
         b"Content-Length: 2\r\nContent-Length: 5\r\n\r\n{}   "),
        ("dup CL 5 then 2",
         b"POST /graphql HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n"
         b"Content-Length: 5\r\nContent-Length: 2\r\n\r\n{}   "),
        ("CL 2 + TE chunked(5)",
         b"POST /graphql HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n"
         b"Content-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{\"a\":1}\r\n0\r\n\r\n"),
        ("TE: chunked ext",
         b"POST /graphql HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n"
         b"Transfer-Encoding: chunked\r\n\r\n2;a=b\r\n{}\r\n0\r\n\r\n"),
        ("TE: xchunked (obfuscated)",
         b"POST /graphql HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n"
         b"Transfer-Encoding: xchunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"),
        ("CL negative", b"POST /graphql HTTP/1.1\r\nHost: h\r\nContent-Length: -1\r\n\r\n"),
        ("CL huge", b"POST /graphql HTTP/1.1\r\nHost: h\r\nContent-Length: 999999999999\r\n\r\n"),
        ("HTTP/0.9 GET /graphql", b"GET /graphql\r\n"),
        ("HTTP/0.9 GET /healthz", b"GET /healthz\r\n"),
        ("garbage first line", b"\x16\x03\x01\x00\x10helloworld\r\n\r\n"),
        ("empty request", b"\r\n\r\n"),
        ("POST no Host 1.1", b"POST /graphql HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}"),
        ("POST 2 Hosts", b"POST /graphql HTTP/1.1\r\nHost: a\r\nHost: b\r\nContent-Length: 2\r\n\r\n{}"),
        ("big header 8k", b"POST /graphql HTTP/1.1\r\nHost: h\r\nX-Pad: " + b"A" * 8000 + b"\r\nContent-Length: 2\r\n\r\n{}"),
        ("big header 1M", b"POST /graphql HTTP/1.1\r\nHost: h\r\nX-Pad: " + b"A" * (1 << 20) + b"\r\nContent-Length: 2\r\n\r\n{}"),
    ]
    run_block("C. framing / parser oddities", cases)

    # ---- D. healthz + graphql with absolute-form & asterisk ----
    cases = [
        ("POST absolute-form", b"POST http://10.230.164.2:8080/graphql HTTP/1.1\r\nHost: 10.230.164.2\r\nContent-Length: 2\r\n\r\n{}"),
        ("POST absolute-form other host", b"POST http://tsp.internal/graphql HTTP/1.1\r\nHost: tsp.internal\r\nContent-Length: 2\r\n\r\n{}"),
        ("OPTIONS *", b"OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n"),
        ("POST * ", b"POST * HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\n{}"),
    ]
    run_block("D. request-target forms", cases)
    print("done")


if __name__ == "__main__":
    main()
