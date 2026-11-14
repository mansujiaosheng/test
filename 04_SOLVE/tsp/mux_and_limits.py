#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Experimental suite: Go ServeMux fingerprint, path normalization, URI/header limits,
   plaintext-on-8443, TLS-on-8080, determinism hashes.  Writes raw to stdout."""
import socket, ssl, hashlib, time, sys, json

T2 = ("10.230.164.2", 8080)
OUT = []
def p(s):
    print(s, flush=True); OUT.append(s)

def raw(host, port, payload, timeout=6.0, read_all=True):
    t0 = time.time()
    s = socket.socket(); s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(payload)
        buf = b""
        while True:
            try:
                d = s.recv(65536)
            except socket.timeout:
                break
            if not d: break
            buf += d
            if not read_all and b"\r\n\r\n" in buf: break
        return buf, time.time()-t0, None
    except Exception as e:
        return buf if 'buf' in dir() else b"", time.time()-t0, repr(e)
    finally:
        s.close()

def summarize(r):
    if not r: return "EMPTY"
    head, _, body = r.partition(b"\r\n\r\n")
    line = head.split(b"\r\n")[0].decode("latin1")
    loc = ""
    for h in head.split(b"\r\n")[1:]:
        if h.lower().startswith(b"location:"):
            loc = " LOC=" + h.split(b":",1)[1].strip().decode("latin1")
    return f"{line}{loc} bodylen={len(body)} body={body[:120]!r}"

H, P = T2
def req(rline, headers=None, body=b"", version="HTTP/1.1"):
    hdrs = headers if headers is not None else [("Host", f"{H}:{P}"), ("Content-Type","application/json")]
    if body and not any(k.lower()=="content-length" for k,_ in hdrs):
        hdrs = hdrs + [("Content-Length", str(len(body)))]
    raw_req = (rline + " " + version + "\r\n" + "".join(f"{k}: {v}\r\n" for k,v in hdrs) + "\r\n").encode() + body
    return raw_req

p("="*78)
p("0402-A  Go http.ServeMux fingerprint: path cleaning / 301 redirects")
p("="*78)
paths = ["/graphql", "/graphql/", "//graphql", "/./graphql", "/graphql/../graphql",
         "/graphql/../ota", "/ota/../graphql", "/%2e/graphql", "/graphql%2f",
         "/graphql;", "/graphql.", "/GRAPHQL", "/GraphQL", "/graphql%00",
         "/graphql?a=1", "/graphql/?a=1", "/./healthz", "//healthz", "/healthz/../graphql",
         "/index.html", "/graphql/..", "/..%2fgraphql", "/%2E%2E/graphql",
         "/graphql/./", "/graphql//", "/healthz//", "/hEaLtHz"]
for pa in paths:
    r, dt, err = raw(H, P, req(f"POST {pa}", body=b"{}"))
    p(f"  POST {pa:<26} {summarize(r) if not err else 'ERR '+err}  ({dt:.2f}s)")

p("")
p("="*78)
p("0402-B  absolute-form request URI + CONNECT/OPTIONS *")
p("="*78)
for rl in ["POST http://127.0.0.1:80/graphql", "POST http://tbox/graphql",
           "POST http://10.230.164.3:8443/graphql", "POST https://10.230.164.2/graphql",
           "GET http://10.230.164.2:8080/healthz", "OPTIONS *", "GET *"]:
    r, dt, err = raw(H, P, req(rl, body=b"{}" if rl.startswith("POST") else b""))
    p(f"  {rl:<42} {summarize(r) if not err else 'ERR '+err}")

p("")
p("="*78)
p("0402-C  request-line / header / body limits (net/http defaults fingerprint)")
p("="*78)
for n in (1000, 8000, 8100, 9000):
    rl = "/" + "a"*n
    r, dt, err = raw(H, P, req(f"GET {rl}", headers=[("Host", f"{H}:{P}")]))
    p(f"  URI len={n+1:<6} {summarize(r) if not err else 'ERR '+err}")
for n in (10000, 100000, 900000, 1100000):
    r, dt, err = raw(H, P, req("GET /healthz", headers=[("Host", f"{H}:{P}"), ("X-Pad", "b"*n)]), timeout=8.0)
    p(f"  header pad len={n:<8} {summarize(r) if not err else 'ERR '+err}")
for n in (131071, 131072, 131073):
    body = json.dumps({"pad": "p"*n}).encode()
    r, dt, err = raw(H, P, req("POST /graphql", body=body), timeout=8.0)
    p(f"  body total={len(body):<8} {summarize(r) if not err else 'ERR '+err}")

p("")
p("="*78)
p("0402-D  determinism: 20 identical POST /graphql, sha256 of body")
p("="*78)
hashes = {}
for i in range(20):
    r, dt, err = raw(H, P, req("POST /graphql", body=b'{"query":"{vehicles{vin}}"}'))
    body = r.partition(b"\r\n\r\n")[2]
    h = hashlib.sha256(body).hexdigest()
    hashes.setdefault(h, 0); hashes[h] += 1
    time.sleep(0.15)
for h, c in hashes.items():
    p(f"  sha256={h}  count={c}")
p(f"  distinct_hashes={len(hashes)}")

p("")
p("="*78)
p("0402-E  plaintext HTTP on 8443 / TLS on 8080 / TLS on 8443 to .2")
p("="*78)
r, dt, err = raw("10.230.164.3", 8443, b"GET / HTTP/1.1\r\nHost: tbox\r\n\r\n", timeout=5)
p(f"  plaintext->8443  {summarize(r) if not err else 'ERR '+err}")
r, dt, err = raw("10.230.164.3", 8443, b"\x16\x03\x01\x00\x00", timeout=5)
p(f"  tls1.2-ish hello->8443 {summarize(r) if not err else 'ERR '+err}")
for tgt in [("10.230.164.2",8080), ("10.230.164.4",8080), ("10.230.164.3",8080), ("10.230.164.2",8443)]:
    try:
        ctx = ssl._create_unverified_context()
        s = socket.socket(); s.settimeout(5)
        s.connect(tgt)
        ss = ctx.wrap_socket(s, server_hostname="tbox")
        p(f"  TLS handshake {tgt[0]}:{tgt[1]} OK ver={ss.version()} cipher={ss.cipher()} cert_subject={ss.getpeercert(True)[:0]}")
        ss.close()
    except Exception as e:
        p(f"  TLS handshake {tgt[0]}:{tgt[1]} FAIL {e!r}")

p("")
p("="*78)
p("0402-F  HTTP/1.0 semantics + Connection headers + pipelining depth")
p("="*78)
r, dt, err = raw(H, P, b"POST /graphql HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
p(f"  HTTP/1.0 no-Host POST    {summarize(r) if not err else 'ERR '+err}")
r, dt, err = raw(H, P, req("POST /graphql", version="HTTP/1.0", body=b"{}"))
p(f"  HTTP/1.0 with-Host POST  {summarize(r) if not err else 'ERR '+err}")
r, dt, err = raw(H, P, req("POST /graphql", headers=[("Host",f"{H}:{P}"),("Connection","close")], body=b"{}"))
p(f"  Connection: close        {summarize(r) if not err else 'ERR '+err}")
r, dt, err = raw(H, P, req("POST /graphql", headers=[("Host","a"),("Host","b")], body=b"{}"))
p(f"  duplicate Host           {summarize(r) if not err else 'ERR '+err}")
r, dt, err = raw(H, P, req("POST /graphql", headers=[], body=b"{}"))
p(f"  no Host at all           {summarize(r) if not err else 'ERR '+err}")
r, dt, err = raw(H, P, b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\nGET /healthz HTTP/1.1\r\nHost: x\r\n\r\nGET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
p(f"  3x pipelined healthz     {summarize(r) if not err else 'ERR '+err}  bodies={r.count(b'{\"status\":\"ok\"}')}")

open("03_EVIDENCE/tsp/0402_mux_limits_raw.txt","w",encoding="utf-8").write("\n".join(OUT)+"\n")
