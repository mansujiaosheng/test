#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""判别 /internal/audit 是不是「恒定 404 桩」。

核心判据：
  1) 若它像 /graphql 那样解析 body，则畸形 JSON / 超限 body 会给出
     与正常 body 不同的响应（400 等）。
  2) 若一切输入（方法/体/头/长度）都得到同一 23 字节响应，
     则它是一个不读 body 的固定桩（诱饵）。
同时打印原始响应头，检查是否有自定义头。
"""
import socket
import sys
import time

import requests
import urllib3

urllib3.disable_warnings()
HOST, PORT = "10.230.164.2", 8080
BASE = f"http://{HOST}:{PORT}"
TIMEOUT = 4.0
CANON = b'{"error":"not found"}\n'


def post(label, data, ctype="application/json", method="POST", timeout=TIMEOUT):
    try:
        r = requests.request(method, BASE + "/internal/audit", data=data,
                             headers={"Content-Type": ctype},
                             timeout=timeout, allow_redirects=False)
        same = (r.content == CANON)
        print(f"  {label:46s} -> {r.status_code} len={len(r.content):7d} "
              f"{'CANON' if same else 'DIFF '} {r.content[:90]!r}", flush=True)
        return r.content == CANON
    except Exception as e:
        print(f"  {label:46s} -> EXC {type(e).__name__}", flush=True)
        return False


def raw(req, label):
    try:
        s = socket.create_connection((HOST, PORT), timeout=TIMEOUT)
        s.settimeout(TIMEOUT)
        s.sendall(req)
        buf = b""
        try:
            while len(buf) < 1200:
                c = s.recv(1200 - len(buf))
                if not c:
                    break
                buf += c
        except socket.timeout:
            pass
        s.close()
        print(f"\n  === {label} ===\n  {buf[:700]!r}", flush=True)
        return buf
    except Exception as e:
        print(f"  {label} EXC {e}", flush=True)
        return b""


def main():
    print("=" * 78)
    print(f"/internal/audit 桩判定  {time.strftime('%Y-%m-%dT%H:%M:%S%z')}")
    print("=" * 78)

    print("\n-- 1. body 敏感性（会解析 body 的 handler 应在这里分化）--")
    ok = True
    ok &= post("valid {}", b"{}")
    ok &= post("malformed json '{'", b"{")
    ok &= post("empty body", b"")
    ok &= post("json array []", b"[]")
    ok &= post("json string", b'"x"')
    ok &= post("131072 bytes (graphql limit+0)", b'{"p":"' + b"a" * 131063 + b'"}')
    ok &= post("131073 bytes (graphql limit+1)", b'{"p":"' + b"a" * 131064 + b'"}')
    ok &= post("1MB body", b'{"p":"' + b"a" * 1048560 + b'"}')
    ok &= post("text/plain body", b"hello", ctype="text/plain")
    ok &= post("xml body", b"<a/>", ctype="application/xml")

    print("\n-- 2. 方法 × 有无 body --")
    for m in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"]:
        post(f"{m} no body", None, method=m)
    print(f"\n  => 全部等于 23 字节固定响应? {ok}")

    print("\n-- 3. 原始响应头（对比 Go 默认 404）--")
    h = f"Host: {HOST}:{PORT}\r\n"
    raw(f"GET /internal/audit HTTP/1.1\r\n{h}\r\n".encode(), "GET /internal/audit")
    raw(f"GET /nope-xyz HTTP/1.1\r\n{h}\r\n".encode(), "GET /nope-xyz (Go 404)")
    raw(f"HEAD /internal/audit HTTP/1.1\r\n{h}\r\n".encode(), "HEAD /internal/audit")
    raw(f"GET /internal/audit HTTP/1.1\r\n{h}Accept: text/html\r\n\r\n".encode(),
        "GET /internal/audit Accept:text/html")

    print("\n-- 4. 极值输入（看是否 panic / 换错误）--")
    post("huge header value", b"{}",
         ) if False else None
    try:
        r = requests.post(BASE + "/internal/audit", data=b"{}",
                          headers={"Content-Type": "application/json",
                                   "X-Audit-Id": "A" * 20000},
                          timeout=TIMEOUT)
        print(f"  20KB header X-Audit-Id       -> {r.status_code} "
              f"len={len(r.content)} {r.content[:80]!r}")
    except Exception as e:
        print("  20KB header EXC", type(e).__name__)
    for q in ["?id=%00", "?id=" + "A" * 4000, "?id=" + VIN if False else "?id=x"]:
        try:
            r = requests.get(BASE + "/internal/audit" + q, timeout=TIMEOUT)
            print(f"  GET {q[:40]:40s} -> {r.status_code} len={len(r.content)} "
                  f"{r.content[:70]!r}")
        except Exception as e:
            print(f"  GET {q[:40]} EXC {type(e).__name__}")

    print("\n[done]", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    return 0


VIN = "CV6FF52FEE9EDDD86"

if __name__ == "__main__":
    sys.exit(main())
