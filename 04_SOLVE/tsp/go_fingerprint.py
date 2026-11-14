#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TSP Go 服务特征面 + 路由归一化 + 畸形请求（只读）。

三块：
  A. 路由归一化：尾部/重复斜杠、大小写、%XX 编码、path.Clean 变体、
     是否 301 重定向（Go ServeMux 的特征）
  B. Go 运行时调试端点族：pprof / expvar / metrics / version
  C. 畸形 HTTP：超长 URL/头、负 Content-Length、非法版本/方法、
     NUL、裸 LF、CONNECT —— 观察是否泄栈/泄路由

判定：与 404 基线（len=19 '404 page not found\\n'）不同即打印全文。
"""
import socket
import sys
import time

import requests
import urllib3

urllib3.disable_warnings()
HOST = "10.230.164.2"
PORT = 8080
BASE = f"http://{HOST}:{PORT}"
BASELINE = b"404 page not found\n"
TIMEOUT = 4.0


def http_get(path, headers=None, method="GET", data=None):
    url = f"{BASE}{path}"
    try:
        r = requests.request(method, url, headers=headers or {}, data=data,
                             timeout=TIMEOUT, allow_redirects=False)
        return r.status_code, r.content, r.headers.get("Location", ""), \
            r.headers.get("Content-Type", "")
    except Exception as e:
        return "EXC", str(e).encode(), type(e).__name__, ""


def section(t):
    print("\n" + "=" * 78)
    print(t)
    print("=" * 78, flush=True)


def part_a():
    section("A. 路由归一化 / 编码变体（Go 是否 path.Clean + 301 重定向）")
    paths = [
        "/healthz", "/healthz/", "/healthz//", "//healthz", "/./healthz",
        "/healthz/.", "/healthz/..", "/healthz/../healthz",
        "/HEALTHZ", "/HealthZ", "/healThz", "/healthz%20", "/healthz%00",
        "/healthz;", "/healthz;x", "/healthz?", "/healthz?a=b",
        "/%68ealthz", "/he%61lthz", "/health%7a", "/%2fhealthz",
        "/healthz%2f", "/healthz%2F..", "/a/../healthz",
        "/graphql", "/graphql/", "/graphql//", "//graphql", "/./graphql",
        "/GRAPHQL", "/Graphql", "/%67raphql", "/graphql%00",
        "/graphql/..", "/graphql/../healthz", "/graphql/x", "/graphql/x/y",
        "/x/graphql", "/healthz/graphql",
    ]
    for p in paths:
        st, body, loc, ct = http_get(p)
        same = (st == 404 and body == BASELINE)
        tag = "base" if same else "DIFF"
        show = body.decode("utf-8", "replace")[:90].replace("\n", "\\n")
        print(f"  GET {p:28s} -> {str(st):4s} len={len(body):5d} "
              f"loc={loc!r} {tag} {show!r}", flush=True)


def part_b():
    section("B. Go 运行时 / 调试端点族")
    paths = [
        "/debug/pprof/", "/debug/pprof", "/debug/pprof/cmdline",
        "/debug/pprof/profile", "/debug/pprof/symbol", "/debug/pprof/trace",
        "/debug/pprof/heap", "/debug/pprof/goroutine", "/debug/pprof/allocs",
        "/debug/pprof/threadcreate", "/debug/pprof/block", "/debug/pprof/mutex",
        "/debug/vars", "/debug/requests", "/debug/events",
        "/metrics", "/metrics/", "/version", "/buildinfo", "/debug/buildinfo",
        "/expvar", "/vars", "/api/debug/pprof/", "/debug/pprof/index",
        "/healthz/debug/pprof/", "/graphql/debug/pprof/",
    ]
    for p in paths:
        st, body, loc, ct = http_get(p)
        same = (st == 404 and body == BASELINE)
        if same:
            print(f"  {p:32s} -> 404 baseline", flush=True)
        else:
            show = body.decode("utf-8", "replace")[:300].replace("\n", "\\n")
            print(f"  {p:32s} -> {st} len={len(body)} ct={ct!r} {show!r}",
                  flush=True)


def raw(req_bytes, label, read_until_close=True):
    """裸 socket 发原始请求，返回收到的响应（最多 800 字节）。"""
    try:
        s = socket.create_connection((HOST, PORT), timeout=TIMEOUT)
        s.settimeout(TIMEOUT)
        s.sendall(req_bytes)
        buf = b""
        try:
            while len(buf) < 800:
                c = s.recv(800 - len(buf))
                if not c:
                    break
                buf += c
                if not read_until_close and b"\r\n\r\n" in buf:
                    break
        except socket.timeout:
            pass
        s.close()
        print(f"  {label}\n     -> {buf[:400]!r}", flush=True)
        return buf
    except Exception as e:
        print(f"  {label}\n     -> EXC {type(e).__name__}: {e}", flush=True)
        return b""


def part_c():
    section("C. 畸形 HTTP（泄栈 / 泄路由 / 边界行为）")
    h = f"Host: {HOST}:{PORT}\r\n"
    raw(f"GET /healthz HTTP/1.1\r\n{h}\r\n".encode(), "baseline GET /healthz")
    raw(f"GET /healthz HTTP/1.1\r\n{h}Content-Length: -1\r\n\r\n".encode(),
        "negative Content-Length")
    raw(f"POST /graphql HTTP/1.1\r\n{h}Content-Type: application/json\r\n"
        f"Content-Length: -5\r\n\r\n".encode(), "POST negative CL")
    raw(f"GET /healthz HTTP/9.9\r\n{h}\r\n".encode(), "bad HTTP version 9.9")
    raw(f"GET /healthz HTTP/1.1\r\n{h}X-Big: {'A' * 200000}\r\n\r\n".encode(),
        "200KB header value")
    long_path = "/" + "a" * 20000
    raw(f"GET {long_path} HTTP/1.1\r\n{h}\r\n".encode(), "20KB path")
    raw(f"GET /{'a/' * 4000} HTTP/1.1\r\n{h}\r\n".encode(), "4000-deep path")
    raw(f"GET /healthz\x00 HTTP/1.1\r\n{h}\r\n".encode(), "NUL in path")
    raw(f"GET /healthz HTTP/1.1\n{h}\n".encode(), "bare LF (no CR)")
    raw(f"CONNECT {HOST}:443 HTTP/1.1\r\n{h}\r\n".encode(), "CONNECT")
    raw(f"FOO /healthz HTTP/1.1\r\n{h}\r\n".encode(), "unknown method FOO")
    raw(f"GET /healthz HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n".encode(),
        "duplicate Host")
    raw(f"GET /healthz HTTP/1.1\r\n\r\n".encode(), "HTTP/1.1 without Host")
    raw(f"GET /healthz HTTP/1.1\r\n{h}X-A: a\r\n b\r\n\r\n".encode(),
        "obs-fold header continuation")
    raw(f"POST /graphql HTTP/1.1\r\n{h}Content-Type: application/json\r\n"
        f"Content-Length: 5\r\n\r\n{{}}xx".encode(), "POST CL mismatch (extra)")
    raw(f"OPTIONS * HTTP/1.1\r\n{h}\r\n".encode(), "OPTIONS * (Go 特例)")


def main():
    print("=" * 78)
    print(f"TSP Go 服务特征面  target={BASE}  {time.strftime('%Y-%m-%dT%H:%M:%S%z')}")
    print("=" * 78)
    part_a()
    part_b()
    part_c()
    print("\n[done]", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
