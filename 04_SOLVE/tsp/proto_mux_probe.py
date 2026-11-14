#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""8080 是否在同一端口复用其它协议（cmux / TLS / gRPC / SSE / WebSocket）。

动机：若服务用 soheilhy/cmux 或类似方案在 8080 上按首字节分流，
      纯 HTTP 探测永远看不到 TLS/gRPC 那一侧，会误判成「只有 3 条路由」。

判据：
  * TLS ClientHello 得到 ServerHello(0x16 0x03) => 该端口同时说 TLS
  * 得到 HTTP 400 文本                        => 只说 HTTP/1.x
  * h2c prior-knowledge preface 得到 400      => 不说 HTTP/2
"""
import socket
import ssl
import sys
import time

HOST, PORT = "10.230.164.2", 8080
TIMEOUT = 5.0


def raw(payload, label, read=600):
    try:
        s = socket.create_connection((HOST, PORT), timeout=TIMEOUT)
        s.settimeout(TIMEOUT)
        s.sendall(payload)
        buf = b""
        try:
            while len(buf) < read:
                c = s.recv(read - len(buf))
                if not c:
                    break
                buf += c
        except socket.timeout:
            pass
        s.close()
        print(f"  {label:38s} -> {len(buf):4d}B {buf[:120]!r}", flush=True)
        return buf
    except Exception as e:
        print(f"  {label:38s} -> EXC {type(e).__name__}: {e}", flush=True)
        return b""


def main():
    print("=" * 78)
    print(f"8080 协议复用探测  {time.strftime('%Y-%m-%dT%H:%M:%S%z')}")
    print("=" * 78)

    # 1) 裸 TLS ClientHello（用 ssl 模块生成真实的）
    print("\n-- 1. TLS ClientHello（cmux 会在这里回 ServerHello）--")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        s = socket.create_connection((HOST, PORT), timeout=TIMEOUT)
        s.settimeout(TIMEOUT)
        try:
            ss = ctx.wrap_socket(s, server_hostname="tsp.local")
            print(f"  TLS handshake SUCCEEDED: {ss.version()} "
                  f"cipher={ss.cipher()}")
            print(f"  peer cert: {ss.getpeercert()}")
            ss.close()
        except ssl.SSLError as e:
            print(f"  TLS handshake failed: {e}")
        finally:
            try:
                s.close()
            except OSError:
                pass
    except Exception as e:
        print(f"  TLS connect EXC {type(e).__name__}: {e}")

    # 2) 手工 ClientHello 记录层（确认不是误判）
    print("\n-- 2. 手工构造的 TLS 记录 --")
    raw(b"\x16\x03\x01\x00\x2e\x01\x00\x00\x2a\x03\x03" + b"\x00" * 42,
        "hand-rolled ClientHello")

    # 3) HTTP/2 prior knowledge
    print("\n-- 3. HTTP/2 / h2c / gRPC 侧信道 --")
    raw(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "h2 prior-knowledge preface")
    raw(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00",
        "h2 preface + SETTINGS frame")
    raw(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00", "raw HTTP/2 frame only")

    # 4) WebSocket / SSE / 升级
    print("\n-- 4. 升级类协议 --")
    raw(b"GET /graphql HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
        b"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
        b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", "WS upgrade /graphql")
    raw(b"GET /healthz HTTP/1.1\r\nHost: x\r\nAccept: text/event-stream\r\n\r\n",
        "SSE /healthz")
    raw(b"GET /internal/audit HTTP/1.1\r\nHost: x\r\nUpgrade: h2c\r\n"
        b"Connection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n",
        "h2c upgrade /internal/audit")

    # 5) SSH / 其它首字节探测（误配的端口转发）
    print("\n-- 5. 其它协议首字节探测 --")
    raw(b"SSH-2.0-Probe\r\n", "SSH banner probe")
    raw(b"\x00\x00\x00\x00", "gRPC length-prefixed empty")

    print("\n[done]", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
