#!/usr/bin/env python3
"""mtls_probe.py -- 严格判定 8443 是否强制 mTLS

判据不是"握手看起来成功"，而是：
  1) TLS 握手本身是否完成（ssl 层是否抛异常）
  2) 握手完成后，能不能真的写出 HTTP 请求并读回响应

用法：
  python mtls_probe.py 10.230.164.3 8443
  python mtls_probe.py 10.230.164.3 8443 --cert client.crt --key client.key
"""
import argparse
import socket
import ssl
import sys

SNI = "tbox"


def probe(host, port, cert=None, key=None, timeout=10):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # 不设 minimum_version，交给服务端协商，便于记录真实版本
    if cert and key:
        ctx.load_cert_chain(certfile=cert, keyfile=key)

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    out = {"connect": None, "handshake": None, "version": None,
           "cipher": None, "alpn": None, "http": None, "raw": None}

    try:
        raw.connect((host, port))
        out["connect"] = "OK"
    except Exception as e:
        out["connect"] = f"FAIL {type(e).__name__}: {e}"
        return out

    tls = None
    try:
        tls = ctx.wrap_socket(raw, server_hostname=SNI)
        out["handshake"] = "OK"
        out["version"] = tls.version()
        ci = tls.cipher()
        out["cipher"] = ci[0] if ci else None
        out["alpn"] = tls.selected_alpn_protocol()
    except ssl.SSLError as e:
        out["handshake"] = f"SSLError: {e}"
        return out
    except Exception as e:
        out["handshake"] = f"{type(e).__name__}: {e}"
        return out

    # 握手成功：真的发一个 HTTP 请求
    try:
        req = (f"GET /healthz HTTP/1.1\r\nHost: {SNI}\r\n"
               f"Connection: close\r\n\r\n").encode()
        tls.sendall(req)
        data = b""
        while len(data) < 4096:
            chunk = tls.recv(4096)
            if not chunk:
                break
            data += chunk
        out["http"] = data[:800].decode("utf-8", "replace") if data else "(empty)"
    except Exception as e:
        out["http"] = f"{type(e).__name__}: {e}"
    finally:
        try:
            tls.close()
        except Exception:
            pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("--cert")
    ap.add_argument("--key")
    a = ap.parse_args()

    label = "WITH client cert" if a.cert else "NO client cert"
    print(f"=== mTLS probe {a.host}:{a.port} [{label}] ===")
    r = probe(a.host, a.port, a.cert, a.key)
    for k in ("connect", "handshake", "version", "cipher", "alpn"):
        print(f"  {k:10s}: {r[k]}")
    print(f"  http      : {r['http']}")
    print()
    # ---- 判定 ----
    # 关键：TLS1.3 的握手机制让客户端以为自己完成了握手，服务端的证书要求
    # 是在客户端发出第一段应用数据之后才以 alert 形式回来的。所以不能只看
    # handshake 字段，必须看 http 字段里到底是什么。
    http = r["http"] if isinstance(r["http"], str) else ""
    if "CERTIFICATE_REQUIRED" in http or "certificate required" in http:
        print("VERDICT: 握手表面完成，但首个应用数据被服务端以")
        print("         TLS1.3 alert 116 (certificate_required) 拒绝")
        print("         => 强制 mTLS：门在 TLS 层，不在 HTTP 层")
        return 2
    if "UNKNOWN_CA" in http or "unknown ca" in http:
        print("VERDICT: 客户端证书链不被信任（alert 48 unknown_ca）")
        print("         => 强制 mTLS 且做真实签名验链，需 CV6 根 CA 签发的证书")
        return 4
    if r["handshake"] != "OK":
        print("VERDICT: 握手未完成 -> 客户端无法发出任何应用层请求 => 强制 mTLS")
        return 2
    if http.startswith("(empty)") or http == "":
        print("VERDICT: 握手完成但应用层无响应（连接被关）")
        return 3
    if "Error" in http or "Reset" in http:
        print("VERDICT: 应用层被异常关闭，未能取得 HTTP 响应")
        return 5
    if http.startswith("HTTP/"):
        print("VERDICT: 握手完成且拿到 HTTP 响应 -> 该路径不需要客户端证书")
        return 0
    print("VERDICT: 得到非 HTTP 数据（可能是裸协议，非 HTTP 服务）")
    return 6


if __name__ == "__main__":
    sys.exit(main())
