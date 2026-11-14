#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""T-BOX 8443 mTLS diagnostics client - ready to fire the moment a client
certificate issued by "CV6 Fleet Diagnostics Root" is available.

Nothing here bypasses anything: it simply performs a correct TLS1.3 mTLS
handshake with the supplied cert/key and then exercises the HTTP surface.

Usage:
    python tbox_client.py --cert client.pem --key client.key
    python tbox_client.py --cert c.pem --key c.key --path /diag --path /status
    python tbox_client.py --cert c.pem --key c.key --methods     # method matrix

Exit codes: 0 = handshake ok, 2 = handshake failed (alert printed verbatim).
"""
import argparse
import json
import socket
import ssl
import sys

HOST = "10.230.164.3"
PORT = 8443
SNI = "tbox"
TIMEOUT = 8.0

DEFAULT_PATHS = [
    "/", "/healthz", "/readyz", "/livez", "/status", "/info", "/version",
    "/diag", "/diagnostics", "/mTLS", "/mtls", "/cert", "/certs", "/ca.crt",
    "/ota", "/campaign", "/campaigns", "/update", "/firmware", "/package",
    "/proxy", "/tsp", "/cloud", "/vehicle", "/vehicles", "/tbox",
    "/api", "/api/v1", "/v1", "/v1/diag", "/v1/status", "/config", "/env",
    "/debug", "/metrics", "/openapi.json", "/swagger.json", "/docs",
    "/vehicles/CV6FF52FEE9EDDD86", "/vehicles/CV6FF52FEE9EDDD86/ota",
    "/tbox/CV6FF52FEE9EDDD86", "/diag/ticket", "/ticket", "/token",
]


def ctx_from(cert, key, insecure=True):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.minimum_version = ssl.TLSVersion.TLSv1_3
    c.maximum_version = ssl.TLSVersion.TLSv1_3
    if insecure:
        # the server sends only its leaf, so its chain cannot be verified; we
        # are not relying on server identity here, only on client acceptance.
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
    c.load_cert_chain(certfile=cert, keyfile=key)
    return c


def describe_peer(sslsock):
    try:
        der = sslsock.getpeercert(binary_form=True)
        if not der:
            return "no peer cert"
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)
        import hashlib
        return json.dumps({
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "sha256": hashlib.sha256(der).hexdigest(),
            "not_valid_after": str(cert.not_valid_after_utc),
        }, indent=2)
    except Exception as e:
        return f"(peer decode failed: {type(e).__name__}: {e})"


def one_request(ctx, path, method="GET", body=b"", extra_headers=None):
    raw = socket.create_connection((HOST, PORT), timeout=TIMEOUT)
    try:
        s = ctx.wrap_socket(raw, server_hostname=SNI)
    except ssl.SSLError as e:
        raw.close()
        raise
    try:
        hdrs = {"Host": SNI, "Connection": "close", "User-Agent": "tbox-diag/1.0"}
        if body:
            hdrs["Content-Type"] = "application/json"
            hdrs["Content-Length"] = str(len(body))
        if extra_headers:
            hdrs.update(extra_headers)
        req = f"{method} {path} HTTP/1.1\r\n" + "".join(
            f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
        s.sendall(req.encode() + body)
        buf = b""
        while True:
            c = s.recv(8192)
            if not c:
                break
            buf += c
        return buf
    finally:
        try:
            s.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--path", action="append", default=None)
    ap.add_argument("--methods", action="store_true")
    ap.add_argument("--verify-server", action="store_true")
    a = ap.parse_args()

    ctx = ctx_from(a.cert, a.key, insecure=not a.verify_server)

    # 1) handshake
    try:
        raw = socket.create_connection((HOST, PORT), timeout=TIMEOUT)
        s = ctx.wrap_socket(raw, server_hostname=SNI)
    except ssl.SSLError as e:
        print(f"[HANDSHAKE FAILED] {e}")
        print("  alert 116 certificate_required -> client cert not presented")
        print("  alert  48 unknown_ca           -> chain does not reach "
              "'CN=CV6 Fleet Diagnostics Root'")
        print("  alert  42 bad_certificate      -> cert rejected for another reason")
        return 2
    print("[HANDSHAKE OK]")
    print("  version :", s.version())
    print("  cipher  :", s.cipher())
    print("  alpn    :", s.selected_alpn_protocol())
    print("  peer    :", describe_peer(s))
    s.close()

    # 2) method matrix
    if a.methods:
        print("\n--- method matrix on /healthz and / ---")
        for p in ("/healthz", "/"):
            for m in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "HEAD"):
                try:
                    r = one_request(ctx, p, m, b"{}" if m in ("POST", "PUT", "PATCH") else b"")
                    head = r.split(b"\r\n\r\n", 1)[0].decode("latin-1").splitlines()
                    status = head[0] if head else "(no status line)"
                    print(f"  {m:8s} {p:10s} -> {status}")
                except Exception as e:
                    print(f"  {m:8s} {p:10s} -> EXC {type(e).__name__}: {e}")

    # 3) paths
    paths = a.path or DEFAULT_PATHS
    print(f"\n--- {len(paths)} paths ---")
    for p in paths:
        try:
            r = one_request(ctx, p)
            head, _, body = r.partition(b"\r\n\r\n")
            status = head.split(b"\r\n", 1)[0].decode("latin-1") if head else "(empty)"
            if b"404 page not found" in body:
                continue
            print(f"  {p:38s} {status} len={len(body)}")
            print(f"      body: {body[:400]!r}")
        except ssl.SSLError as e:
            print(f"  {p:38s} SSL error: {e}")
            break
        except Exception as e:
            print(f"  {p:38s} EXC {type(e).__name__}: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
