#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""T-BOX 10.230.164.3:8443 mTLS matrix + SNI scan.

Two modes:
  python mtls_matrix.py certs   # client-cert constructions x SNI
  python mtls_matrix.py sni     # no client cert, sweep SNI names

Records, per attempt: TLS version/cipher, peer cert sha256 (detect per-SNI cert
switch), and the exact OpenSSL alert name surfaced during handshake or first I/O.
"""
import hashlib
import json
import socket
import ssl
import sys

HOST = "10.230.164.3"
PORT = 8443
MAT = "mat/"
REQ = b"GET / HTTP/1.1\r\nHost: tbox\r\nUser-Agent: tbox-mtls-probe\r\nConnection: close\r\n\r\n"


def attempt(cert=None, key=None, sni="tbox", timeout=8, path=None):
    out = {"cert": cert, "sni": sni}
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    try:
        if cert:
            ctx.load_cert_chain(MAT + cert, MAT + key)
    except Exception as e:
        out["local_error"] = f"{type(e).__name__}: {e}"
        return out
    try:
        raw = socket.create_connection((HOST, PORT), timeout=timeout)
    except Exception as e:
        out["connect_error"] = f"{type(e).__name__}: {e}"
        return out
    try:
        s = ctx.wrap_socket(raw, server_hostname=sni if sni else None)
        out["handshake"] = "OK"
        out["tls"] = s.version()
        out["cipher"] = s.cipher()[0]
        der = s.getpeercert(binary_form=True)
        out["peer_sha256"] = hashlib.sha256(der).hexdigest() if der else None
        try:
            s.sendall(path or REQ)
        except Exception as e:
            out["send_error"] = f"{type(e).__name__}: {e}"
            return out
        data = b""
        try:
            while len(data) < 4096:
                c = s.recv(4096)
                if not c:
                    break
                data += c
        except Exception as e:
            out["recv_error"] = f"{type(e).__name__}: {e}"
            return out
        out["resp_len"] = len(data)
        out["resp"] = data.decode("latin1")
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    finally:
        try:
            s.close()
        except Exception:
            pass
        try:
            raw.close()
        except Exception:
            pass
    return out


CERTS = [
    # control: no cert
    (None, None),
    # real VPN cert we legitimately hold
    ("/d/qwb/01_TARGETS/tbox/vpn_client_cert.pem", "/d/qwb/01_TARGETS/tbox/vpn_client_key.pem"),
    ("v1_ed25519_selfsign.pem", "v1_ed25519_selfsign.key"),
    ("v2_rsa2048_selfsign.pem", "v2_rsa2048_selfsign.key"),
    ("v3_selfsign_caTrue.pem", "v3_selfsign_caTrue.key"),
    ("v4_leaf.pem", "v4_leaf.key"),
    ("v4_leaf_chain.pem", "v4_leaf.key"),
    ("v5_leaf.pem", "v5_leaf.key"),
    ("v5_leaf_chain.pem", "v5_leaf.key"),
    ("v6_root_as_client.pem", "v6_root_as_client.key"),
    ("v7_v1_noext.pem", "v7_v1_noext.key"),
    ("v8_expired.pem", "v8_expired.key"),
    ("v9_leaf_noeku.pem", "v9_leaf_noeku.key"),
    ("v9_leaf_noeku_chain.pem", "v9_leaf_noeku.key"),
    ("srv_leaf.pem", "v4_leaf.key"),  # mismatched on purpose -> local error expected
]

SNIS = [
    "tbox", "TBOX", "tbox.local", "tbox.cybercar", "tbox.cybercar.local",
    "tbox.internal", "tbox.ota", "diagnostics", "diag", "diagnostic",
    "ota", "ota.local", "ota-server", "fleet", "fleet.local", "fleet.local.",
    "cv6", "cv6.fleet", "tsp", "tsp.local", "cgw", "gateway", "ecu",
    "vehicle", "telematics", "tcu", "api", "public", "enroll", "ca",
    "cert", "certs", "mtls", "secure", "admin", "default", "any",
    "localhost", "127.0.0.1", "10.230.164.3", "CV6FF52FEE9EDDD86",
    "cybercar", "cybercar.local", "range", "root", "pki",
]


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "certs"
    if mode == "certs":
        for cert, key in CERTS:
            r = attempt(cert, key, sni="tbox")
            print(json.dumps(r, ensure_ascii=False))
            print("=" * 78)
    else:
        for sni in SNIS + [None]:
            r = attempt(None, None, sni=sni)
            print(json.dumps(r, ensure_ascii=False))
            print("=" * 78)


if __name__ == "__main__":
    main()
