#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Probe the local lab Go mTLS server (127.0.0.1:9443) with the same client
certificate set used against 10.230.164.3:8443.

Purpose: show the alert triple (116 / 48 / 43) is stock Go behaviour, and that a
leaf signed by the root in ClientCAs gets HTTP 200.
Run `lab/lab_server.exe` first.
"""
import socket
import ssl

LAB = ("127.0.0.1", 9443)

CASES = [
    ("no-cert", None, None),
    ("ed25519 self-signed", "lab/c_self.pem", "lab/c_self.key"),
    ("expired self-signed (2020)", "lab/c_expired.pem", "lab/c_expired.key"),
    ("fakeCA-sameDN leaf only", "mat/v4_leaf.pem", "mat/v4_leaf.key"),
    ("fakeCA-sameDN leaf + chain", "mat/v4_leaf_chain.pem", "mat/v4_leaf.key"),
]


def main():
    for name, cert, key in CASES:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        if cert:
            ctx.load_cert_chain(cert, key)
        try:
            s = ctx.wrap_socket(socket.create_connection(LAB, timeout=6),
                                server_hostname="localhost")
            try:
                s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                print(f"{name:30s} -> HANDSHAKE OK resp={s.recv(120)!r}")
            except Exception as e:
                print(f"{name:30s} -> {type(e).__name__}: {e}")
            s.close()
        except Exception as e:
            print(f"{name:30s} -> {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
