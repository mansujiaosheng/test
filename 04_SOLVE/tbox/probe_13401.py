#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fingerprint 10.230.164.4:13401 and re-check :13400/8443 handshake behaviour.

13401 is an unassigned open port next to the DoIP gateway; determine whether it
is TLS (and whether it demands a client cert), HTTP, or a raw DoIP/UDS variant.
Read-only: sends EHLO-less banners, one TLS ClientHello, one HTTP request.
"""
import socket
import ssl
import sys

HOST = "10.230.164.4"


def raw(port, payload=b"", wait=2.0, label=""):
    print(f"--- raw {label} {HOST}:{port} payload={payload!r} ---")
    s = socket.socket()
    s.settimeout(wait)
    try:
        s.connect((HOST, port))
        if payload:
            s.sendall(payload)
        try:
            data = s.recv(512)
            print("  recv:", len(data), data[:200].hex())
            print("  text:", data[:200].decode("latin1", "replace").replace("\r\n", " | "))
        except socket.timeout:
            print("  recv: timeout (no banner)")
    except Exception as e:
        print("  err:", type(e).__name__, e)
    finally:
        s.close()


def tls(port, sni=None):
    print(f"--- TLS probe {HOST}:{port} sni={sni} ---")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        raw_s = socket.create_connection((HOST, port), timeout=6)
    except Exception as e:
        print("  connect err:", e)
        return
    try:
        s = ctx.wrap_socket(raw_s, server_hostname=sni)
        print("  handshake OK", s.version(), s.cipher()[0])
        cert = s.getpeercert(binary_form=True)
        print("  peer cert bytes:", len(cert) if cert else 0)
        s.sendall(b"GET / HTTP/1.1\r\nHost: tbox\r\nConnection: close\r\n\r\n")
        print("  resp:", s.recv(512)[:400])
    except Exception as e:
        print("  tls err:", type(e).__name__, e)
    finally:
        try:
            raw_s.close()
        except Exception:
            pass


if __name__ == "__main__":
    raw(13401, b"", 2.0, "silent")
    raw(13401, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", 2.0, "http")
    raw(13401, bytes.fromhex("02fdfd"), 2.0, "doip-vehicle-ident")
    tls(13401, "tbox")
    raw(13400, bytes.fromhex("02fd00010000000000000000"), 2.0, "doip-routing-act-incomplete")
