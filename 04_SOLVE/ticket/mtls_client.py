#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Minimal reusable mTLS HTTP/1.1 client for the CV6 T-BOX diagnostics endpoint
(https://10.225.139.3:8443, TLS 1.3-only, RequireAndVerifyClientCert).

Why not curl: the Windows curl build here speaks schannel, which refuses the
client cert / TLS1.3 setup. Python's ssl module (OpenSSL 3.0.15) works.

Usage as a library:
    from mtls_client import MTLSClient
    c = MTLSClient()
    st, hdrs, body = c.request("GET", "/healthz")

Usage as CLI:
    python mtls_client.py --dir <bundle dir> GET /healthz
    python mtls_client.py GET /ticket --body '{"vin":"CV6..."}'
    python mtls_client.py --raw GET /healthz          # also dump hex of raw bytes

Material layout expected (defaults to 03_EVIDENCE/ticket/b1):
    <dir>/diagnostics/ca.pem  client.pem  client-key.pem
"""

import argparse
import json
import os
import socket
import ssl
import sys
import time

DEFAULT_HOST = "10.225.139.3"
DEFAULT_PORT = 8443
DEFAULT_MAT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "..", "03_EVIDENCE", "ticket", "b1")


class MTLSClient:
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT, matdir=DEFAULT_MAT,
                 server_hostname="tbox", timeout=10.0, insecure_ca=False,
                 alpn=None, debug=False):
        self.host = host
        self.port = port
        self.matdir = os.path.abspath(matdir)
        self.server_hostname = server_hostname
        self.timeout = timeout
        self.alpn = alpn
        self.debug = debug

        d = os.path.join(self.matdir, "diagnostics")
        self.ca = os.path.join(d, "ca.pem")
        self.cert = os.path.join(d, "client.pem")
        self.key = os.path.join(d, "client-key.pem")
        for p in (self.ca, self.cert, self.key):
            if not os.path.exists(p):
                raise FileNotFoundError(p)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # TLS 1.3 only (server rejects 1.2 with alert protocol_version 70)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        # TLS1.3 suites are not governed by set_ciphers(); they are always on
        # in OpenSSL 3. Trying to force one via set_ciphersets is unnecessary.
        try:
            ctx.set_ciphersuites("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
                                 "TLS_AES_128_GCM_SHA256")
        except Exception:
            pass
        if insecure_ca:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx.load_verify_locations(self.ca)
            ctx.check_hostname = False   # cert CN is "tbox", we connect by IP
            ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_cert_chain(self.cert, self.key)
        if self.alpn:
            ctx.set_alpn_protocols(self.alpn.split(","))
        self.ctx = ctx
        self.conn = None
        self.sock = None
        self.tls_info = {}

    # ---------- transport ----------
    def connect(self):
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        raw.settimeout(self.timeout)
        self.sock = self.ctx.wrap_socket(raw, server_hostname=self.server_hostname)
        self.conn = self.sock
        ci = self.sock.cipher()
        self.tls_info = {
            "version": self.sock.version(),
            "cipher": ci[0] if ci else None,
            "bits": ci[2] if ci else None,
            "alpn": self.sock.selected_alpn_protocol(),
            "peercert_subject": self._name(self.sock.getpeercert()),
            "peercert_der_sha256": None,
        }
        der = self.sock.getpeercert(binary_form=True)
        if der:
            import hashlib
            self.tls_info["peercert_der_sha256"] = hashlib.sha256(der).hexdigest()
        if self.debug:
            sys.stderr.write("[tls] %s\n" % json.dumps(self.tls_info))
        return self

    @staticmethod
    def _name(cert):
        if not cert:
            return None
        out = []
        for rdn in cert.get("subject", ()):  # type: ignore
            for k, v in rdn:
                out.append("%s=%s" % (k, v))
        return ",".join(out)

    def close(self):
        for s in (self.conn, self.sock):
            try:
                if s:
                    s.close()
            except Exception:
                pass
        self.conn = self.sock = None

    # ---------- HTTP/1.1 ----------
    def request(self, method="GET", path="/", body=None, headers=None,
                host_header=None, close=True, raw_result=False):
        """Returns (status:int, headers:dict, body:bytes).
        If raw_result, returns (status, headers, body, raw_bytes)."""
        if self.conn is None:
            self.connect()
        if isinstance(body, (dict, list)):
            body = json.dumps(body, separators=(",", ":")).encode()
        if isinstance(body, str):
            body = body.encode()

        h = {
            "Host": host_header or ("%s:%d" % (self.host, self.port)),
            "User-Agent": "cv6-diag/1.0",
            "Accept": "*/*",
            "Connection": "close" if close else "keep-alive",
        }
        if body is not None:
            h["Content-Length"] = str(len(body))
            h["Content-Type"] = "application/json"
        if headers:
            for k, v in headers.items():
                # case-insensitive override of defaults
                for dk in list(h):
                    if dk.lower() == k.lower():
                        del h[dk]
                h[k] = v

        req = ("%s %s HTTP/1.1\r\n" % (method, path)).encode()
        for k, v in h.items():
            req += ("%s: %s\r\n" % (k, v)).encode()
        req += b"\r\n"
        if body is not None:
            req += body

        if self.debug:
            sys.stderr.write("[req] %s %s (%d B body)\n" % (method, path, len(body or b"")))
        self.conn.sendall(req)

        status, rhdrs, rbody, raw = self._read_response()
        if close:
            self.close()
        if raw_result:
            return status, rhdrs, rbody, raw
        return status, rhdrs, rbody

    def _read_response(self):
        buf = b""
        # read headers
        while b"\r\n\r\n" not in buf:
            chunk = self.conn.recv(65536)
            if not chunk:
                break
            buf += chunk
        if b"\r\n\r\n" not in buf:
            return 0, {}, buf, buf
        head, rest = buf.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        try:
            status = int(lines[0].split(b" ")[1])
        except Exception:
            status = 0
        hdrs = {}
        for ln in lines[1:]:
            if b":" in ln:
                k, v = ln.split(b":", 1)
                hdrs[k.decode("latin1").strip()] = v.decode("latin1").strip()

        body = rest
        te = ""
        cl = None
        for k, v in hdrs.items():
            if k.lower() == "transfer-encoding":
                te = v.lower()
            if k.lower() == "content-length":
                try:
                    cl = int(v)
                except Exception:
                    cl = None

        if "chunked" in te:
            body, tail = self._dechunk(body)
        elif cl is not None:
            while len(body) < cl:
                chunk = self.conn.recv(65536)
                if not chunk:
                    break
                body += chunk
            body = body[:cl]
        else:
            while True:
                chunk = self.conn.recv(65536)
                if not chunk:
                    break
                body += chunk
        return status, hdrs, body, head + b"\r\n\r\n" + body

    def _dechunk(self, buf):
        out = b""
        dead = 0
        while True:
            while b"\r\n" not in buf:
                chunk = self.conn.recv(65536)
                if not chunk:
                    return out, b""
                buf += chunk
            line, buf = buf.split(b"\r\n", 1)
            try:
                n = int(line.split(b";")[0], 16)
            except Exception:
                return out, buf
            if n == 0:
                # consume trailers until blank line
                while b"\r\n" not in buf:
                    chunk = self.conn.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                if buf.startswith(b"\r\n"):
                    buf = buf[2:]
                return out, buf
            while len(buf) < n + 2:
                chunk = self.conn.recv(65536)
                if not chunk:
                    out += buf[:n]
                    return out, b""
                buf += chunk
            out += buf[:n]
            buf = buf[n + 2:]
            dead += 1
            if dead > 100000:
                return out, buf


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("method")
    ap.add_argument("path")
    ap.add_argument("--dir", dest="matdir", default=DEFAULT_MAT)
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--sni", default="tbox")
    ap.add_argument("--body", default=None)
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--raw", action="store_true")
    ap.add_argument("--debug", action="store_true")
    a = ap.parse_args()

    hd = {}
    for h in a.header:
        if ":" in h:
            k, v = h.split(":", 1)
            hd[k.strip()] = v.strip()

    c = MTLSClient(host=a.host, port=a.port, matdir=a.matdir,
                   server_hostname=a.sni, debug=a.debug)
    t0 = time.time()
    st, hh, bb, raw = c.request(a.method.upper(), a.path, body=a.body,
                                headers=hd, raw_result=True)
    dt = time.time() - t0
    print("%s %s -> %d  (%d B, %.3fs)" % (a.method.upper(), a.path, st, len(bb), dt))
    print("TLS:", json.dumps(c.tls_info))
    for k, v in hh.items():
        print("  %s: %s" % (k, v))
    print("--- body ---")
    try:
        print(bb.decode("utf-8"))
    except Exception:
        print(bb[:512].hex())
    if a.raw:
        print("--- raw hex ---")
        print(raw[:2048].hex())


if __name__ == "__main__":
    main()
