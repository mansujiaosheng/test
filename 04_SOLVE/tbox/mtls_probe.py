#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mTLS probe for the T-BOX diagnostics endpoint (10.230.164.3:8443).

Speaks TLS1.3 (or 1.2 with --tls12) with an optional client certificate, then
sends one HTTP/1.1 request per path on its own connection and prints a status
line plus the full response body. Built so that the moment a client certificate
passes the handshake, the ticket endpoints can be swept in seconds:

    python 04_SOLVE/tbox/mtls_probe.py --host 10.230.164.3 --port 8443 \
        --cert eng.pem --key eng.key --no-verify \
        --path / --path /diag/ticket --path /api/v1/diagnostics/ticket

What it reports, and why:
  * `TLS:` line      - negotiated version / ciphersuite / ALPN / peer subject.
  * `ALERT:` line    - the TLS alert the *server* sent (116 certificate_required,
                       48 unknown_ca, 45 certificate_expired, 42 bad_certificate,
                       40 handshake_failure, 70 protocol_version ...), because the
                       alert code is the discriminator in these experiments.
  * `PATH ... STATUS` - "<code> <reason> bytes=<n>", then the raw body.

Exit codes: 0 = at least one path answered <400; 2 = handshake ok but all paths
>=400; 3 = handshake failed; 4 = connection error.
"""
import argparse
import socket
import ssl
import sys

ALERTS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    22: "record_overflow", 40: "handshake_failure", 42: "bad_certificate",
    43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired",
    46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca",
    49: "access_denied", 50: "decode_error", 51: "decrypt_error",
    70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
    86: "inappropriate_fallback", 90: "user_canceled", 109: "missing_extension",
    110: "unsupported_extension", 112: "unrecognized_name",
    116: "certificate_required", 120: "no_application_protocol",
}

DEFAULT_PATHS = [
    "/", "/healthz", "/diag/ticket", "/diagnostics/ticket", "/ticket",
    "/api/v1/diagnostics/ticket", "/api/v1/ticket", "/v1/ticket",
    "/diagnostics", "/diag", "/diag/tickets", "/api/diag/ticket",
    "/v1/diagnostics/ticket", "/fleet/diagnostics/ticket", "/session",
]


def alert_of(exc):
    """Extract the numeric TLS alert from an SSLError, if any."""
    for name in dir(ssl):
        pass
    # python puts the alert in the args text; also SSLError has .code (errno-like)
    txt = str(exc)
    for num, nm in ALERTS.items():
        if nm.replace("_", " ") in txt.lower():
            return num, nm
    for num in (116, 48, 45, 42, 40, 70, 47, 46, 110, 120, 112, 20, 10, 51):
        s = ssl.AlertDescription(num) if hasattr(ssl, "AlertDescription") else None
        if s is not None and str(s) in txt:
            return num, ALERTS[num]
    return None, None


def make_ctx(args):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if args.tls12:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    if args.no_verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.load_verify_locations(args.ca) if args.ca else ctx.load_default_certs()
    if args.cert:
        ctx.load_cert_chain(args.cert, args.key)
    if args.alpn:
        ctx.set_alpn_protocols([a.strip() for a in args.alpn.split(",") if a.strip()])
    return ctx


def handshake(ctx, host, port, sni, timeout):
    raw = socket.create_connection((host, port), timeout)
    raw.settimeout(timeout)
    tls = ctx.wrap_socket(raw, server_hostname=sni if sni else None)
    return raw, tls


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="10.230.164.3")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--sni", default="tbox", help="pass '' for no SNI")
    ap.add_argument("--cert", help="client cert PEM (may contain the whole chain)")
    ap.add_argument("--key", help="client key PEM")
    ap.add_argument("--ca", help="CA bundle to verify the server against")
    ap.add_argument("--no-verify", action="store_true", help="skip server cert verification")
    ap.add_argument("--tls12", action="store_true", help="force TLS1.2 instead of TLS1.3")
    ap.add_argument("--alpn", help="comma separated ALPN protocols")
    ap.add_argument("--path", action="append", help="request path (repeatable)")
    ap.add_argument("--paths-file", help="file with one path per line")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--body", default=None)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--quiet", action="store_true", help="status lines only, no bodies")
    args = ap.parse_args()

    paths = []
    if args.path:
        paths.extend(args.path)
    if args.paths_file:
        paths.extend(l.strip() for l in open(args.paths_file) if l.strip()
                     and not l.startswith("#"))
    if not paths:
        paths = list(DEFAULT_PATHS)

    print("## mtls_probe  host=%s:%d sni=%s cert=%s tls=%s alpn=%s verify=%s"
          % (args.host, args.port, args.sni or "(none)", args.cert or "(none)",
             "1.2" if args.tls12 else "1.3", args.alpn or "(none)",
             "off" if args.no_verify else (args.ca or "system")))

    ctx = make_ctx(args)
    best = 4
    sni_used = None
    try:
        raw, tls = handshake(ctx, args.host, args.port, args.sni, args.timeout)
        try:
            peer = tls.getpeercert()
            subj = dict(x[0] for x in peer["subject"]) if peer else {}
            sni_used = tls.version(), tls.cipher()[0] if tls.cipher() else None
            print("TLS: version=%s cipher=%s alpn=%s peer_subject=%s"
                  % (tls.version(), tls.cipher()[0] if tls.cipher() else None,
                     tls.selected_alpn_protocol(), subj.get("commonName")))
        finally:
            tls.close()
            raw.close()
    except ssl.SSLError as e:
        num, nm = alert_of(e)
        print("ALERT: %s (%s)  raw=%s" % (num, nm, e))
        try:
            raw.close()
        except Exception:
            pass
        return 3
    except OSError as e:
        print("CONNECT-ERROR: %s: %s" % (type(e).__name__, e))
        return 4

    body = args.body.encode() if args.body is not None else b""
    for path in paths:
        try:
            raw, tls = handshake(ctx, args.host, args.port, args.sni, args.timeout)
        except ssl.SSLError as e:
            num, nm = alert_of(e)
            print("PATH %-38s HANDSHAKE-FAIL alert=%s (%s)" % (path, num, nm))
            best = min(best, 2)
            continue
        except OSError as e:
            print("PATH %-38s CONNECT-ERROR %s" % (path, e))
            best = min(best, 4)
            continue
        try:
            req = ("%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n"
                   "User-Agent: mtls_probe\r\n" % (args.method, path, args.sni or args.host))
            if body:
                req += "Content-Type: application/json\r\nContent-Length: %d\r\n" % len(body)
            req += "\r\n"
            tls.sendall(req.encode() + body)
            chunks = []
            while True:
                try:
                    d = tls.recv(65536)
                except ssl.SSLError as e:
                    print("PATH %-38s READ-ALERT %s" % (path, e))
                    break
                if not d:
                    break
                chunks.append(d)
                if sum(len(c) for c in chunks) > 262144:
                    break
            resp = b"".join(chunks)
            head, _, rest = resp.partition(b"\r\n\r\n")
            status = head.split(b"\r\n")[0].decode("latin1") if head else "(no response)"
            print("PATH %-38s STATUS %s bytes=%d" % (path, status, len(rest)))
            if not args.quiet and rest:
                print(rest.decode("utf-8", "replace"))
            code = int(status.split()[1]) if status.startswith("HTTP/") and len(status.split()) > 1 else 0
            if 0 < code < 400:
                best = min(best, 0)
        finally:
            try:
                tls.close()
                raw.close()
            except Exception:
                pass
    return best


if __name__ == "__main__":
    sys.exit(main())
