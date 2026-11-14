#!/usr/bin/env python3
"""mTLS HTTP client for the CV6 TBOX diagnostics port (10.230.164.3:8443).

Ready-to-fire: once a client cert/key signed by 'CN=CV6 Fleet Diagnostics Root'
is obtained (e.g. extracted from CGW via UDS), run:

    python tls_client.py 10.230.164.3 8443 --cert client.pem --key client.key \
        --path /healthz --path /diagnostics --path /

Read-only GET by default. Add --method POST --body '{}' for JSON POSTs.
"""
import argparse, socket, ssl, sys


def build_ctx(args):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE          # peer cert is self-signed under the challenge root
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    if args.ca:
        ctx.load_verify_locations(args.ca)
        ctx.verify_mode = ssl.CERT_REQUIRED
    if args.cert and args.key:
        ctx.load_cert_chain(args.cert, args.key)
    if args.alpn:
        ctx.set_alpn_protocols(args.alpn.split(","))
    return ctx


def one_request(args, ctx, path):
    raw = socket.create_connection((args.host, args.port), timeout=args.timeout)
    rec = {"path": path}
    try:
        s = ctx.wrap_socket(raw, server_hostname=args.sni)
        rec["tls"] = {"version": s.version(), "cipher": s.cipher()[0],
                      "alpn": s.selected_alpn_protocol()}
        body = args.body.encode() if args.body else b""
        req = (f"{args.method} {path} HTTP/1.1\r\n"
               f"Host: {args.host}\r\n"
               f"User-Agent: cv6-recon/1.0\r\n"
               f"Accept: */*\r\n"
               f"Connection: close\r\n")
        if body:
            req += f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
        req += "\r\n"
        s.sendall(req.encode() + body)
        chunks = []
        while True:
            d = s.recv(65536)
            if not d:
                break
            chunks.append(d)
            if sum(len(c) for c in chunks) > args.max_bytes:
                break
        rec["response"] = b"".join(chunks).decode("utf-8", "replace")
        rec["bytes"] = sum(len(c) for c in chunks)
        s.close()
    except ssl.SSLError as e:
        rec["ssl_error"] = f"{e.reason} (errno={e.errno})"
    except Exception as e:
        rec["error"] = f"{type(e).__name__}: {e}"
    finally:
        try:
            raw.close()
        except Exception:
            pass
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host"); ap.add_argument("port", type=int)
    ap.add_argument("--cert"); ap.add_argument("--key"); ap.add_argument("--ca")
    ap.add_argument("--sni", default="tbox")
    ap.add_argument("--path", action="append")
    ap.add_argument("--method", default="GET")
    ap.add_argument("--body")
    ap.add_argument("--alpn")
    ap.add_argument("--timeout", type=float, default=8)
    ap.add_argument("--max-bytes", type=int, default=1 << 20)
    args = ap.parse_args()
    paths = args.path or ["/"]
    ctx = build_ctx(args)
    print(f"# target={args.host}:{args.port} sni={args.sni} cert={args.cert or 'NONE'}")
    for p in paths:
        r = one_request(args, ctx, p)
        print(f"\n===== {args.method} {p} =====")
        if "ssl_error" in r:
            print(f"[SSL FAILURE] {r['ssl_error']}")
            continue
        if "error" in r:
            print(f"[CONN ERROR] {r['error']}")
            continue
        print(f"[TLS] {r['tls']}  bytes={r['bytes']}")
        print(r["response"][:4000])


if __name__ == "__main__":
    main()
