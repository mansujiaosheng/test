#!/usr/bin/env python3
# -*- coding: ascii -*-
"""Present EVERY key/cert pair reachable in the workspace to the live T-BOX mTLS
port, and record the alert each one receives.

Purpose: turn "the workspace holds no CV6-issued material" from an inventory
inference into a functional experiment -- if any local PEM happened to be issued
by the round's root, its pair would come back 200 instead of alert 48.

Read-only. Output: 03_EVIDENCE/tbox-mtls/0111_all_local_material_sweep.txt/.json
"""
import hashlib
import json
import os
import socket
import ssl
import time
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
EV = os.path.join(ROOT, "03_EVIDENCE", "tbox-mtls")
TARGET = (os.environ.get("TBOX_HOST", "10.225.139.3"), int(os.environ.get("TBOX_PORT", "8443")))

CERT_EXT = (".pem", ".crt", ".cer", ".der", ".chain")
KEY_EXT = (".key", ".pem")


def spki_hash(pub):
    der = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def load_certs():
    out = []
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", ".scratch")]
        for f in files:
            if not f.lower().endswith(CERT_EXT):
                continue
            p = os.path.join(base, f)
            try:
                blob = open(p, "rb").read()
            except OSError:
                continue
            if b"-----BEGIN CERTIFICATE-----" not in blob:
                continue
            try:
                cs = x509.load_pem_x509_certificates(blob)
            except Exception:
                try:
                    cs = [x509.load_der_x509_certificate(blob)]
                except Exception:
                    continue
            for c in cs:
                try:
                    h = spki_hash(c.public_key())
                except Exception:
                    continue
                out.append({"path": p, "cert": c, "spki": h})
    return out


def load_keys():
    out = []
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", ".scratch")]
        for f in files:
            if not f.lower().endswith((".key", ".pem")):
                continue
            p = os.path.join(base, f)
            try:
                blob = open(p, "rb").read()
            except OSError:
                continue
            if b"PRIVATE KEY" not in blob:
                continue
            try:
                k = serialization.load_pem_private_key(blob, password=None)
            except Exception:
                continue
            try:
                out.append({"path": p, "key": k, "spki": spki_hash(k.public_key())})
            except Exception:
                continue
    return out


def probe(cert_path, key_path):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.load_cert_chain(cert_path, key_path)
    except Exception as exc:  # noqa: BLE001
        return {"handshake": "LOAD_FAIL", "message": str(exc)}
    for attempt in range(3):
        try:
            raw = socket.create_connection(TARGET, timeout=10)
            ss = ctx.wrap_socket(raw, server_hostname="tbox")
            ss.sendall(b"GET / HTTP/1.1\r\nHost: tbox\r\nConnection: close\r\n\r\n")
            body = ss.recv(4096)
            ss.close()
            return {"handshake": "OK", "http": body[:300].decode("latin-1")}
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            r = {"handshake": "FAIL", "message": msg,
                 "reason": getattr(exc, "reason", None)}
            if "10054" in msg or "reset" in msg.lower():
                time.sleep(0.7)
                continue
            return r
    return r


def main():
    os.makedirs(EV, exist_ok=True)
    certs = load_certs()
    keys = load_keys()
    by_spki = {}
    for k in keys:
        by_spki.setdefault(k["spki"], k)

    pairs, unmatched = [], 0
    for c in certs:
        k = by_spki.get(c["spki"])
        if not k:
            unmatched += 1
            continue
        pairs.append((c, k))

    # de-duplicate on (cert spki, key path) keeping the shortest cert path
    uniq = {}
    for c, k in pairs:
        uniq.setdefault((c["spki"], k["path"]), (c, k))
    pairs = list(uniq.values())

    rows = []
    for c, k in pairs:
        r = probe(c["path"], k["path"])
        r["cert"] = os.path.relpath(c["path"], ROOT).replace(os.sep, "/")
        r["key"] = os.path.relpath(k["path"], ROOT).replace(os.sep, "/")
        r["subject"] = c["cert"].subject.rfc4514_string()
        r["issuer"] = c["cert"].issuer.rfc4514_string()
        rows.append(r)
        print("%-58s %-10s %s" % (r["cert"][:58], r["handshake"], r.get("reason") or
                                  r.get("message", "")[:60]))

    stamp = datetime.now(timezone.utc).isoformat()
    with open(os.path.join(EV, "0111_all_local_material_sweep.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"target": "%s:%d" % TARGET, "utc": stamp,
                   "certs_found": len(certs), "keys_found": len(keys),
                   "pairs_tested": len(pairs), "certs_without_key": unmatched,
                   "rows": rows}, fh, indent=1, ensure_ascii=False)
    lines = ["###### every key/cert pair in D:\\qwb presented to %s:%d ######" % TARGET,
             "# utc=%s  certs_found=%d keys_found=%d pairs_tested=%d certs_without_key=%d"
             % (stamp, len(certs), len(keys), len(pairs), unmatched), ""]
    for r in rows:
        lines.append("%s" % r["cert"])
        lines.append("    subj=%s" % r.get("subject"))
        lines.append("    iss =%s" % r.get("issuer"))
        lines.append("    key =%s" % r["key"])
        lines.append("    -> handshake=%s reason=%s %s"
                     % (r["handshake"], r.get("reason"), (r.get("message") or r.get("http") or "")[:200]))
        lines.append("")
    with open(os.path.join(EV, "0111_all_local_material_sweep.txt"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    ok = [r for r in rows if r["handshake"] == "OK"]
    print("\npairs=%d  accepted=%d  certs_without_key=%d" % (len(pairs), len(ok), unmatched))


if __name__ == "__main__":
    main()
