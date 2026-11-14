#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Diagnostic-ticket helpers: fetch, decode, describe.

Ticket wire format (verified 2026-11-14, see FINDINGS.md):
    40 bytes = nonce(16) || expiry_u64_be(8) || tag(16)
    transported as base64url without padding (54 or 64 chars depending on
    how many leading zero bits the nonce/tag happen to have -- do NOT assume
    a fixed length, always re-pad to a multiple of 4).
"""
import base64
import json
import os
import time

HERE = os.path.dirname(os.path.abspath(__file__))
EVID = os.path.abspath(os.path.join(HERE, "..", "..", "03_EVIDENCE", "ticket"))
BUNDLE_DIR = os.path.join(EVID, "b1")


def b64d(s):
    s = s.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def issue(matdir=BUNDLE_DIR, timeout=10.0):
    """POST /api/v1/diag/session over mTLS, return the parsed JSON."""
    import sys
    sys.path.insert(0, HERE)
    from mtls_client import MTLSClient
    c = MTLSClient(matdir=matdir, timeout=timeout)
    st, hd, bb = c.request("POST", "/api/v1/diag/session")
    c.close()
    if st != 200:
        raise RuntimeError("issue failed: %s %s" % (st, bb[:200]))
    return json.loads(bb.decode())


def describe(ticket_b64):
    raw = b64d(ticket_b64)
    exp = int.from_bytes(raw[16:24], "big")
    now = int(time.time())
    return {
        "ticket": ticket_b64,
        "bytes": len(raw),
        "hex": raw.hex(),
        "nonce_hex": raw[0:16].hex(),
        "exp_epoch": exp,
        "exp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(exp)),
        "now_epoch": now,
        "remaining_s": exp - now,
        "tag_hex": raw[24:40].hex(),
        "raw": raw,
    }


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--issue", action="store_true", help="fetch a fresh ticket first")
    ap.add_argument("--ticket", default=None)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    t = a.ticket
    if a.issue or not t:
        r = issue()
        t = r["diagnosticTicket"]
        print("endpoint response:", json.dumps(r))
    d = describe(t)
    if a.json:
        d.pop("raw")
        print(json.dumps(d, indent=1))
    else:
        for k in ("ticket", "bytes", "nonce_hex", "exp_epoch", "exp_utc",
                  "remaining_s", "tag_hex", "hex"):
            print("%-12s %s" % (k, d[k]))
