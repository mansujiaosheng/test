#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Try to find where the 40-byte diagnostic ticket is presented to the CGW/0x1220.

Every experiment: fresh TCP connection -> RA -> optional session -> probe 27 01.
The discriminator is whether `27 01` stops answering 7F 27 7E.
"""
import base64
import binascii
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from doip_send import DoIP, hexs  # noqa: E402

EVID = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "..", "03_EVIDENCE", "ticket")
TA = 0xE442
TICKET_B64 = "3I-tVCsWTfSqqZE-ZrqsQgAAAABq98emLAlQ9atV-YO71pCxdYJwcA"


def decode(t):
    return base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))


def fresh_ticket():
    """Re-issue a ticket so the TTL is fresh for this experiment run."""
    from mtls_client import MTLSClient
    c = MTLSClient(matdir=os.path.join(EVID, "b1"))
    st, hd, bb = c.request("POST", "/api/v1/diag/session")
    c.close()
    return json.loads(bb)["diagnosticTicket"]


def run(label, steps, note=""):
    """steps: list of (ta, bytes) sent in order; then 27 01 is probed."""
    c = DoIP().open()
    out = {"label": label, "note": note, "steps": []}
    try:
        out["ra"] = c.routing_activation()
        for ta, data in steps:
            uds, ack = c.uds(ta, data, wait=1.5)
            out["steps"].append({"ta": "0x%04X" % ta, "tx": hexs(data), "rx": hexs(uds), "ack": ack})
        uds, ack = c.uds(TA, bytes([0x27, 0x01]), wait=2.0)
        out["probe_2701"] = hexs(uds)
    finally:
        out["log"] = c.log
        c.close()
    return out


def main():
    T = decode(TICKET_B64)
    try:
        T = decode(fresh_ticket())
        print("[i] fresh ticket %s" % T.hex())
    except Exception as e:
        print("[!] could not refresh ticket (%s); using stored one" % e)

    exps = []
    # 1. baseline
    exps.append(("baseline", [], "no ticket anywhere"))
    # 2. ticket as the session-control data record
    exps.append(("session_with_ticket", [(TA, bytes([0x10, 0x03]) + T)], "10 03 <ticket>"))
    # 3. session then ticket as a bare write
    exps.append(("sess_then_2E_F1XX", [(TA, bytes([0x10, 0x03])), (TA, bytes([0x2E, 0xF1, 0x00]) + T)],
                  "2E F100 <ticket>"))
    # 4. ticket presented via direct SA/TA fields (SA = ticket-derived) -- sanity
    exps.append(("ticket_as_2E_FF00", [(TA, bytes([0x10, 0x03])), (TA, bytes([0x2E, 0xFF, 0x00]) + T)],
                  "2E FF00 <ticket>"))
    # 5. 27 with the ticket appended after an arbitrary subfunction
    exps.append(("27_with_ticket", [(TA, bytes([0x10, 0x03])), (TA, bytes([0x27, 0x01]) + T)],
                  "27 01 <ticket>"))
    # 6. ticket sent as the whole UDS payload
    exps.append(("raw_ticket_payload", [(TA, T)], "40 raw bytes as UDS payload"))
    # 7. nonce|exp|tag split: send nonce as 27 01 seed request payload
    exps.append(("nonce_only", [(TA, bytes([0x10, 0x03])), (TA, T[:16])], "16B nonce as payload"))

    results = []
    for label, steps, note in exps:
        try:
            r = run(label, steps, note)
        except Exception as e:
            r = {"label": label, "note": note, "error": "%s: %s" % (type(e).__name__, e)}
        results.append(r)
        print("\n== %s (%s)" % (label, note))
        print("   RA %s" % (r.get("ra")))
        for s in r.get("steps", []):
            print("   %s %-30s -> %s" % (s["ta"], s["tx"], s["rx"]))
        print("   probe 27 01 -> %s" % r.get("probe_2701"))
        time.sleep(0.3)

    out = os.path.join(EVID, "0220_ticket_presentation_matrix.json")
    json.dump(results, open(out, "w"), indent=1)
    print("\nwrote %s" % out)


if __name__ == "__main__":
    main()
