#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Complete the *pre-activation* service sweep (SIDs 0xA6-0xFF).

Background: the first attempt walked SID 0x00-0xFF with three payload shapes on
a socket that was never routing-activated.  While it was at SID 0xA5 the lab VPN
tunnel dropped, and every following request recorded "no response".  Those
records are an outage artifact, not target behaviour
(see 03_EVIDENCE/cgw/doip_outage_vpn_down.txt).

Guard rails added here so an outage can never again be mistaken for a finding:
  * preflight connectivity check -- abort before touching the target state
  * abort after N consecutive failures  -- a real gateway answers in ~60 ms
  * any "no response" is re-probed once on a fresh connection before it counts

Baseline expectation (established for SIDs 0x00-0xA4): 7F <sid> 22.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from doip_client import DoIPClient, hexs  # noqa: E402

HOST = "10.229.221.2"
PORT = 13400
SA, TA = 0x0E00, 0x1000
SHAPES = ["", "00", "0100"]
FIRST_SID = 0xA6
MAX_CONSECUTIVE_FAIL = 5

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..",
                   "03_EVIDENCE", "cgw", "doip_service_sweep_no_activation_resume.jsonl")


def preflight() -> bool:
    """Refuse to start unless the target answers a real request end to end."""
    try:
        c = DoIPClient(HOST, PORT, 3.0, verbose=False).connect(attempts=2, connect_timeout=6.0)
    except OSError as e:
        print("[!] preflight: cannot connect %s:%d -- %s" % (HOST, PORT, e))
        return False
    try:
        fr = c.vehicle_identification()
        if not fr:
            print("[!] preflight: connected but no vehicle identification answer")
            return False
        ra, _ = c.routing_activation(SA)
        if not ra or ra["code"] != "0x10":
            print("[!] preflight: routing activation failed: %r" % (ra,))
            return False
        r = c.diag(SA, TA, b"\x22\xf1\x90", timeout=3.0)
        if not r["uds"] or not r["uds"][0]["hex"].startswith("62F190"):
            print("[!] preflight: 22F190 did not return the VIN: %r" % (r["uds"],))
            return False
        print("[+] preflight OK (ident + RA 0x10 + VIN readable)")
        return True
    finally:
        c.close()


def main() -> int:
    if not preflight():
        print("[ABORT] target unreachable or unhealthy; nothing recorded. "
              "This is the exact failure mode that produced the bogus 0xA6-0xFF block last time.")
        return 2

    rows, fails, streak = [], 0, 0
    c = DoIPClient(HOST, PORT, 2.0, verbose=False).connect()
    try:
        for sid in range(FIRST_SID, 0x100):
            for sh in SHAPES:
                uds = bytes([sid]) + (bytes.fromhex(sh) if sh else b"")
                c.drain()
                r = c.diag(SA, TA, uds, timeout=2.0, wait_pending=False)
                resp = r["uds"][0]["hex"] if r["uds"] else None
                # a negative response must echo the SID we just sent
                if resp and resp.startswith("7F") and resp[2:4].upper() != "%02X" % sid:
                    resp = None
                if resp is None:
                    # re-probe once on a fresh connection before believing it
                    c.close()
                    time.sleep(0.2)
                    c = DoIPClient(HOST, PORT, 2.0, verbose=False).connect()
                    r = c.diag(SA, TA, uds, timeout=3.0, wait_pending=False)
                    resp = r["uds"][0]["hex"] if r["uds"] else None
                rows.append({"sid": "0x%02X" % sid, "req": hexs(uds), "resp": resp})
                if resp is None:
                    fails += 1
                    streak += 1
                    print("  SID 0x%02X shape=%-6r -> NO RESPONSE (streak %d)"
                          % (sid, sh, streak), flush=True)
                    if streak >= MAX_CONSECUTIVE_FAIL:
                        print("[ABORT] %d consecutive failures -- the network/target went away, "
                              "not a target behaviour. Partial results kept." % streak)
                        return 3
                else:
                    streak = 0
                    if not resp.startswith("7F") or resp[4:6] != "22":
                        print("  !! SID 0x%02X shape=%-6r -> %s  (deviates from 7F<sid>22)"
                              % (sid, sh, resp), flush=True)
                time.sleep(0.005)
    finally:
        c.close()

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    dev = [r for r in rows if r["resp"] is None
           or (r["resp"].startswith("7F") and r["resp"][4:6] != "22")]
    print("\n[+] %d records, %d no-response, %d deviations from 7F<sid>22"
          % (len(rows), fails, len(dev)))
    for d in dev:
        print("    ", d)
    print("[+] evidence: %s" % os.path.abspath(OUT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
