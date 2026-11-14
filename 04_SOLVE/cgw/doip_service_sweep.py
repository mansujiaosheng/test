#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate which UDS services the CGW (TA=0x1000) implements.

Discriminator established earlier on this target:
    7F <sid> 11  -> service not implemented (dispatch reached, SID unknown)
    7F <sid> 31  -> request out of range (service known, parameter rejected)
    positive     -> implemented

Every SID 0x00-0xFF is tried with several payload shapes because this gateway
is picky about length (e.g. 0x22 answers 7F2211 unless the request carries
exactly one 2-byte DID).  Read-only: no write-class service is retried after a
positive answer.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from doip_client import DoIPClient, hexs  # noqa: E402

HOST = "10.229.221.2"
SA, TA = 0x0E00, 0x1000
SHAPES = ["", "00", "01", "0000", "0100", "010000"]
WRITE_CLASS = {0x2E, 0x31, 0x34, 0x35, 0x36, 0x37, 0x38, 0x2F, 0x28, 0x85, 0x11, 0x14, 0x3D, 0x2C, 0x86, 0x87, 0x83, 0x84, 0x29, 0x2A}

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..",
                   "03_EVIDENCE", "cgw", "doip_service_sweep.jsonl")


def shape_to_bytes(sid: int, shape: str):
    b = bytes([sid])
    extra = bytes.fromhex(shape) if shape else b""
    return b + extra


def main() -> int:
    rows = []
    with DoIPClient(HOST, 13400, 2.0, verbose=False) as c:
        ra, _ = c.routing_activation(SA)
        print("[*] routing activation: %s" % (ra.get("text") if ra else "FAILED"))
        implemented = []
        stale = 0
        for sid in range(0x00, 0x100):
            best = None
            for shape in SHAPES:
                uds = shape_to_bytes(sid, shape)
                # drop any late answer to a previous request before asking again
                dropped = c.drain()
                res = c.diag(SA, TA, uds, timeout=2.0, wait_pending=False)
                hexresp = res["uds"][0]["hex"] if res["uds"] else None
                # a negative response must echo the SID we just sent; if it does
                # not, the frame belongs to an earlier request -> discard it
                if (hexresp and hexresp.startswith("7F")
                        and hexresp[2:4].upper() != "%02X" % sid):
                    stale += 1
                    print("  ! stale frame while probing SID 0x%02X: got %s (dropped %d bytes)"
                          % (sid, hexresp, dropped), flush=True)
                    hexresp = None
                nrc = hexresp[4:6] if hexresp and hexresp.startswith("7F") else ""
                row = {"sid": "0x%02X" % sid, "req": hexs(uds), "resp": hexresp,
                       "dropped_bytes": dropped}
                rows.append(row)
                if hexresp and not hexresp.startswith("7F"):
                    best = ("POSITIVE", hexresp, uds)
                    break
                if hexresp and nrc not in ("11", "12", "7E", "7F", ""):
                    best = ("NRC_" + nrc, hexresp, uds)
                    break
                time.sleep(0.01)
            if best:
                implemented.append({"sid": "0x%02X" % sid,
                                    "kind": best[0], "resp": best[1],
                                    "req": hexs(best[2])})
                print("  SID 0x%02X -> %-12s %s   (req=%s)"
                      % (sid, best[0], best[1], hexs(best[2])), flush=True)
                if sid in WRITE_CLASS and best[0] == "POSITIVE":
                    print("      !! positive answer on a write-class service -- stopping this SID",
                          flush=True)
        print("\n[+] implemented / noteworthy services: %d (stale frames discarded: %d)"
              % (len(implemented), stale))

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print("[+] %d request records -> %s" % (len(rows), os.path.abspath(OUT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
