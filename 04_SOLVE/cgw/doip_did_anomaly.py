#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Re-probe the DIDs that produced *no* answer in the cgw-group full 0x0000-0xFFFF
scan.  A DID that answers '7F 22 31' is plainly unknown; a DID that answers
nothing at all (or very slowly) is a different code path and worth isolating.

Full-scan anomalies (from 0425_didscan_0000_ffff_summary.json):
    0x3CE0-0x3CE2, 0x8DA0-0x8DA9, 0xA7E0-0xA7F7, 0xF1A8
plus the two known-positive DIDs for reference.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from doip_client import DoIPClient, parse_hex  # noqa: E402

HOST = "10.229.221.2"
SA, TA = 0x0E00, 0x1000
DIDS = ([0x3CE0, 0x3CE1, 0x3CE2]
        + list(range(0x8DA0, 0x8DAA))
        + list(range(0xA7E0, 0xA7F8))
        + [0xF1A8, 0xF190, 0xF1A0, 0xF1A9, 0xF1AA, 0xF1A7])
ROUNDS = 3
TIMEOUT = 4.0

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..",
                   "03_EVIDENCE", "cgw", "doip_did_anomaly_retest.jsonl")


def main() -> int:
    rows = []
    with DoIPClient(HOST, 13400, TIMEOUT, verbose=True) as c:
        ra, _ = c.routing_activation(SA)
        print("[*] routing activation: %s" % (ra.get("text") if ra else "FAILED"))
        for did in DIDS:
            rec = {"did": "0x%04X" % did, "req": "22%04X" % did, "attempts": []}
            for rnd in range(ROUNDS):
                res = c.diag(SA, TA, parse_hex("22%04X" % did), timeout=TIMEOUT,
                             wait_pending=True)
                ans = {
                    "round": rnd + 1,
                    "latency_ms": res["latency_ms"],
                    "resp": res["uds"][0]["hex"] if res["uds"] else None,
                    "from": res["uds"][0]["from"] if res["uds"] else None,
                    "nacks": res["nacks"],
                    "pending_frames": sum(1 for u in res["uds"] if u["hex"].endswith("78")),
                }
                rec["attempts"].append(ans)
                time.sleep(0.08)
            answered = [a for a in rec["attempts"] if a["resp"]]
            rec["answered"] = len(answered)
            rec["verdict"] = ("ANSWERED" if answered else "SILENT")
            rec["resp_unique"] = sorted({a["resp"] for a in answered})
            rec["lat_max"] = max(a["latency_ms"] for a in rec["attempts"])
            rows.append(rec)
            print("  %s  %-9s answered=%d/%d  resp=%s  lat_max=%.0fms"
                  % (rec["did"], rec["verdict"], rec["answered"], ROUNDS,
                     ",".join(rec["resp_unique"]) or "-", rec["lat_max"]), flush=True)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    silent = [r for r in rows if r["verdict"] == "SILENT"]
    print("\n[+] silent after %d rounds: %d  -> %s"
          % (ROUNDS, len(silent), [r["did"] for r in silent]))
    print("[+] evidence: %s" % os.path.abspath(OUT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
