#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""p6_e442.py - is 0xE442 / responder 0x1220 real, or an artifact?

One out of 9216 TA probes came back with response SA = 0x1220 instead of the
gateway's 0x1000. Two competing explanations:
  (1) real: 0xE442 is a functional/group address that the entity forwards, and a
      node at 0x1220 answered.
  (2) artifact: late/duplicate frames on a reused socket got attributed to the
      next request.

Test discipline: one connection per request, no socket reuse, N repetitions,
and record every frame verbatim (all 0x8001 frames, not just the first).
"""
import sys, os, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dx
from dx import hx, verdict

EV = r"D:\qwb\03_EVIDENCE\cgw"
OUT = os.path.join(EV, "p6_e442.jsonl")


def once(host, ta, uds_hex, tag):
    d = dx.Link(host, 13400, timeout=5.0).connect()   # fresh connection every time
    ra = d.ra()
    ra_ok = d.activated
    r = d.uds_raw(bytes.fromhex(uds_hex), ta=ta, timeout=5.0)
    d.close()
    return {"tag": tag, "ta": "0x%04X" % ta, "req": uds_hex, "ra_ok": ra_ok,
            "frames": [{"sa": "0x%04X" % f["sa"], "ta": "0x%04X" % f["ta"], "uds": hx(f["uds"])}
                       for f in r["frames"]],
            "n_frames": len(r["frames"]),
            "verdict": verdict(r), "ms": r["ms"]}


def main():
    host = "10.229.221.2"
    recs = []
    # A) repeat the exact anomalous cell 10x on a fresh connection each time
    for i in range(10):
        recs.append(once(host, 0xE442, "22F190", "A_rep%d" % i))
        time.sleep(0.1)
    # B) neighbourhood scan, 3x each, to see if the anomaly is positional or random
    for ta in list(range(0xE430, 0xE460)):
        recs.append(once(host, ta, "22F190", "B_nb"))
    # C) is 0x1220 itself a node?
    for ta in (0x1220, 0x1200, 0x1221, 0x1FFF):
        recs.append(once(host, ta, "22F190", "C_node"))
        recs.append(once(host, ta, "3E00", "C_node_3e"))
        recs.append(once(host, ta, "1003", "C_node_1003"))
    # D) functional broadcast style: 0xE400/0xE000 with a DID that exists
    for ta in (0xE400, 0xE000, 0xE442):
        recs.append(once(host, ta, "22F1A0", "D_fn_f1a0"))
        recs.append(once(host, ta, "22F191", "D_fn_f191"))

    with open(OUT, "a", encoding="utf-8") as f:
        for r in recs:
            r["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print("%-10s %-7s %-8s %-6s %s" % ("tag", "TA", "respSA", "nfr", "verdict"))
    for r in recs:
        sas = ",".join(sorted({fr["sa"] for fr in r["frames"]})) or "-"
        print("%-10s %-7s %-8s %-6d %s" % (r["tag"], r["ta"], sas, r["n_frames"], r["verdict"]))
    print("# wrote", OUT)


if __name__ == "__main__":
    main()
