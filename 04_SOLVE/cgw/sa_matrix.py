#!/usr/bin/env python3
"""Does the DoIP routing-activation tester SA change the UDS service surface?

Rationale: a DoIP gateway maps tester logical address (SA) to a permission set.
The previous sweep only ever used SA 0x0E00. Each SA is tried on a fresh
connection: activate, verify routing with a known-good read (22F190), then probe
services that are supposed to be privilege-gated (27 01, 31 01 FF00, 34, 10 03,
2E F190).

Also sweeps the RA "OEM" 4-byte field, which ISO 13400 leaves OEM-defined and
some gateways use as an activation token.
"""
import json, os, binascii, time
from cli import Cli, pfmt

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sa_matrix.jsonl")

SAS = [0x0E00, 0x0E01, 0x0E80, 0x0F00, 0x0F01, 0x0F10, 0x0F20, 0x0F30, 0x0F40,
       0x0001, 0x0002, 0x0010, 0x0100, 0x1000, 0x1001, 0x2000, 0x07E0, 0x07E8,
       0xE000, 0xE400, 0xFF00, 0xFF01, 0xFFFF]

PROBES = [("3E00", bytes.fromhex("3E00")),
          ("22F190", bytes.fromhex("22F190")),
          ("2701", bytes.fromhex("2701")),
          ("3101FF00", bytes.fromhex("3101FF00")),
          ("3400440000000000001000", bytes.fromhex("3400440000000000001000")),
          ("1003", bytes.fromhex("1003"))]


def main():
    rows = []
    c = Cli()
    for sa in SAS:
        rec = {"sa": "0x%04X" % sa}
        try:
            m, got, ms = c.ra(sa=sa)
        except Exception as e:
            rec["ra_error"] = repr(e)
            rows.append(rec)
            print("%-8s RA error %r" % (rec["sa"], e), flush=True)
            continue
        if not m:
            rec["ra"] = None
            rows.append(rec)
            print("%-8s RA: NO RESPONSE" % rec["sa"], flush=True)
            continue
        pt, d = m
        rec["ra_resp"] = binascii.hexlify(d).decode()
        code = d[4] if len(d) > 4 else None
        rec["ra_code"] = "0x%02X" % code if code is not None else None
        if len(d) >= 2:
            rec["ra_entity_la"] = "0x%04X" % int.from_bytes(d[0:2], "big")
        print("%-8s RA %s code=%s la=%s" % (rec["sa"], rec["ra_resp"], rec.get("ra_code"),
                                            rec.get("ra_entity_la")), flush=True)
        if code != 0x10:
            rows.append(rec)
            continue
        c.sa = sa
        probes = {}
        for name, payload in PROBES:
            r = c.uds(payload, sa=sa)
            probes[name] = {"parsed": pfmt(r["uds"]),
                            "hex": binascii.hexlify(r["uds"]).decode().upper() if r["uds"] else None,
                            "ms": round(r["ms"], 1)}
            print("          %-22s %s" % (name, pfmt(r["uds"])), flush=True)
        rec["probes"] = probes
        rows.append(rec)
    c.close()
    with open(OUT, "w") as f:
        json.dump(rows, f, indent=2)
    # summary: any SA that makes a gated service behave differently from 0x0E00
    base = next((r for r in rows if r["sa"] == "0x0E00"), None)
    print("\n=== SA matrix done. %d SAs." % len(rows))
    if base and base.get("probes"):
        for r in rows:
            if not r.get("probes") or r["sa"] == "0x0E00":
                continue
            for k in base["probes"]:
                if r["probes"].get(k, {}).get("parsed") != base["probes"][k]["parsed"]:
                    print("  DIFF SA=%s %s: %s  (vs 0E00: %s)" % (
                        r["sa"], k, r["probes"][k]["parsed"], base["probes"][k]["parsed"]))


if __name__ == "__main__":
    main()
