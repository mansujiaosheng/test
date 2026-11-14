#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Re-derive the DoIP TA matrix from already captured raw records.

The first sweep wrote correct wire data but tagged every row INTERESTING because
of a string-compare bug in the classifier ("0x1000".upper() -> "0X1000").
Re-classifying from the saved jsonl avoids re-hitting the target.
"""
import json
import os
import sys

BASE = os.path.join(os.path.dirname(__file__), "..", "..", "03_EVIDENCE", "cgw")
SRC = os.path.join(BASE, "doip_sweep_ta_all.jsonl")
MATRIX = os.path.join(BASE, "doip_ta_matrix.txt")
SUMMARY = os.path.join(BASE, "doip_sweep_ta_10_229_221_2.json")


def classify(row: dict) -> str:
    resp = row.get("resp") or {}
    h = (resp.get("hex") or "").upper()
    if h:
        nrc = h[4:6] if h.startswith("7F") and len(h) >= 6 else ""
        try:
            frm = int(str(resp.get("from")).replace("0X", "0x"), 16)
        except (TypeError, ValueError):
            frm = None
        if nrc == "31" and frm == 0x1000 and row["ta"] != 0x1000:
            return "BASELINE_NRC31"
        return "INTERESTING"
    if row.get("nacks"):
        return "DIAG_NACK"
    return "TIMEOUT"


def main() -> int:
    rows = []
    with open(SRC, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            r["class"] = classify(r)
            rows.append(r)

    counts: dict = {}
    for r in rows:
        counts[r["class"]] = counts.get(r["class"], 0) + 1
    hits = [r for r in rows if r["class"] != "BASELINE_NRC31"]

    # ---- console-style report
    print("[+] reclassified from %s" % SRC)
    print("[+] n_ta=%d  counts=%s" % (len(rows), counts))
    print("[+] non-baseline rows (%d):" % len(hits))
    for r in hits:
        resp = r.get("resp") or {}
        print("    TA=0x%04X %-14s nrc=%-4s %7.1fms  %s"
              % (r["ta"], r["class"], r.get("nrc") or "-",
                 r.get("latency_ms") or 0, resp.get("hex", "-")))

    # ---- matrix file
    with open(MATRIX, "w", encoding="utf-8") as f:
        f.write("# DoIP target logical address matrix  host=10.229.221.2  sa=0x0E00  probe=3E00\n")
        f.write("# classification: BASELINE_NRC31 = 7F3E31 from 0x1000 (gateway: unknown target)\n")
        f.write("#                 INTERESTING    = any other answer (target exists / handled)\n")
        f.write("# %-10s %-14s %-5s %11s %5s %-9s %s\n"
                % ("TA", "class", "nrc", "latency_ms", "att", "responder", "raw"))
        for r in rows:
            resp = r.get("resp") or {}
            f.write("  %-10s %-14s %-5s %11.1f %5d %-9s %s\n"
                    % ("0x%04X" % r["ta"], r["class"], r.get("nrc") or "-",
                       r.get("latency_ms") or 0, r.get("attempts", 1),
                       resp.get("from", "-"), resp.get("hex", "-")))
        f.write("\n# summary: %s\n" % json.dumps(counts))

    # ---- summary json (keep hits only)
    with open(SUMMARY, encoding="utf-8") as f:
        s = json.load(f)
    s["counts"] = counts
    s["hits"] = hits
    s["note"] = ("baseline NRC 0x31 = gateway does not know the target; "
                 "only rows whose answer deviates are listed as hits")
    with open(SUMMARY, "w", encoding="utf-8") as f:
        json.dump(s, f, ensure_ascii=False, indent=2)

    print("\n[+] wrote %s" % MATRIX)
    print("[+] wrote %s" % SUMMARY)
    return 0


if __name__ == "__main__":
    sys.exit(main())
