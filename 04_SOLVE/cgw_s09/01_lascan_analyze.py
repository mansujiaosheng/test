#!/usr/bin/env python3
"""Item 1: extract the 125 empty-response TAs and the 2 NRC 0x11 TAs from
the previous round's 65536-address scan. Read-only over 03_EVIDENCE/cgw/."""
import json, os, sys, collections

SRC = r"D:\qwb\03_EVIDENCE\cgw\1318_lascan_0000_ffff.jsonl"
OUT = r"D:\qwb\03_EVIDENCE\cgw_s09"
os.makedirs(OUT, exist_ok=True)

empty, n11, buckets = [], [], collections.Counter()
total = 0
for line in open(SRC, encoding="utf-8"):
    line = line.strip()
    if not line:
        continue
    d = json.loads(line)
    total += 1
    r = d.get("resp")
    if r is None or r == "":
        empty.append(d)
        buckets["EMPTY"] += 1
    else:
        buckets[r] += 1
        if r.upper().startswith("7F3E11"):
            n11.append(d)

print("total lines :", total)
print("distinct resp:", len(buckets))
for k, v in buckets.most_common(20):
    print("   %-90s %d" % (k, v))


def h(v):
    return int(v, 16)


print()
print("=== EMPTY (%d) ===" % len(empty))
for d in empty:
    print("  TA=%s resp=%r" % (d["v"], d.get("resp")))
print()
print("=== 7F3E11 (%d) ===" % len(n11))
for d in n11:
    print("  TA=%s resp=%r" % (d["v"], d.get("resp")))

# cluster the empty addresses into runs
addrs = sorted(h(d["v"]) for d in empty)
runs = []
for a in addrs:
    if runs and a == runs[-1][1] + 1:
        runs[-1][1] = a
    else:
        runs.append([a, a])
print()
print("=== empty-address runs (contiguous ranges) ===")
for s, e in runs:
    print("  0x%04X - 0x%04X  (%d)" % (s, e, e - s + 1))

json.dump({"empty": empty, "n11": n11, "runs": [[s, e] for s, e in runs]},
          open(os.path.join(OUT, "0001_lascan_empty_n11.json"), "w"), indent=1)
print()
print("wrote 0001_lascan_empty_n11.json")
