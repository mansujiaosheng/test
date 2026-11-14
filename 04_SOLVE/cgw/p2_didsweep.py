#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""p2_didsweep.py - sweep the 0x22 ReadDataByIdentifier space at TA=0x1000.

Discriminator: NRC 0x31 = "this DID does not exist" (baseline).
              anything else (POS, NRC 33/22/13/...) = the DID exists / behaves differently.

Concurrency: N threads, each with its own TCP connection + routing activation.

Usage:
  python p2_didsweep.py 0xF100 0xF200            # single range
  python p2_didsweep.py --ranges F000-F200,0100-0200
"""
import sys, os, json, threading, queue, time, binascii
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dx
from dx import hx, verdict

EV = r"D:\qwb\03_EVIDENCE\cgw"
OUT = os.path.join(EV, "p2_did_sweep.jsonl")
HITS = os.path.join(EV, "p2_did_hits.json")

lock = threading.Lock()


def worker(host, port, ta, q, res, areq):
    d = None
    while True:
        try:
            did = q.get_nowait()
        except queue.Empty:
            break
        u = bytes([0x22, (did >> 8) & 0xFF, did & 0xFF])
        r = None
        for attempt in range(3):
            try:
                if d is None:
                    d = dx.Link(host, port, timeout=4.0).connect()
                    d.ra()
                    if not d.activated:
                        d.close(); d = None; time.sleep(0.3); continue
                r = d.uds_raw(u, ta=ta, timeout=4.0)
                if r["uds"] is not None or (r["acks"] and r["nack"] is not None):
                    break
                d.close(); d = None
            except Exception:
                try:
                    d and d.close()
                except Exception:
                    pass
                d = None
                time.sleep(0.2)
        if r is None:
            rec = {"did": "0x%04X" % did, "kind": "ERROR", "uds": None}
        else:
            v = verdict(r)
            sd = r["frames"][0]["uds"] if r["frames"] else None
            kind = "pos" if v.startswith("POS") else ("nrc" if v.startswith("NRC") else "other")
            rec = {"did": "0x%04X" % did, "kind": kind, "uds": hx(sd) if sd else None,
                   "verdict": v, "ms": r["ms"]}
        with lock:
            res.append(rec)
            areq.append(rec)
        q.task_done()
    try:
        d and d.close()
    except Exception:
        pass


def parse_ranges(spec):
    out = []
    for part in spec.split(","):
        a, b = part.split("-")
        out.append((int(a, 16), int(b, 16)))
    return out


def main():
    host = os.environ.get("DOIP_HOST", "10.229.221.2")
    port = int(os.environ.get("DOIP_PORT", "13400"))
    ta = 0x1000
    ranges = [(0xF100, 0xF200)]
    nthreads = 16
    args = sys.argv[1:]
    if args and args[0] == "--ranges":
        ranges = parse_ranges(args[1])
        if len(args) > 2:
            ta = int(args[2], 16)
    elif len(args) >= 2:
        ranges = [(int(args[0], 16), int(args[1], 16))]

    q = queue.Queue()
    total = 0
    for a, b in ranges:
        for did in range(a, b):
            q.put(did); total += 1
    print("# sweep TA=0x%04X dids=%d threads=%d ranges=%s" % (ta, total, nthreads, ranges), flush=True)

    res, areq = [], []
    ths = [threading.Thread(target=worker, args=(host, port, ta, q, res, areq), daemon=True)
           for _ in range(nthreads)]
    t0 = time.time()
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    dur = time.time() - t0

    res.sort(key=lambda r: r["did"])
    with open(OUT, "a", encoding="utf-8") as f:
        for r in res:
            r["ta"] = "0x%04X" % ta
            r["ts"] = dx.now()
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    hits = [r for r in res if r["kind"] != "nrc" or (r.get("uds") and r["uds"] != "7F2231")]
    print("# done in %.1fs (%.0f ms/req effective)" % (dur, dur * 1000 / max(1, total)))
    print("# non-baseline results: %d" % len(hits))
    for r in hits:
        print("  %s  %-10s %s" % (r["did"], r["kind"], r.get("uds")))

    # merge hits file
    old = []
    if os.path.exists(HITS):
        try:
            old = json.load(open(HITS, encoding="utf-8"))
        except Exception:
            old = []
    seen = {(o["ta"], o["did"]) for o in old}
    for r in hits:
        if ("0x%04X" % ta, r["did"]) not in seen:
            old.append({"ta": "0x%04X" % ta, "did": r["did"], "kind": r["kind"],
                        "uds": r.get("uds"), "ts": dx.now()})
    json.dump(old, open(HITS, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print("# hits file:", HITS, "entries:", len(old))


if __name__ == "__main__":
    main()
