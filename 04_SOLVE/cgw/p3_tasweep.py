#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""p3_tasweep.py - enumerate DoIP target logical addresses with a *real* discriminator.

Why redo it: the earlier sweep used UDS 3E00, and 3E00 answers NRC 0x11 even for the
known-good gateway LA 0x1000 -> that probe cannot distinguish anything.

Discriminator used here: 22 F1 90 (ReadDataByIdentifier, VIN).
  * known-good gateway LA 0x1000  -> POS 62F190...           (measured)
  * any LA the entity cannot route -> NRC 0x31 (7F2231)      (measured)
So "verdict != NRC 0x31" == something real answered. We also record the responder SA,
because in DoIP the response SA is the actual responder: SA != 0x1000 would prove a bridge.
"""
import sys, os, json, threading, queue, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dx
from dx import hx, verdict

EV = r"D:\qwb\03_EVIDENCE\cgw"
OUT = os.path.join(EV, "p3_ta_sweep.jsonl")
HITS = os.path.join(EV, "p3_ta_hits.json")
lock = threading.Lock()


def worker(host, port, probe, q, res):
    d = None
    while True:
        try:
            ta = q.get_nowait()
        except queue.Empty:
            break
        r = None
        for _ in range(3):
            try:
                if d is None:
                    d = dx.Link(host, port, timeout=4.0).connect()
                    d.ra()
                    if not d.activated:
                        d.close(); d = None; time.sleep(0.2); continue
                r = d.uds_raw(probe, ta=ta, timeout=4.0)
                if r["uds"] is not None or (r["acks"] and r["nack"] is not None):
                    break
                d.close(); d = None
            except Exception:
                try:
                    d and d.close()
                except Exception:
                    pass
                d = None
                time.sleep(0.15)
        if r is None:
            rec = {"ta": "0x%04X" % ta, "kind": "ERROR", "src": None, "uds": None}
        else:
            sd = r["frames"][0]["uds"] if r["frames"] else None
            src = r["frames"][0]["sa"] if r["frames"] else None
            v = verdict(r)
            kind = "pos" if v.startswith("POS") else ("nrc" if v.startswith("NRC") else "other")
            rec = {"ta": "0x%04X" % ta, "kind": kind, "src": ("0x%04X" % src) if src is not None else None,
                   "uds": hx(sd) if sd else None, "verdict": v}
        with lock:
            res.append(rec)
        q.task_done()
    try:
        d and d.close()
    except Exception:
        pass


def main():
    host = os.environ.get("DOIP_HOST", "10.229.221.2")
    port = int(os.environ.get("DOIP_PORT", "13400"))
    probe = bytes.fromhex(os.environ.get("PROBE", "22F190"))
    nthreads = int(os.environ.get("NT", "8"))
    ranges = [(0x0000, 0x2000), (0x7000, 0x7100), (0x7E00, 0x7F00),
              (0xE000, 0xE100), (0xE400, 0xE500)]
    if len(sys.argv) > 1:
        ranges = []
        for part in sys.argv[1].split(","):
            a, b = part.split("-")
            ranges.append((int(a, 16), int(b, 16)))

    q = queue.Queue()
    for a, b in ranges:
        for ta in range(a, b):
            q.put(ta)
    total = q.qsize()
    print("# TA sweep host=%s probe=%s total=%d threads=%d ranges=%s" %
          (host, hx(probe), total, nthreads, ranges), flush=True)
    res = []
    ths = [threading.Thread(target=worker, args=(host, port, probe, q, res), daemon=True) for _ in range(nthreads)]
    t0 = time.time()
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    dur = time.time() - t0
    res.sort(key=lambda r: r["ta"])
    with open(OUT, "a", encoding="utf-8") as f:
        for r in res:
            r["probe"] = hx(probe); r["ts"] = dx.now(); r["host"] = host
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    hits = [r for r in res if r["kind"] != "nrc"]
    offsrc = [r for r in res if r["src"] not in (None, "0x1000")]
    print("# done %.1fs, %d probes" % (dur, total))
    print("# responders with verdict != NRC31: %d" % len(hits))
    for r in hits:
        print("   %s %-8s %-6s %s" % (r["ta"], r["kind"], r["src"], r["uds"]))
    print("# responders with SA != 0x1000 (bridge evidence): %d" % len(offsrc))
    for r in offsrc[:20]:
        print("   %s %-8s %-6s %s" % (r["ta"], r["kind"], r["src"], r["uds"]))
    old = []
    if os.path.exists(HITS):
        try:
            old = json.load(open(HITS, encoding="utf-8"))
        except Exception:
            old = []
    seen = {(o["ta"], o.get("probe")) for o in old}
    for r in hits + offsrc:
        if (r["ta"], r["probe"]) not in seen:
            old.append(r)
    json.dump(old, open(HITS, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print("# hits:", HITS, len(old))


if __name__ == "__main__":
    main()
