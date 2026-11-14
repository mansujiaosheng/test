#!/usr/bin/env python3
"""fullscan2.py - full-port TCP connect scan, slot-scheduled rate limiting.

Why the rewrite: the previous version slept while holding the rate-limit lock,
which serialised every coroutine and cut throughput to ~216 pps. Here each
probe is assigned a fixed start slot (1/pps apart) up front, so the limit is
exact and there is no lock contention.

Writes evidence INCREMENTALLY so a killed process still leaves its results.

Usage: python fullscan2.py <host> <label> <outfile> [pps]
"""
import asyncio
import json
import sys
import time

CONCURRENCY = 600
TIMEOUT = 0.6


async def scan(host, label, outfile, pps=450.0):
    fh = open(outfile, "w", encoding="utf-8", buffering=1)
    fh.write(f"# full-port TCP connect scan\n# host   : {host} ({label})\n"
             f"# ports  : 1-65535\n# timeout: {TIMEOUT}s  concurrency: {CONCURRENCY}  rate: {pps} pps\n"
             f"# start  : {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
             f"# note   : closed ports on this range are silently DROPped, so a timeout\n"
             f"#          means 'no listener OR no host'; an OPEN line is proof of life.\n\n")
    stats = {"open": 0, "timeout": 0, "refused": 0, "other": 0}
    sem = asyncio.Semaphore(CONCURRENCY)
    t0 = time.monotonic()
    interval = 1.0 / pps

    async def probe(port, slot):
        delay = t0 + slot * interval - time.monotonic()
        if delay > 0:
            await asyncio.sleep(delay)
        async with sem:
            try:
                fut = asyncio.open_connection(host, port)
                r, w = await asyncio.wait_for(fut, timeout=TIMEOUT)
                w.close()
                stats["open"] += 1
                fh.write(f"OPEN     {host}:{port}\n")
            except asyncio.TimeoutError:
                stats["timeout"] += 1
            except ConnectionRefusedError:
                stats["refused"] += 1
                fh.write(f"REFUSED  {host}:{port}   <- host ALIVE, port closed\n")
            except OSError as e:
                stats["other"] += 1
                fh.write(f"ERR      {host}:{port} {e!r} win={getattr(e,'winerror',None)}\n")

    tasks = [asyncio.create_task(probe(p, i)) for i, p in enumerate(range(1, 65536))]
    done = 0
    for batch in asyncio.as_completed(tasks):
        await batch
        done += 1
        if done % 10000 == 0:
            el = time.monotonic() - t0
            fh.write(f"# progress {done}/65535 elapsed={el:.0f}s "
                     f"rate={done/el:.0f}pps stats={stats}\n")
            print(f"[{label}] {done}/65535 {el:.0f}s {done/el:.0f}pps {stats}", flush=True)

    el = time.monotonic() - t0
    summary = {"host": host, "label": label, "ports": 65535, "elapsed_s": round(el, 1),
               "pps_actual": round(65535 / el, 1), **stats,
               "verdict": "ALIVE" if stats["open"] or stats["refused"] else "NO-RESPONSE-AT-ALL"}
    fh.write("\n# SUMMARY " + json.dumps(summary) + "\n")
    fh.close()
    print("SUMMARY " + json.dumps(summary), flush=True)
    return summary


if __name__ == "__main__":
    host, label, out = sys.argv[1], sys.argv[2], sys.argv[3]
    pps = float(sys.argv[4]) if len(sys.argv) > 4 else 450.0
    asyncio.run(scan(host, label, out, pps))
