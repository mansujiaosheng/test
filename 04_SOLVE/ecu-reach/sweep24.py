#!/usr/bin/env python3
"""Fast asyncio TCP-connect sweep of a /24 for a small port list.

Why not full 1-65535 on a /24: that is 16.6M connect attempts. We first find live
hosts on a curated port set (which includes the service ports named in the task and
a few discovery ports), then any live host gets a full-port scan.

Usage:
  python sweep24.py --cidr 10.226.197.0/24 --ports 8080,8443,13400,13401,80,443,22,23,3000,5000,8081,8888,9000
  python sweep24.py --hosts 10.226.197.5 --ports 1-65535 --timeout 1.0 --concurrency 600
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import sys
import time


async def probe(host: str, port: int, timeout: float, sem: asyncio.Semaphore):
    async with sem:
        t0 = time.time()
        try:
            fut = asyncio.open_connection(host, port)
            r, w = await asyncio.wait_for(fut, timeout=timeout)
            dt = time.time() - t0
            try:
                w.close()
                await w.wait_closed()
            except Exception:
                pass
            return {"host": host, "port": port, "state": "OPEN", "dt": round(dt, 3)}
        except asyncio.TimeoutError:
            return {"host": host, "port": port, "state": "TIMEOUT", "dt": round(time.time() - t0, 3)}
        except OSError as e:
            import errno as E
            st = {E.ECONNREFUSED: "RST", E.EHOSTUNREACH: "UNREACH",
                  E.ENETUNREACH: "NETUNREACH"}.get(e.errno, f"ERR{e.errno}")
            return {"host": host, "port": port, "state": st, "dt": round(time.time() - t0, 3)}


def parse_ports(spec: str):
    out = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-")
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return out


async def run(hosts, ports, timeout, conc):
    sem = asyncio.Semaphore(conc)
    tasks = [probe(h, p, timeout, sem) for h in hosts for p in ports]
    res = []
    done = 0
    t0 = time.time()
    for coro in asyncio.as_completed(tasks):
        r = await coro
        done += 1
        if r["state"] in ("OPEN", "RST"):
            res.append(r)
            print(f"  HIT {r['host']}:{r['port']} {r['state']} {r['dt']}s", flush=True)
        if done % 5000 == 0:
            print(f"  ... {done}/{len(tasks)} elapsed={time.time()-t0:.1f}s", flush=True)
    return res, time.time() - t0, len(tasks)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cidr")
    ap.add_argument("--hosts")
    ap.add_argument("--ports", required=True)
    ap.add_argument("--timeout", type=float, default=1.2)
    ap.add_argument("--concurrency", type=int, default=400)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    if a.cidr:
        net = ipaddress.ip_network(a.cidr, strict=False)
        hosts = [str(h) for h in net.hosts()]
    else:
        hosts = [h.strip() for h in a.hosts.split(",") if h.strip()]
    ports = parse_ports(a.ports)
    print(f"# sweep hosts={len(hosts)} ports={len(ports)} probes={len(hosts)*len(ports)} "
          f"timeout={a.timeout}s conc={a.concurrency}", flush=True)
    res, elapsed, total = asyncio.run(run(hosts, ports, a.timeout, a.concurrency))
    out = {"hosts": hosts if len(hosts) < 300 else a.cidr, "ports": ports,
           "probes": total, "elapsed_s": round(elapsed, 1), "hits": res}
    text = json.dumps(out, indent=2)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    print(f"# done probes={total} elapsed={elapsed:.1f}s hits={len(res)}")
    print(text[:4000])


if __name__ == "__main__":
    sys.exit(main())
