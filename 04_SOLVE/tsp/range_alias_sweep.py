#!/usr/bin/env python3
"""
Range-topology recon (read-only, low volume).

Motivation: 10.230.164.4 and 10.229.221.2 are the SAME service on two IPs
(per 00_SCOPE/CONTEST.md), i.e. this range gives each target a second IP alias.
T01 lives at 10.230.164.2. If the *real* TSP (with an OTA endpoint) is bound to
the alias IP rather than 10.230.164.2, a plain host-port scan of 10.230.164.2
would never see it.

So: for the three challenge /24s, find every host with the challenge ports open.
Concurrency is capped at 24 and each probe is a single non-destructive TCP connect
(no payload is sent). Nothing is written to any target.
"""
import concurrent.futures as cf
import socket
import sys
import time

SUBNETS = ["10.230.164", "10.229.221", "10.224.139"]
PORTS = [8080, 8443, 13400, 13401]
TIMEOUT = 0.9
WORKERS = 24


def probe(ip, port):
    s = socket.socket()
    s.settimeout(TIMEOUT)
    t0 = time.time()
    try:
        s.connect((ip, port))
        return (ip, port, True, time.time() - t0)
    except Exception:
        return (ip, port, False, time.time() - t0)
    finally:
        try:
            s.close()
        except Exception:
            pass


def main():
    targets = []
    for net in SUBNETS:
        for i in range(1, 255):
            ip = f"{net}.{i}"
            for p in PORTS:
                targets.append((ip, p))
    print(f"# probing {len(targets)} (ip,port) pairs over {len(SUBNETS)} /24s, "
          f"ports={PORTS}, workers={WORKERS}, timeout={TIMEOUT}s", flush=True)
    t0 = time.time()
    open_hosts = {}
    done = 0
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(probe, ip, p): (ip, p) for ip, p in targets}
        for f in cf.as_completed(futs):
            ip, port, ok, dt = f.result()
            done += 1
            if ok:
                open_hosts.setdefault(ip, []).append(port)
                print(f"OPEN {ip}:{port}  ({dt*1000:.0f} ms)", flush=True)
            if done % 500 == 0:
                print(f"# progress {done}/{len(targets)}  {time.time()-t0:.1f}s",
                      flush=True)
    print()
    print("=" * 60)
    print(f"# done in {time.time()-t0:.1f}s")
    print("=== live hosts with challenge ports ===")
    for ip in sorted(open_hosts, key=lambda x: tuple(int(o) for o in x.split("."))):
        print(f"  {ip:16s} open={sorted(open_hosts[ip])}")
    print(f"total live hosts: {len(open_hosts)}")
    print()
    print("=== quick HTTP fingerprint on every 8080/8443 hit ===")
    import requests
    for ip in sorted(open_hosts, key=lambda x: tuple(int(o) for o in x.split("."))):
        for p in sorted(open_hosts[ip]):
            if p not in (8080,):
                continue
            for path in ("/healthz", "/graphql"):
                try:
                    r = requests.get(f"http://{ip}:{p}{path}", timeout=5)
                    print(f"  http://{ip}:{p}{path}  {r.status_code} {r.content[:90]!r}")
                except Exception as e:
                    print(f"  http://{ip}:{p}{path}  EXC {type(e).__name__}")


if __name__ == "__main__":
    main()
