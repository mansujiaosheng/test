#!/usr/bin/env python3
"""
New-range service discovery (read-only TCP connect, no payload).

Why: the platform's own stage text (03_EVIDENCE/tsp/0170) says the chain needs
  q3 "结合 MQTT 任务报文和历史 PCAP"          -> there is an MQTT broker somewhere
  q1 "利用云端 IDOR 读取测试车 OTA 包"          -> there is a "cloud" service holding packages
Neither is on the 3-route TSP, so the new range almost certainly has services that
the old 8080-only picture never hinted at. The old range is dead; this scans the
NEW range only.

Concurrency is capped at 40 (workspace rule: no >50). 0.7 s per connect.
"""
import concurrent.futures as cf
import socket
import sys
import time

SUBNETS = sys.argv[1:] or ["10.225.139", "10.226.193"]
PORTS = [80, 443, 1883, 1884, 8883, 9001, 22, 3000, 5000, 7001, 8000, 8080,
         8081, 8082, 8443, 9000, 9090, 13400, 13401, 2181, 6379, 5432, 3306]
TIMEOUT = 0.7
WORKERS = 40


def probe(ip, port):
    s = socket.socket()
    s.settimeout(TIMEOUT)
    try:
        rc = s.connect_ex((ip, port))
        return ip, port, rc == 0
    except Exception:
        return ip, port, False
    finally:
        try:
            s.close()
        except Exception:
            pass


def main():
    jobs = []
    for net in SUBNETS:
        for i in range(1, 255):
            for p in PORTS:
                jobs.append((f"{net}.{i}", p))
    print(f"# {len(jobs)} connect probes over {len(SUBNETS)} /24 x {len(PORTS)} ports, "
          f"workers={WORKERS}, timeout={TIMEOUT}", flush=True)
    t0 = time.time()
    openmap = {}
    done = 0
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = [ex.submit(probe, ip, p) for ip, p in jobs]
        for f in cf.as_completed(futs):
            ip, port, ok = f.result()
            done += 1
            if ok:
                openmap.setdefault(ip, []).append(port)
                print(f"OPEN {ip}:{port}  @{time.time()-t0:.1f}s", flush=True)
            if done % 2000 == 0:
                print(f"# {done}/{len(jobs)}  {time.time()-t0:.1f}s", flush=True)
    print()
    print("=" * 60)
    print(f"# done {time.time()-t0:.1f}s")
    for ip in sorted(openmap, key=lambda x: tuple(int(o) for o in x.split("."))):
        print(f"  {ip:16s} {sorted(openmap[ip])}")
    print(f"live hosts: {len(openmap)}")


if __name__ == "__main__":
    main()
