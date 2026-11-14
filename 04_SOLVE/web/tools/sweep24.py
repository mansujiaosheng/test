#!/usr/bin/env python3
"""Horizontal sweep of the challenge /24 on the ports that could host OTA.

Purpose: my card asks "where is the OTA package / firmware / client cert".
The two assigned hosts turned out to carry only /healthz (+ a stub /graphql).
Before writing "not found", rule out that the OTA service simply lives on a
neighbouring address in the same lab subnet.

Read-only TCP connect + one banner-less HTTP HEAD.  Rate <= 20 conn/s.
"""
import json, os, socket, sys, threading, time
from queue import Queue, Empty

EVID = os.path.join(os.path.dirname(__file__), "..", "..", "..", "03_EVIDENCE", "web")
NET = "10.230.164."
HOSTS = [f"{NET}{i}" for i in range(1, 255)]
PORTS = [80, 443, 1883, 3000, 5000, 8000, 8080, 8443, 8888, 9090, 13400, 13401]

lock = threading.Lock()
hits = []
n_done = 0
t0 = time.time()

def probe(ip, port):
    s = socket.socket()
    s.settimeout(1.2)
    try:
        s.connect((ip, port))
        return True
    except Exception:
        return False
    finally:
        try: s.close()
        except Exception: pass

def worker(q, pps):
    global n_done
    while True:
        try:
            ip, port = q.get_nowait()
        except Empty:
            return
        with lock:
            want = n_done / float(pps)
            now = time.time() - t0
            wait = want - now
            n_done += 1
        if wait > 0:
            time.sleep(wait)
        ok = probe(ip, port)
        if ok:
            with lock:
                hits.append((ip, port))
                print(f"[+] {ip}:{port} open", flush=True)

def main():
    pps = 20
    q = Queue()
    for ip in HOSTS:
        for p in PORTS:
            q.put((ip, p))
    total = q.qsize()
    ts = [threading.Thread(target=worker, args=(q, pps), daemon=True) for _ in range(40)]
    for t in ts: t.start()
    for t in ts: t.join()
    dt = time.time() - t0
    print(f"\nprobes={total} elapsed={dt:.0f}s hits={len(hits)}")
    by_ip = {}
    for ip, p in sorted(hits):
        by_ip.setdefault(ip, []).append(p)
    for ip, ps in by_ip.items():
        print(f"  {ip}: {ps}")
    os.makedirs(EVID, exist_ok=True)
    p = os.path.join(EVID, "sweep_24_ports.json")
    open(p, "w", encoding="utf-8").write(json.dumps(
        {"ports": PORTS, "hits": by_ip, "probes": total, "elapsed_s": round(dt)}, indent=1))
    print("wrote", p)

if __name__ == "__main__":
    main()
