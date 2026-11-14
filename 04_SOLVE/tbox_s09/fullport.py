#!/usr/bin/env python3
"""Full 1-65535 TCP connect scan against a single host (+ banner grab).
Read-only reconnaissance; small thread pool to avoid knocking over the range."""
import socket, sys, json, time
from concurrent.futures import ThreadPoolExecutor

HOST = sys.argv[1] if len(sys.argv) > 1 else "10.230.164.3"
TIMEOUT = 1.2
OPEN = []


def probe(port):
    s = socket.socket()
    s.settimeout(TIMEOUT)
    try:
        if s.connect_ex((HOST, port)) != 0:
            return None
        banner = b""
        try:
            s.settimeout(1.0)
            banner = s.recv(256)
        except Exception:
            pass
        return (port, banner)
    finally:
        try:
            s.close()
        except Exception:
            pass


def main():
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=256) as ex:
        for r in ex.map(probe, range(1, 65536)):
            if r:
                OPEN.append(r)
                print(f"OPEN {HOST}:{r[0]} banner={r[1][:120]!r}", flush=True)
    print(f"=== done {len(OPEN)} open / 65535 in {time.time()-t0:.1f}s ===")
    with open(sys.argv[2], "w") as f:
        json.dump([{"port": p, "banner": b.decode("latin1")} for p, b in OPEN], f, indent=1)


if __name__ == "__main__":
    main()
