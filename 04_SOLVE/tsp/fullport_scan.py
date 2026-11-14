#!/usr/bin/env python3
"""
Full 1-65535 TCP connect scan of T01 (10.230.164.2), as an independent cross-check
of the earlier nmap -sT -Pn -p- run (which reported only 8080 open + 92 "filtered").

Pure connect() probes, no payload. Bounded concurrency (256), 0.6 s per-probe timeout.
"""
import concurrent.futures as cf
import socket
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "10.230.164.2"
TIMEOUT = 0.6
WORKERS = 256

# Windows: avoid TIME_WAIT pile-up / port exhaustion by not keeping sockets.
def probe(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        r = s.connect_ex((HOST, port))
        return port, r
    except Exception:
        return port, -1
    finally:
        try:
            s.close()
        except Exception:
            pass


def main():
    t0 = time.time()
    opens = []
    other = {}
    done = 0
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = [ex.submit(probe, p) for p in range(1, 65536)]
        for f in cf.as_completed(futs):
            port, rc = f.result()
            done += 1
            if rc == 0:
                opens.append(port)
                print(f"OPEN {HOST}:{port}  @{time.time()-t0:.1f}s", flush=True)
            elif rc not in (10061, 111, -1, 61):  # 10061=WSAECONNREFUSED
                other[port] = rc
            if done % 5000 == 0:
                print(f"# {done}/65535  open={len(opens)}  other={len(other)}  "
                      f"{time.time()-t0:.1f}s", flush=True)
    print()
    print("=" * 60)
    print(f"# {HOST} full 1-65535 TCP connect scan finished in {time.time()-t0:.1f}s")
    print(f"# open ports: {sorted(opens)}  (count={len(opens)})")
    print(f"# non-refused, non-open ports: {sorted(other.items())[:60]} (count={len(other)})")
    if other:
        vals = {}
        for p, rc in other.items():
            vals.setdefault(rc, []).append(p)
        for rc, ps in vals.items():
            print(f"#   rc={rc}  n={len(ps)}  first20={sorted(ps)[:20]}")
    # banner grab on opens
    for p in opens:
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect((HOST, p))
            if p in (443, 8443):
                s.close()
                continue
            s.sendall(b"GET /healthz HTTP/1.0\r\n\r\n")
            d = s.recv(400)
            print(f"# banner {p}: {d[:200]!r}")
            s.close()
        except Exception as e:
            print(f"# banner {p}: EXC {type(e).__name__}")


if __name__ == "__main__":
    main()
