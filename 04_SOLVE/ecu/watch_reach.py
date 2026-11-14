#!/usr/bin/env python3
"""watch_reach.py - poll BCM/BMS/VCU :8080 every 60 s.

The range instance may be brought up late, so keep polling. Exit code 0 the
moment any of the three answers, non-zero if nothing came up before the
deadline. Every cycle is logged so the timeline is auditable afterwards.

Usage: python watch_reach.py [minutes] [--once]
"""
import asyncio
import socket
import sys
import time

TARGETS = [
    ("10.224.139.5", 8080, "BCM"),
    ("10.224.139.6", 8080, "BMS"),
    ("10.224.139.7", 8080, "VCU"),
]
INTERVAL = 60
TIMEOUT = 3.0


async def probe(host, port):
    t0 = time.monotonic()
    try:
        fut = asyncio.open_connection(host, port)
        r, w = await asyncio.wait_for(fut, timeout=TIMEOUT)
        dt = time.monotonic() - t0
        w.close()
        return True, dt
    except asyncio.TimeoutError:
        return False, time.monotonic() - t0
    except ConnectionRefusedError:
        # RST proves the host EXISTS even though the port is shut
        return "REFUSED", time.monotonic() - t0
    except OSError as e:
        return f"ERR:{getattr(e, 'winerror', e)}", time.monotonic() - t0


def http_get(host, port, path="/healthz"):
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect((host, port))
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n".encode())
        d = b""
        while len(d) < 4096:
            c = s.recv(4096)
            if not c:
                break
            d += c
        return d.decode(errors="replace")
    except Exception as e:
        return f"<EXC {e!r}>"
    finally:
        s.close()


async def cycle(n):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n=== cycle {n} @ {ts} ===", flush=True)
    any_up = False
    for host, port, label in TARGETS:
        ok, dt = await probe(host, port)
        state = "OPEN" if ok is True else ("REFUSED" if ok == "REFUSED" else "no-response")
        print(f"  {label:4s} {host}:{port} {state:12s} dt={dt:.2f}", flush=True)
        if ok is True:
            any_up = True
            print(f"  *** {label} REACHABLE - raw curl response follows ***", flush=True)
            print(http_get(host, port), flush=True)
        if ok == "REFUSED":
            any_up = True
            print(f"  *** {label} HOST ALIVE (RST on 8080) - 8080 shut but host exists ***", flush=True)
    return any_up


async def main():
    minutes = 20
    once = "--once" in sys.argv
    for a in sys.argv[1:]:
        if a.isdigit():
            minutes = int(a)
    if once:
        up = await cycle(1)
        sys.exit(0 if up else 2)
    deadline = time.monotonic() + minutes * 60
    n = 0
    while time.monotonic() < deadline:
        n += 1
        if await cycle(n):
            print("\nRESULT: REACHABLE - stopping watch", flush=True)
            sys.exit(0)
        left = deadline - time.monotonic()
        if left <= 0:
            break
        await asyncio.sleep(min(max(left, 1), INTERVAL))
    print(f"\nRESULT: still unreachable after {minutes} min ({n} cycles)", flush=True)
    sys.exit(3)


if __name__ == "__main__":
    asyncio.run(main())
