#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Serial re-test of the 18 "hits" from the host-scoped sweep.

They were all ERR TimeoutError, i.e. my client gave up under 16-way
concurrency, not an HTTP response. Re-run one at a time with a long timeout so
each is either a real status line or a definitive failure.
"""
import socket
import time

HOST_IP, PORT = "10.230.164.3", 8080

CASES = [
    # (path, host header, extra headers, label)
    ("/fleet/api/debug", "tbox.local", "", "p1"),
    ("/cv6/vin", "tbox.local", "", "p1"),
    ("/vehicle/version", "tbox.local", "", "p1"),
    ("/vehicle/update", "tbox.local", "", "p1"),
    ("/vehicle/reports", "tbox.local", "", "p1"),
    ("/vehicle/artifacts", "tbox.local", "", "p1"),
    ("/vehicle/download", "tbox.local", "", "p1"),
    ("/vehicle/upload", "tbox.local", "", "p1"),
    ("/vehicle/audit", "tbox.local", "", "p1"),
    ("/vehicle/event", "tbox.local", "", "p1"),
    ("/vehicle/events", "tbox.local", "", "p1"),
    ("/vehicle/state", "tbox.local", "", "p1"),
    ("/vehicle/devices", "tbox.local", "", "p1"),
    ("/vehicle/device", "tbox.local", "", "p1"),
    ("/vehicle/ecu", "tbox.local", "", "p1"),
    ("/vehicle/ecus", "tbox.local", "", "p1"),
    ("/jsonrpc/can", "tbox", "X-Forwarded-For: 127.0.0.1\r\nX-Real-IP: 127.0.0.1\r\nX-Forwarded-Host: tbox\r\n", "p2"),
    ("/api/v1/vehicles/CV6FF52FEE9EDDD86/diagnostics", "tbox:8080", "", "p2"),
]


def once(path, host, extra, timeout=15.0):
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: retry\r\n"
           f"{extra}Accept: */*\r\nConnection: close\r\n\r\n")
    s = socket.socket()
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((HOST_IP, PORT))
        s.sendall(req.encode())
        data = b""
        while len(data) < 1024:
            c = s.recv(1024)
            if not c:
                break
            data += c
        return data.decode("latin1", "replace"), time.time() - t0
    except Exception as e:
        return f"ERR {type(e).__name__}: {e}", time.time() - t0
    finally:
        s.close()


if __name__ == "__main__":
    for i, (p, h, x, tag) in enumerate(CASES, 1):
        r, dt = once(p, h, x)
        first = r.split("\r\n")[0]
        print(f"[{i:02d}/{tag}] Host:{h:12s} {p:50s} {dt:5.2f}s -> {first}")
        if "404" not in first:
            print("     FULL:", r[:300].replace("\r\n", " | "))
