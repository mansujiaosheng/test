#!/usr/bin/env python3
"""Precise TCP connect probe: classify every attempt as OPEN / RST(refused) / TIMEOUT / other.

Method (important): Python sets the socket non-blocking when a timeout is set, so
connect_ex() returns WSAEWOULDBLOCK immediately. We must then select() for writability
and read SO_ERROR. Only SO_ERROR tells us whether a RST (10061) arrived or nothing did.

Why this matters: on this fleet some hosts DROP closed ports (timeout) and some RST.
A timeout therefore proves nothing on its own; controls + traceroute decide.

Only reads. No retries beyond the explicit rep count.

Usage:
  python probe_tcp.py --targets 10.224.139.5,10.224.139.6,10.224.139.7 \
      --ports 8080,80,443,8443,13400,13401,3000,5000 --reps 3 --timeout 2.0 \
      --out 03_EVIDENCE/ecu-reach/02_tcp_matrix.txt
"""
import argparse
import select
import socket
import sys
import time

ERR = {
    0: "OPEN",
    10061: "RST",          # WSAECONNREFUSED -> SYN answered with RST
    10060: "TIMEOUT",      # WSAETIMEDOUT (kernel-side)
    10065: "UNREACH",      # WSAEHOSTUNREACH
    10051: "NETUNREACH",   # WSAENETUNREACH
    10013: "DENIED",
    10035: "INPROGRESS",   # WSAEWOULDBLOCK
}


def one(host: str, port: int, timeout: float):
    """return (class, elapsed_seconds, errno_or_None)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(False)
    t0 = time.time()
    try:
        rc = s.connect_ex((host, port))
        if rc == 0:
            return "OPEN", time.time() - t0, 0
        if rc not in (10035, 115, 11):          # not "in progress" -> real immediate error
            return ERR.get(rc, f"ERR{rc}"), time.time() - t0, rc
        # wait for socket to become writable (connect finished) or timeout
        _, w, _ = select.select([], [s], [], timeout)
        dt = time.time() - t0
        if not w:
            return "TIMEOUT", dt, None
        err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if err == 0:
            return "OPEN", dt, 0
        return ERR.get(err, f"ERR{err}"), dt, err
    except OSError as e:
        return ERR.get(e.errno, f"ERR{e.errno}"), time.time() - t0, e.errno
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", required=True)
    ap.add_argument("--ports", required=True)
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--out", required=True)
    ap.add_argument("--note", default="")
    a = ap.parse_args()

    targets = [x.strip() for x in a.targets.split(",") if x.strip()]
    ports = [int(x) for x in a.ports.split(",") if x.strip()]
    import datetime
    lines = []
    lines.append("# precise TCP connect matrix (RST vs TIMEOUT)")
    lines.append(f"# start  : {datetime.datetime.now().astimezone().isoformat(timespec='seconds')}")
    lines.append("# host   : local 10.252.3.20 (TAP/OpenVPN), route 10.224.0.0/12 -> 10.252.3.1")
    lines.append(f"# method : nonblocking connect_ex + select(write) + SO_ERROR")
    lines.append(f"# reps   : {a.reps}   timeout/attempt: {a.timeout}s")
    if a.note:
        lines.append(f"# note   : {a.note}")
    lines.append("# verdict: OPEN=connected | RST=refused (IP alive, port closed) | "
                 "TIMEOUT=no answer (drop/blackhole) | UNREACH/other")
    lines.append("")
    n_open = n_rst = n_to = n_other = 0
    for t in targets:
        lines.append(f"=== {t} ===")
        for p in ports:
            got = []
            for _ in range(a.reps):
                got.append(one(t, p, a.timeout))
                time.sleep(0.05)
            classes = [g[0] for g in got]
            dts = ", ".join(f"{g[1]:.3f}" for g in got)
            if "OPEN" in classes:
                verdict = "OPEN"; n_open += 1
            elif all(c == "RST" for c in classes):
                verdict = "RST"; n_rst += 1
            elif all(c == "TIMEOUT" for c in classes):
                verdict = "TIMEOUT"; n_to += 1
            else:
                verdict = "MIXED"; n_other += 1
            lines.append(f"  {p:>5}/tcp  {verdict:<8} reps={'/'.join(classes):<24} dt=[{dts}]")
        lines.append("")

    lines.append(f"# summary: OPEN={n_open} RST={n_rst} TIMEOUT={n_to} MIXED/other={n_other}")
    out = "\n".join(lines)
    print(out)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(out + "\n")


if __name__ == "__main__":
    sys.exit(main())
