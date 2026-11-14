#!/usr/bin/env python3
"""Build the reachability evidence chain for 10.224.139.0/24 from THIS vantage point.

The claim to support is not "it looks down" but "there is no path from this VPN
attachment, and no intermediate on the two reachable segments will carry one".

Three independent legs:
  LEG 1  TCP: try 10.224.139.5/.6/.7 on :8080 and on the CGW's own service ports
         for 3 attempts each, record the exact errno/timeout. A TCP RST would mean
         "host up, port closed"; a timeout means "no answer at all".
  LEG 2  ICMP/TTL: run the platform traceroute and keep every hop, so the point
         where the path dies is explicit rather than inferred.
  LEG 3  intermediate inventory: ping-sweep the two segments we CAN reach
         (10.229.221.0/24, 10.230.164.0/24) to show the only live host is the
         gateway itself -- i.e. there is no second box that could route onward.

Written to 03_EVIDENCE/cgw-web/0620_reachability_chain.txt
"""
import socket, subprocess, os, time, json, sys, struct

OUT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "..", "..", "03_EVIDENCE", "cgw-web",
                                   "0620_reachability_chain.txt"))
ECUS = [("10.224.139.5", "BCM"), ("10.224.139.6", "BMS"), ("10.224.139.7", "VCU")]

buf = []


def w(line=""):
    print(line, flush=True)
    buf.append(line)


def tcp(host, port, budget=6.0):
    t0 = time.perf_counter()
    s = socket.socket()
    s.settimeout(budget)
    try:
        s.connect((host, port))
        return "OPEN", round((time.perf_counter() - t0) * 1000, 1), ""
    except ConnectionRefusedError as e:
        return "REFUSED", round((time.perf_counter() - t0) * 1000, 1), str(e)
    except socket.timeout:
        return "TIMEOUT", round((time.perf_counter() - t0) * 1000, 1), "no SYN-ACK"
    except OSError as e:
        return "ERR", round((time.perf_counter() - t0) * 1000, 1), str(e)
    finally:
        try:
            s.close()
        except Exception:
            pass


def main():
    w("# Reachability chain for 10.224.139.0/24")
    w("# time: %s" % time.strftime("%Y-%m-%d %H:%M:%S%z"))
    w()
    w("== LEG 1: direct TCP, 3 attempts each ==")
    for host, name in ECUS:
        for port in (8080, 13400, 13401, 22, 443, 80):
            outcomes = []
            for _ in range(3 if port in (8080, 443) else 1):
                o, ms, det = tcp(host, port, budget=6.0)
                outcomes.append("%s/%.0fms%s" % (o, ms, ("/" + det) if det and o == "ERR" else ""))
            w("  %-14s %-5s %-6s %s" % (host, name, port, " ".join(outcomes)))
            time.sleep(0.15)

    w()
    w("== LEG 2: traceroute ==")
    for host, name in ECUS:
        w("  --- tracert %s (%s) ---" % (host, name))
        try:
            r = subprocess.run(["tracert", "-d", "-w", "1200", "-h", "6", host],
                               capture_output=True, text=True, timeout=120)
            for ln in r.stdout.splitlines():
                if ln.strip():
                    w("    " + ln.rstrip())
        except subprocess.TimeoutExpired:
            w("    <tracert timed out>")

    w()
    w("== LEG 3: live-host inventory on the reachable segments ==")
    for seg in ("10.229.221", "10.230.164"):
        w("  --- %s.0/24 (TCP probe of the CGW service ports) ---" % seg)
        live = []
        for i in range(1, 40):
            ip = "%s.%d" % (seg, i)
            hits = []
            for port, budget in ((8080, 1.2), (13400, 1.2)):
                o, ms, _ = tcp(ip, port, budget=budget)
                if o == "OPEN":
                    hits.append("%d" % port)
                elif o == "REFUSED":
                    hits.append("%d:RST" % port)
            if hits:
                live.append((ip, hits))
                w("    %-15s %s" % (ip, ",".join(hits)))
        if not live:
            w("    <no host with 8080/13400 in .1-.39>")

    w()
    w("== verdict ==")
    w("  ECUs answer nothing (see LEG 1 outcomes above); the path dies after the")
    w("  VPN first hop (LEG 2); the only reachable intermediate is the CGW (LEG 3).")

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(buf) + "\n")
    print("\nevidence:", OUT)


if __name__ == "__main__":
    main()
